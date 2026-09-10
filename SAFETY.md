# Safety boundary

Run this package only in a disposable local VM/container or an explicitly authorized CI
job. The inputs intentionally terminate or abort the local test process.

The package enforces the following limits:

- execution is opt-in through `GDCM_REPRO_ACK`;
- core dumps are disabled;
- each child is killed after 15 seconds;
- Finding 5 uses a bounded stack limit;
- automated trigger commands receive checked-in synthetic DICOM files whose SHA-256
  digests are pinned in `manifest/expectations.json`; controls and the manual Finding 1
  primitive input are generated locally;
- child output and generated files remain in package-owned directories;
- no runner performs network access, SSH, upload, or submission.

`bootstrap.sh` is the sole script that may use the network, and only to clone the
official public GDCM repository over HTTPS. Point `GDCM_SOURCE_REPO` at a local clone to
avoid that access.

## Finding 3 and heap disclosure

Finding 3 is an out-of-bounds *read*. The three automated reproduction cases do not emit
adjacent heap contents:

- `f3` is an ASan heap-read report;
- `f3-sentinel` allocates a known `0xC0DE` guard word past the declared logical LUT
  length and reports only whether that known word propagates;
- `f3-propagation` drives the full file-to-pixel path and reports only a *count* of
  decoded words that are absent from the file's own LUT element.

The separate Linux-only `finding03_leak` research harness scans decoded pixels for
pointer-shaped values, prints matching pointer candidates, and checks whether a known,
build-specific vtable offset derives the loaded library base. It does not dump the full
decoded buffer. Its output is process memory information and should be handled as such.

## Finding 1 and the exploitation primitive

`f1-exploit` goes further than a sanitizer report: within an instrumented allocation
layout, it shows control of selected bytes in the overflow, modification of a live
adjacent object, and replacement of a function pointer with an address supplied by the
DICOM file. This is a stronger exploitation primitive than a crash. It is not a
code-execution demonstration in an unmodified application.

It stops there, deliberately. The address planted in the file is printed by the same
binary that consumes it (`--print-target`) and refers to a function inside that binary,
so control can only ever transfer back into the harness. `f1-exploit` contains no
shellcode or gadget chain and does not bypass ASLR or other mitigations. `-no-pie` is used
only so the address is stable across the two runs.

The harness replaces the global array allocator so that the victim object sits at a known
offset after the overrun buffer. That makes the result deterministic instead of dependent
on heap grooming; it is a measurement instrument, not an exploitation technique, and it
does not make the underlying defect more or less exploitable in a real process.

## General

Do not point these fixtures at PACS/clinical systems or systems you do not own or have
permission to test. Do not extend the harnesses toward persistence or real-data
collection.
