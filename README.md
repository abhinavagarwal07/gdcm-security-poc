# GDCM findings 1-6: reproduction package

Six parser/codec defects in GDCM, reproduced on v3.2.6 as sanitizer failures or bounded
propagation checks. Each automated trigger has a near-valid control that does not produce
the vulnerable signal. Finding 1 also includes an instrumented control-flow primitive.

Intended for maintainer and vulnerability-coordinator review. Read `SAFETY.md` before
running anything.

## Pinned targets

`manifest/targets.env`:

| Name | Revision | What it is |
|---|---|---|
| `vulnerable` | `9c71b163` | tag v3.2.6 |
| `master` | `2cd05d13` | upstream `master` snapshot reviewed statically; runtime matrix pending |
| `fixed` | unset | populate only once a reviewed remediation commit exists |

`master` is a dated snapshot, not a moving branch. Both revisions are reachable from the
public repository, so `bootstrap.sh` can prepare either without any private source.

## Finding scope

Runtime evidence in this repository is for v3.2.6. The wider ranges below come from
source-history inspection; the implicated patterns also remain in the pinned master
snapshot.

| # | CWE | Source-inspected range | Required path |
|---|---|---|---|
| 1 | CWE-787 | v3.0.4 through v3.2.7 | multi-frame RLE `YBR_FULL_422` read |
| 2 | CWE-787 | v2.0.16 through v3.2.7 | JPEG2000 encoding/transcoding |
| 3 | CWE-125 | v2.0.5 through v3.2.7 | segmented palette parsing; LUT application exposes propagated values |
| 4 | CWE-787 | v2.0.8 through v3.2.7 | `ImageRegionReader::ReadIntoBuffer`; related to incomplete precision validation after CVE-2024-22373 |
| 5 | CWE-674 | v2.0.4 or earlier through v3.2.7 | ordinary nested-sequence parsing |
| 6 | CWE-369 | v2.0.4 or earlier through v3.2.7 | ordinary RLE parsing with `NumSegments=0` |

## Contents

- `fixtures/` - the inert DICOM inputs, SHA-256-pinned in `manifest/expectations.json`
  and verified before every trigger run
- `generators/` - deterministic, dependency-free source generators for every fixture
- `harnesses/` - minimal read/encode/decode harnesses; Finding 2 is shown through both
  the `gdcmconv` CLI and the library transcode API a server would call
- `manifest/expectations.json` - machine-readable commands, decisive signals, and
  acceptance criteria for the `fixed` target
- `scripts/` - pinned-source preparation, sanitizer builds, bounded execution, cleanup
- `evidence/` - concise results already observed, with untested targets stated explicitly
- `LICENSE` - MIT license

## Prerequisites

A disposable Linux or macOS build environment with Git, Python 3, CMake 3.20+, Ninja, and
a C++11 toolchain (Clang or GCC). On Ubuntu: `git python3 cmake ninja-build clang
zlib1g-dev`. Set `CC`/`CXX` to use GCC instead.

Source preparation clones over HTTPS unless `GDCM_SOURCE_REPO` points at an existing
local clone. No SSH host is used.

## Prepare and build

These commands prepare source and build artifacts only; they do not open any fixture.

```bash
./scripts/build-target.sh vulnerable asan  debug
./scripts/build-target.sh vulnerable ubsan debug
./scripts/build-target.sh master     asan  debug
./scripts/build-target.sh master     ubsan debug
```

The third argument is the profile. `debug` is `-O0 -g`; `release` is `-O2 -g -DNDEBUG`,
which elides GDCM's `gdcm_debug_assert()`s and matches how distributions build the
library. Running the matrix under both answers the first question a maintainer asks,
which is whether the reports are an artifact of an assertion-enabled build.

`GDCM_SUPPORT_BROKEN_IMPLEMENTATION=ON` is GDCM's own default and is left alone.
Override the conservative parallelism with `JOBS=8`.

Every build writes `build-info.json` (revision, compiler, flags, platform) into its GDCM
build tree, and every run summary embeds it, so archived evidence is self-describing.

## Run

```bash
export GDCM_REPRO_ACK=I_UNDERSTAND_THIS_CRASHES_A_LOCAL_PROCESS

./scripts/run-matrix.sh vulnerable master --profile debug   # all automated cases
./scripts/run-one.sh vulnerable f1                          # one trigger
./scripts/run-one.sh vulnerable f1 --control                # its control
```

`run-matrix.sh` runs every automated case for every target, does not stop at the first
failure, and writes `_runs/matrix-<stamp>.json` plus a rendered
`_runs/matrix-<stamp>.md`. The two-stage `f1-exploit` case remains manual and is reported
as such rather than being misclassified as a failed automated case.

Each child has core dumps disabled and a 15-second timeout; Finding 5 additionally gets a
bounded stack limit. Outputs stay under `_runs/`. The classifier matches sanitizer class
and implicated function, never addresses, PIDs, or source line numbers.

For `vulnerable`, a case passes when the decisive signal appears and its control stays
clean. For `master`, the runner records observation rather than a predeclared verdict.
For `fixed`, a case passes only when the signal is absent, no other sanitizer or fatal
signal appears, and the harness returns an allowed clean outcome. These rules are
provisional until `FIXED_REV` names an actual patch; they must be reviewed against that
patch's intended reject-or-process behavior.

## Cases

| Case | Finding | What it shows |
|---|---|---|
| `f1` | 1 | ASan heap write in `RLECodec::DecodeFragment` |
| `f1-exploit` | 1 | instrumented adjacent-object overwrite and indirect-branch control (Linux x86-64) |
| `f2` | 2 | ASan heap write in `opj_write_from_memory` via `gdcmconv --j2k` |
| `f2-lib` | 2 | the same write via `ImageChangeTransferSyntax::Change` |
| `f3` | 3 | ASan heap read in segmented palette expansion |
| `f3-propagation` | 3 | out-of-bounds bytes reach decoded pixels, reported as a count |
| `f3-sentinel` | 3 | a bounded known guard word crosses the logical LUT bound |
| `f4` | 4 | ASan heap write in JPEG2000 region decode |
| `f5` | 5 | ASan stack exhaustion on nested sequence items |
| `f6` | 6 | UBSan division by zero in RLE decode; SIGFPE on x86 |

Two further harnesses are exploitability research rather than reproduction cases, and
build only in the unsanitized profile on Linux x86-64:

| Harness | Finding | What it establishes |
|---|---|---|
| `finding01_groom` | 1 | the tested glibc adjacency, observed through allocation-recording hooks |
| `finding03_leak` | 3 | a 131070-byte overread can expose a build-specific library pointer |

## Retained evidence

`evidence/v3.2.6-macos-arm64-debug.md` records the completed v3.2.6 debug matrix,
including every control and both bounded Finding 3 propagation checks.

`evidence/v3.2.6-linux-x86_64-finding01-groom.md` and
`evidence/v3.2.6-linux-x86_64-finding03-leak.md` record the two exploitability results
below. Current-master, the full release-profile matrix, and `f1-exploit` results are not
claimed until their transcripts are retained.

## Cleanup

```bash
./scripts/clean.sh
```

Cleanup refuses to run without the package marker and removes only `_work`, `_build`,
`_generated`, `_runs`, and Python bytecode caches beneath this repository. Retained
evidence under `evidence/` is not removed.

## Exploitation primitive (Finding 1)

`f1-exploit` is Linux-x86_64 only and is run by hand; `manifest/expectations.json` carries
the exact command sequence. Under the harness's deterministic allocation layout it tests
three separate facts, each with a matched negative case:

- the overflow reaches memory the allocator handed out after the target buffer;
- the bytes landing there are the exact bytes the crafted DICOM asked for. Planting a
  different value, or using the plain `f1` fixture, reports corruption but explicitly
  *not* content control, so the check is falsifiable;
- the synthetic victim's function pointer ends up holding an address supplied by the
  file, and calling it transfers control to a function inside the harness.

About half of the 8-byte windows within the 12288-byte overflow accept an arbitrary
value. The rest are coupled, because `DoYBRFull422` duplicates one source byte into two
output positions; offset 6144 is one of the free windows. Frame 1's decode runs last, so
it is frame 1's content that persists past the allocation.

The harness records whether `ImageReader::Read()` returns true while the adjacent object
is modified. A successful Linux x86-64 transcript must be retained before describing that
result as observed evidence.

## What happens without the instrumentation

`f1-exploit` supplies its own victim layout, so it cannot answer whether an unmodified
process has that layout. `finding01_groom` uses stock glibc, default PIE, and ASLR, with
global allocation hooks that record but do not relocate allocations. In the retained
tests:

- the allocation following the 24576-byte buffer was a freed 2049-byte GDCM scratch
  chunk in all 20 recorded trials. No live object or vtable was observed;
- corrupting that chunk's free-list metadata trips glibc's own consistency check, which
  aborts. The plain `finding01` harness dies the same way with no instrumentation at all.

On the tested glibc build, **Finding 1 reliably caused denial of service; no
code-execution path was found.** The tested geometry was fixed, and other allocators or
platforms may lay out the heap differently.

`finding03_leak` is the stronger result. In the tested build, the out-of-bounds read
reaches 131070 bytes, a `gdcm::ByteValue` vtable pointer enters decoded pixels, and the
harness derives the library load base using that build's known vtable offset. This is a
local API-level disclosure result: it requires LUT application and access to the decoded
pixel buffer. It does not show that a network service returns those pixels.

The two cannot be chained into code execution here, and not only because no victim was
found: they need different PhotometricInterpretation values, so they need two files, and
a leaked base is only useful while the leaking process is still alive.

## Evidence boundary

A sanitizer report proves the stated memory-safety or undefined-behavior event in the
tested process and revision. `f1-exploit` tests byte control and an adjacent function-
pointer overwrite under an instrumented allocator that deliberately supplies the target
layout. It does not establish that layout in an unmodified consumer. The retained
`finding01_groom` trials did not observe that layout for the tested geometry and glibc
build.

None of this proves remote reachability in any particular product, persistence, or
downstream applicability. The reachability argument for a given deployment is a separate
claim, made in the disclosure text and not by this package.
