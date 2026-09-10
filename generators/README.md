# Generator provenance

Normal reproduction uses the checked-in `fixtures/` and does not invoke these files.
They are here so a reviewer can see how each input was constructed and vary it.

Every generator is deterministic and depends on nothing outside the standard library:
an earlier Finding 4 generator shelled out to the host's `opj_compress` and so produced
different bytes on different machines. It was replaced rather than shipped.

`finding-01-exploit.py` is not a fixture generator. It inverts the byte-permutation
pipeline that the Finding 1 overflow travels through, so a chosen byte string can be
placed at a chosen offset past the overrun allocation. See SAFETY.md for the boundary
that demonstration deliberately stops at.

`finding-03-leak.py` generates the Linux-only research input documented in
`evidence/v3.2.6-linux-x86_64-finding03-leak.md`. Its output is not part of the automated
matrix; use the exact command and digest recorded in that evidence file.

Default output locations differ between the historical generators; Finding 4 defaults to
its canonical fixture path. Pass an explicit temporary output path where supported, or
use a disposable copy. Do not overwrite the canonical fixtures, whose digests are pinned
in `manifest/expectations.json` and checked before every trigger run.
