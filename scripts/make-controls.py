#!/usr/bin/env python3
"""Create deterministic, non-trigger controls without opening them in GDCM."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import struct
import sys
from pathlib import Path

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "_generated" / "controls"


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write(rel: str, data: bytes) -> None:
    path = OUT / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def main() -> None:
    # F1: one frame and RGB metadata remove the YBR expansion from the same RLE shape.
    f1 = load("control_f1", ROOT / "generators" / "finding-01.py")
    tmp1 = OUT / "finding-01" / "generated.dcm"
    tmp1.parent.mkdir(parents=True, exist_ok=True)
    f1.FRAMES = 1
    f1.OUTPUT_FILE = str(tmp1)
    with contextlib.redirect_stdout(io.StringIO()):
        f1.generate_poc()
    data = tmp1.read_bytes().replace(b"YBR_FULL_422", b"RGB         ")
    write("finding-01/control.dcm", data)
    tmp1.unlink()

    # F2: a larger ordinary monochrome image gives the encoder ample output space.
    f2 = load("control_f2", ROOT / "generators" / "finding-02.py")
    write("finding-02/control.dcm", f2.build_dicom(64, 64, bytes(64 * 64)))

    # F3: a single discrete segment whose 16 declared entries are all present.
    f3 = load("control_f3", ROOT / "generators" / "finding-03.py")
    f3.N = 16
    f3.build_segmented_lut = lambda: struct.pack("<HH16H", 0, 16, *range(16))
    tmp3 = OUT / "finding-03" / "control.dcm"
    with contextlib.redirect_stdout(io.StringIO()):
        f3.build_dicom(str(tmp3))

    # F4: the codestream was originally 8-bit. Restore its SIZ precision byte.
    data = bytearray((ROOT / "fixtures" / "finding-04" / "trigger.dcm").read_bytes())
    siz = data.find(b"\xff\x51")
    component_precision = siz + 40
    if siz < 0 or component_precision >= len(data) or data[component_precision] != 0x1E:
        raise RuntimeError("Finding 4 SIZ marker did not match the reviewed fixture")
    data[component_precision] = 0x07
    write("finding-04/control.dcm", bytes(data))

    # F5: the same valid nested-SQ structure at a benign depth.
    f5 = load("control_f5", ROOT / "generators" / "finding-05.py")
    with contextlib.redirect_stdout(io.StringIO()):
        data = f5.build_dicom_file(8)
    write("finding-05/control.dcm", data)

    # F6: a nonzero RLE segment count avoids division by zero; the intentionally
    # empty segment then follows the normal safe decode-failure path.
    data = bytearray((ROOT / "fixtures" / "finding-06" / "trigger.dcm").read_bytes())
    marker = b"\xfe\xff\x00\xe0" + struct.pack("<I", 64)
    item = data.find(marker)
    if item < 0:
        raise RuntimeError("Finding 6 fragment item was not found")
    header = item + len(marker)
    data[header : header + 8] = struct.pack("<II", 1, 64)
    write("finding-06/control.dcm", bytes(data))

    print(f"generated controls under {OUT}")


if __name__ == "__main__":
    main()
