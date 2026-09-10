#!/usr/bin/env python3
"""Bounded single-case executor and evidence classifier."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import resource
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ACK = "I_UNDERSTAND_THIS_CRASHES_A_LOCAL_PROCESS"
ROOT = Path(__file__).resolve().parent.parent
VALID_SANITIZERS = ("asan", "ubsan", "none")
SANITIZER_SIGNAL = re.compile(r"AddressSanitizer|UndefinedBehaviorSanitizer|runtime error:")


def limit_child(stack_limit: int | None) -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if stack_limit:
        hard = resource.getrlimit(resource.RLIMIT_STACK)[1]
        new_hard = stack_limit if hard == resource.RLIM_INFINITY else min(stack_limit, hard)
        resource.setrlimit(resource.RLIMIT_STACK, (min(stack_limit, new_hard), new_hard))


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("target", choices=("vulnerable", "master", "fixed"))
    parser.add_argument("case_id")
    parser.add_argument("--control", action="store_true")
    parser.add_argument("--profile", choices=("debug", "release"), default="debug")
    return parser.parse_args(argv)


def run_case(args: argparse.Namespace) -> tuple[int, dict]:
    """Execute one case. Returns (exit_code, summary). Never raises for expected errors."""
    manifest = json.loads((ROOT / "manifest" / "expectations.json").read_text())
    try:
        case = manifest["cases"][args.case_id]
    except KeyError:
        return 2, {"case": args.case_id, "status": "ERROR", "error": "unknown case"}
    if case.get("manual"):
        return 2, {
            "case": args.case_id,
            "status": "ERROR",
            "error": "manual case; follow its reproduce sequence in manifest/expectations.json",
        }
    if args.control and not case.get("control"):
        return 2, {"case": args.case_id, "status": "ERROR", "error": "case has no separate control"}

    sanitizer = case["sanitizer"]
    stem = f"{args.target}-{sanitizer}-{args.profile}"
    gdcm_build = ROOT / "_build" / f"{stem}-gdcm"
    harness_build = ROOT / "_build" / f"{stem}-harness"
    if case["kind"] == "gdcmconv":
        executable = gdcm_build / "bin" / "gdcmconv"
    else:
        executable = harness_build / case["executable"]
    if not executable.is_file():
        return 2, {
            "case": args.case_id,
            "status": "ERROR",
            "error": f"missing build output: {executable}; run scripts/build-target.sh "
                     f"{args.target} {sanitizer} {args.profile}",
        }

    fixture = None
    fixture_digest = None
    if args.case_id != "f3-sentinel":
        finding_dir = f"finding-{case['finding']:02d}"
        if args.control:
            fixture = ROOT / "_generated" / "controls" / case["control"]
        else:
            fixture = ROOT / "fixtures" / finding_dir / "trigger.dcm"
        if not fixture.is_file():
            return 2, {
                "case": args.case_id,
                "status": "ERROR",
                "error": f"missing fixture: {fixture}; run scripts/bootstrap.sh first",
            }
        fixture_digest = sha256(fixture)
        # Triggers are pinned: the input a reviewer runs must be the input that was
        # tested. Controls are regenerated locally, so only their digest is recorded.
        if not args.control:
            expected = manifest["fixtures"].get(finding_dir)
            if expected and expected != fixture_digest:
                return 2, {
                    "case": args.case_id,
                    "status": "ERROR",
                    "error": f"fixture digest mismatch for {finding_dir}: "
                             f"expected {expected}, got {fixture_digest}",
                }

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    suffix = "control" if args.control else "trigger"
    run_dir = ROOT / "_runs" / stem / f"{args.case_id}-{suffix}-{stamp}"
    run_dir.mkdir(parents=True)

    replacements = {
        "{fixture}": str(fixture) if fixture else "",
        "{output}": str(run_dir / "out.dcm"),
    }
    command = [str(executable)] + [replacements.get(value, value) for value in case["args"]]

    env = os.environ.copy()
    libdir = str(gdcm_build / "bin")
    for name in ("LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH"):
        env[name] = libdir + (os.pathsep + env[name] if env.get(name) else "")
    env["ASAN_OPTIONS"] = "abort_on_error=1:detect_leaks=0:symbolize=1"
    env["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"

    timed_out = False
    try:
        result = subprocess.run(
            command,
            cwd=run_dir,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            timeout=manifest["timeout_seconds"],
            preexec_fn=lambda: limit_child(case.get("stack_limit_bytes")),
        )
        returncode = result.returncode
        output = result.stdout
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        returncode = None
        partial = exc.stdout or ""
        if isinstance(partial, bytes):
            partial = partial.decode(errors="replace")
        output = partial + "\nTIMEOUT\n"

    (run_dir / "transcript.txt").write_text(output)
    signal_seen = re.search(case["vulnerable_regex"], output, re.MULTILINE) is not None
    sanitizer_seen = SANITIZER_SIGNAL.search(output) is not None
    # A negative return code is a fatal signal (SIGABRT/SIGSEGV/SIGFPE). A patch that
    # replaces a memory error with an uncaught exception still crashes the process, so
    # the fixed-target acceptance must reject it rather than score it as clean.
    killed_by_signal = returncode is not None and returncode < 0

    if args.control:
        allowed = case.get("control_allowed_returncodes", [0])
        ok = not timed_out and not sanitizer_seen and returncode in allowed
        status = "PASS" if ok else "FAIL"
    elif args.target == "vulnerable":
        status = "PASS" if signal_seen and not timed_out else "FAIL"
    elif args.target == "master":
        allowed = case.get("fixed_allowed_returncodes", [0])
        if signal_seen and not timed_out:
            status = "OBSERVED_VULNERABLE"
        elif timed_out:
            status = "TIMEOUT"
        elif sanitizer_seen or killed_by_signal or returncode not in allowed:
            status = "UNEXPECTED_FAILURE"
        else:
            status = "NO_VULNERABLE_SIGNAL"
    else:
        allowed = case.get("fixed_allowed_returncodes", [0, 1])
        ok = (
            not timed_out
            and not signal_seen
            and not sanitizer_seen
            and not killed_by_signal
            and returncode in allowed
        )
        status = "PASS" if ok else "FAIL"

    build_info_path = gdcm_build / "build-info.json"
    build_info = json.loads(build_info_path.read_text()) if build_info_path.is_file() else None

    summary = {
        "case": args.case_id,
        "finding": case["finding"],
        "title": case.get("title"),
        "site": case.get("site"),
        "entry_point": case.get("entry_point"),
        "control": args.control,
        "target": args.target,
        "profile": args.profile,
        "sanitizer": sanitizer,
        "fixture": str(fixture) if fixture else None,
        "fixture_sha256": fixture_digest,
        "command": command,
        "returncode": returncode,
        "killed_by_signal": killed_by_signal,
        "timed_out": timed_out,
        "vulnerable_signal": signal_seen,
        "sanitizer_signal": sanitizer_seen,
        "status": status,
        "run_dir": str(run_dir.relative_to(ROOT)),
        "build": build_info,
    }
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return (1 if status in ("FAIL", "TIMEOUT", "UNEXPECTED_FAILURE") else 0), summary


def main() -> int:
    args = parse_args()
    if os.environ.get("GDCM_REPRO_ACK") != ACK:
        print("read SAFETY.md and set GDCM_REPRO_ACK before execution", file=sys.stderr)
        return 2
    code, summary = run_case(args)
    if summary.get("status") == "ERROR":
        print(summary["error"], file=sys.stderr)
        return code
    print(json.dumps(summary, indent=2))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
