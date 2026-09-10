#!/usr/bin/env python3
"""Run the full case matrix for one or more targets and emit a single report.

Unlike a shell loop, one failing case does not abort the rest: every case runs,
and the aggregate exit status reflects the whole matrix.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

from execute import ACK, ROOT, parse_args as parse_case_args, run_case  # noqa: E402

STATUS_MARK = {
    "PASS": "PASS",
    "SKIPPED": "n/a here",
    "FAIL": "FAIL",
    "OBSERVED_VULNERABLE": "vulnerable",
    "NO_VULNERABLE_SIGNAL": "no signal",
    "UNEXPECTED_FAILURE": "unexpected failure",
    "TIMEOUT": "TIMEOUT",
    "ERROR": "ERROR",
    "MANUAL": "manual",
}


def render_markdown(rows: list[dict], builds: dict[str, dict]) -> str:
    lines = ["# Reproduction matrix", ""]
    if builds:
        lines += [
            "| Target/build | Revision | Profile | Compiler | Platform |",
            "|---|---|---|---|---|",
        ]
        for name, build in sorted(builds.items()):
            compiler = (build.get("compiler") or "").splitlines()[0]
            lines.append(
                f"| `{name}` | `{build.get('revision')}` | `{build.get('profile')}` | "
                f"{compiler} | {build.get('platform')} ({build.get('machine')}) |"
            )
        lines.append("")
    lines += [
        "| Finding | Case | Target | Trigger | Control | Implicated site |",
        "|---|---|---|---|---|---|",
    ]
    for row in rows:
        lines.append(
            f"| {row['finding']} | `{row['case']}` | {row['target']} | "
            f"{STATUS_MARK.get(row['trigger'], row['trigger'])} | "
            f"{STATUS_MARK.get(row['control'], row['control'])} | {row['site'] or ''} |"
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "targets", nargs="*", choices=("vulnerable", "master", "fixed"),
        default=["vulnerable", "master"]
    )
    parser.add_argument("--profile", choices=("debug", "release"), default="debug")
    parser.add_argument("--case", action="append", dest="cases")
    opts = parser.parse_args()

    if os.environ.get("GDCM_REPRO_ACK") != ACK:
        print("read SAFETY.md and set GDCM_REPRO_ACK before execution", file=sys.stderr)
        return 2

    manifest = json.loads((ROOT / "manifest" / "expectations.json").read_text())
    case_ids = opts.cases or list(manifest["cases"])
    targets = opts.targets or ["vulnerable", "master"]

    results: list[dict] = []
    rows: list[dict] = []
    builds: dict[str, dict] = {}
    failures = 0

    host = f"{platform.system()}-{platform.machine()}"

    for target in targets:
        for case_id in case_ids:
            case = manifest["cases"][case_id]
            if case.get("manual"):
                results.append({
                    "case": case_id,
                    "finding": case["finding"],
                    "target": target,
                    "status": "MANUAL",
                    "reproduce": case.get("reproduce", []),
                })
                rows.append({
                    "finding": case["finding"], "case": case_id, "target": target,
                    "site": case.get("site", "").split(",")[0],
                    "trigger": "MANUAL", "control": "n/a",
                })
                print(f"{target:<10} {case_id:<16} {'trigger':<7} MANUAL (see manifest reproduce steps)")
                continue
            # Some cases only mean anything on one platform (the exploitation
            # primitive needs ELF symbol interposition and a fixed load address).
            # Those are not failures anywhere else.
            supported = case.get("platforms")
            if supported and host not in supported:
                results.append({
                    "case": case_id,
                    "finding": case["finding"],
                    "target": target,
                    "status": "SKIPPED",
                    "host": host,
                    "supported_platforms": supported,
                })
                rows.append({
                    "finding": case["finding"], "case": case_id, "target": target,
                    "site": case.get("site", "").split(",")[0],
                    "trigger": "SKIPPED", "control": "n/a",
                })
                print(f"{target:<10} {case_id:<16} {'trigger':<7} SKIPPED ({host} not in {supported})")
                continue
            row = {
                "finding": case["finding"],
                "case": case_id,
                "target": target,
                "site": case.get("site", "").split(",")[0],
                "trigger": "-",
                "control": "n/a",
            }
            for control in (False, True):
                if control and not case.get("control"):
                    continue
                ns = parse_case_args([target, case_id] + (["--control"] if control else []))
                ns.profile = opts.profile
                code, summary = run_case(ns)
                results.append(summary)
                if summary.get("build"):
                    build_key = f"{target}/{summary['sanitizer']}"
                    builds[build_key] = summary["build"]
                row["control" if control else "trigger"] = summary["status"]
                failures += 1 if code else 0
                print(
                    f"{target:<10} {case_id:<16} {'control' if control else 'trigger':<7} "
                    f"{summary['status']}"
                )
                if summary.get("status") == "ERROR":
                    print(f"  {summary['error']}", file=sys.stderr)
            rows.append(row)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = ROOT / "_runs"
    out_dir.mkdir(parents=True, exist_ok=True)
    report = {
        "generated": stamp,
        "profile": opts.profile,
        "targets": targets,
        "builds": builds,
        "results": results,
    }
    (out_dir / f"matrix-{stamp}.json").write_text(json.dumps(report, indent=2) + "\n")
    (out_dir / f"matrix-{stamp}.md").write_text(render_markdown(rows, builds))
    print(f"\nwrote _runs/matrix-{stamp}.json and _runs/matrix-{stamp}.md")
    print(f"{failures} case(s) did not meet expectations")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
