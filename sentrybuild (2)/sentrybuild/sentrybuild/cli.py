"""SentryBuild command-line interface.

Subcommands:
  scan      Scan a file or directory of ELF binaries, emit a JSON snapshot.
  diff      Compare two snapshots (or snapshot directories) and report drift.
  baseline  Convenience alias for `scan` that writes to a canonical baseline file.
  verify    Scan a target fresh and diff it against a stored baseline in one step.

Exit codes (useful for CI gating):
  0  no findings at or above the configured failure threshold
  1  findings at or above the threshold were found
  2  usage / runtime error (bad path, unreadable file, etc.)
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, List, Optional

from . import __version__
from .diff_engine import diff_scan_lists, diff_scans, SEVERITY_ORDER
from .elf_scanner import scan_directory, scan_file


def _write_json(data: Any, output_path: Optional[str]) -> None:
    text = json.dumps(data, indent=2, sort_keys=False)
    if output_path:
        with open(output_path, "w") as f:
            f.write(text + "\n")
    else:
        print(text)


def _load_json(path: str) -> Any:
    with open(path, "r") as f:
        return json.load(f)


def _print_findings_human(findings: List[Dict[str, str]]) -> None:
    if not findings:
        print("No findings.")
        return
    order = {"CRITICAL": 0, "WARNING": 1, "INFO": 2}
    for f in sorted(findings, key=lambda x: order.get(x["severity"], 3)):
        print(f"[{f['severity']:8}] {f['code']}: {f['message']}")


def cmd_scan(args: argparse.Namespace) -> int:
    try:
        if args.recursive or _is_dir(args.target):
            data: Any = scan_directory(args.target, recursive=True)
        else:
            data = scan_file(args.target)
    except FileNotFoundError:
        print(f"error: no such file or directory: {args.target}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    _write_json(data, args.output)
    return 0


def cmd_baseline(args: argparse.Namespace) -> int:
    args.output = args.baseline_file
    return cmd_scan(args)


def cmd_diff(args: argparse.Namespace) -> int:
    try:
        base = _load_json(args.baseline)
        cand = _load_json(args.candidate)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error reading snapshot: {exc}", file=sys.stderr)
        return 2

    if isinstance(base, list) or isinstance(cand, list):
        base_list = base if isinstance(base, list) else [base]
        cand_list = cand if isinstance(cand, list) else [cand]
        report = diff_scan_lists(base_list, cand_list)
        if args.format == "json":
            _write_json(report, args.output)
        else:
            for r in report["reports"]:
                label = r.get("candidate_path") or r.get("baseline_path")
                print(f"=== {label} ===")
                _print_findings_human(r["findings"])
                print()
            print(f"Summary: {report['summary']} (max severity: {report['max_severity']})")
        max_sev = report["max_severity"]
    else:
        report = diff_scans(base, cand)
        if args.format == "json":
            _write_json(report, args.output)
        else:
            _print_findings_human(report["findings"])
            print(f"\nSummary: {report['summary']} (max severity: {report['max_severity']})")
        max_sev = report["max_severity"]

    threshold = args.fail_on
    if threshold and SEVERITY_ORDER[max_sev] >= SEVERITY_ORDER[threshold]:
        return 1
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    try:
        if _is_dir(args.target):
            candidate: Any = scan_directory(args.target, recursive=True)
        else:
            candidate = scan_file(args.target)
    except FileNotFoundError:
        print(f"error: no such file or directory: {args.target}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    try:
        baseline = _load_json(args.baseline)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error reading baseline: {exc}", file=sys.stderr)
        return 2

    if isinstance(baseline, list) or isinstance(candidate, list):
        base_list = baseline if isinstance(baseline, list) else [baseline]
        cand_list = candidate if isinstance(candidate, list) else [candidate]
        report = diff_scan_lists(base_list, cand_list)
        if args.format == "json":
            _write_json(report, args.output)
        else:
            for r in report["reports"]:
                label = r.get("candidate_path") or r.get("baseline_path")
                print(f"=== {label} ===")
                _print_findings_human(r["findings"])
                print()
            print(f"Summary: {report['summary']} (max severity: {report['max_severity']})")
        max_sev = report["max_severity"]
    else:
        report = diff_scans(baseline, candidate)
        if args.format == "json":
            _write_json(report, args.output)
        else:
            _print_findings_human(report["findings"])
            print(f"\nSummary: {report['summary']} (max severity: {report['max_severity']})")
        max_sev = report["max_severity"]

    threshold = args.fail_on
    if threshold and SEVERITY_ORDER[max_sev] >= SEVERITY_ORDER[threshold]:
        return 1
    return 0


def _is_dir(path: str) -> bool:
    import os

    return os.path.isdir(path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentrybuild",
        description=(
            "Detect supply-chain tampering and unauthorized IFUNC/GOT/PLT "
            "hooking by scanning ELF binaries and diffing against a trusted baseline."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Scan a file or directory and emit a JSON snapshot.")
    p_scan.add_argument("target", help="Path to an ELF file or a directory to scan.")
    p_scan.add_argument("-o", "--output", help="Write JSON snapshot to this file instead of stdout.")
    p_scan.add_argument(
        "-r", "--recursive", action="store_true", help="Recurse into subdirectories."
    )
    p_scan.set_defaults(func=cmd_scan)

    p_baseline = sub.add_parser(
        "baseline", help="Scan a target and save it as a named baseline snapshot."
    )
    p_baseline.add_argument("target", help="Path to an ELF file or a directory to scan.")
    p_baseline.add_argument("baseline_file", help="Output path for the baseline JSON snapshot.")
    p_baseline.add_argument(
        "-r", "--recursive", action="store_true", help="Recurse into subdirectories."
    )
    p_baseline.set_defaults(func=cmd_baseline)

    p_diff = sub.add_parser(
        "diff", help="Compare two JSON snapshots (single-file or directory scans)."
    )
    p_diff.add_argument("baseline", help="Path to the baseline JSON snapshot.")
    p_diff.add_argument("candidate", help="Path to the candidate JSON snapshot.")
    p_diff.add_argument("-o", "--output", help="Write the diff report to this file instead of stdout.")
    p_diff.add_argument(
        "--format", choices=["human", "json"], default="human", help="Output format (default: human)."
    )
    p_diff.add_argument(
        "--fail-on",
        choices=["INFO", "WARNING", "CRITICAL"],
        default="CRITICAL",
        help="Exit non-zero if any finding at/above this severity is found (default: CRITICAL).",
    )
    p_diff.set_defaults(func=cmd_diff)

    p_verify = sub.add_parser(
        "verify", help="Scan a target fresh and diff it against a stored baseline in one step."
    )
    p_verify.add_argument("target", help="Path to an ELF file or a directory to scan now.")
    p_verify.add_argument("baseline", help="Path to a previously saved baseline JSON snapshot.")
    p_verify.add_argument(
        "-o", "--output", help="Write the diff report to this file instead of stdout."
    )
    p_verify.add_argument(
        "--format", choices=["human", "json"], default="human", help="Output format (default: human)."
    )
    p_verify.add_argument(
        "--fail-on",
        choices=["INFO", "WARNING", "CRITICAL"],
        default="CRITICAL",
        help="Exit non-zero if any finding at/above this severity is found (default: CRITICAL).",
    )
    p_verify.set_defaults(func=cmd_verify)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
