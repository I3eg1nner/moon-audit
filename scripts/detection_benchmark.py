#!/usr/bin/env python3
"""Automated detection effectiveness regression test.

Runs the scanner on each benchmark case and checks finding counts
against benchmarks/expected.json. Exit 0 = all pass, exit 1 = failures.

Usage:
    python3 scripts/detection_benchmark.py [--verbose]
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BENCHMARKS = ROOT / "benchmarks"
EXPECTED = BENCHMARKS / "expected.json"


def scan_files(rule: str, directory: Path) -> dict[str, list[dict]]:
    """Run scanner with a single rule on a directory, return findings grouped by file."""
    cmd = [
        "moon", "run", "src/main", "--",
        "-f", "json", "-q",
        "--rule", rule,
        str(directory),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT, timeout=60)
    if result.returncode not in (0, 1):
        print(f"  Scanner error (exit {result.returncode}):", file=sys.stderr)
        if result.stderr:
            print(f"  {result.stderr[:500]}", file=sys.stderr)
        return {}
    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError:
        print(f"  Failed to parse scanner JSON output", file=sys.stderr)
        return {}
    grouped: dict[str, list[dict]] = {}
    for finding in report.get("findings", []):
        fname = Path(finding["file"]).name
        grouped.setdefault(fname, []).append(finding)
    return grouped


def run_benchmark(verbose: bool) -> bool:
    with open(EXPECTED) as f:
        spec = json.load(f)

    cases_by_rule: dict[str, list[dict]] = {}
    for case in spec["cases"]:
        cases_by_rule.setdefault(case["rule"], []).append(case)

    total = 0
    passed = 0
    failed_cases = []

    for rule, cases in sorted(cases_by_rule.items()):
        rule_dir_name = cases[0]["file"].split("/")[0]
        rule_dir = BENCHMARKS / rule_dir_name
        if not rule_dir.exists():
            print(f"SKIP  {rule}: directory {rule_dir} not found")
            continue

        findings_by_file = scan_files(rule, rule_dir)

        for case in cases:
            total += 1
            file_basename = Path(case["file"]).name
            count = len(findings_by_file.get(file_basename, []))
            lo, hi = case["expected_min"], case["expected_max"]
            ok = lo <= count <= hi

            if ok:
                passed += 1
                status = "PASS"
            else:
                status = "FAIL"
                failed_cases.append((case, count))

            if verbose or not ok:
                expected_str = f"{lo}" if lo == hi else f"{lo}-{hi}"
                print(f"  {status}  {case['file']}: got {count}, expected {expected_str}")
                if verbose and case.get("label"):
                    print(f"        {case['label']}")

    print()
    print(f"Results: {passed}/{total} passed", end="")
    if failed_cases:
        print(f", {len(failed_cases)} FAILED")
    else:
        print()

    if failed_cases:
        print()
        print("Failures:")
        for case, actual in failed_cases:
            expected_str = f"{case['expected_min']}" if case["expected_min"] == case["expected_max"] else f"{case['expected_min']}-{case['expected_max']}"
            print(f"  {case['file']}: expected {expected_str}, got {actual}")
            print(f"    {case['label']}")
        return False

    return True


def main():
    parser = argparse.ArgumentParser(description="Detection effectiveness regression test")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show all results, not just failures")
    args = parser.parse_args()

    print(f"Running detection benchmark ({EXPECTED.relative_to(ROOT)})")
    print()
    ok = run_benchmark(args.verbose)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
