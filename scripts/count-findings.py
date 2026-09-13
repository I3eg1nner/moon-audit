#!/usr/bin/env python3
"""Count report entries, rejecting missing or malformed reports."""
import json
from pathlib import Path
import re
import sys


def count_findings(report_format, path):
    text = Path(path).read_text(encoding="utf-8")
    if report_format == "text":
        counts = re.findall(r"^\d+ files scanned, (\d+) issues found(?:, \d+ errors)?$", text, re.M)
        if len(counts) == 1:
            return int(counts[0])
        if not counts and re.search(r"^No issues found\.$", text, re.M):
            return 0
        raise ValueError("missing or ambiguous text report summary")
    report = json.loads(text)
    if not isinstance(report, dict):
        raise ValueError("expected a report object")
    if report_format == "json":
        findings = report.get("findings")
        if not isinstance(findings, list):
            raise ValueError("expected a findings array")
        return len(findings)
    if report_format == "sarif":
        runs = report.get("runs")
        if not isinstance(runs, list) or not runs:
            raise ValueError("expected a nonempty SARIF runs array")
        count = 0
        for run in runs:
            if not isinstance(run, dict) or not isinstance(run.get("results"), list):
                raise ValueError("expected a SARIF results array in each run")
            count += len(run["results"])
        return count
    raise ValueError(f"unsupported report format: {report_format}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: count-findings.py FORMAT REPORT")
    try:
        print(count_findings(sys.argv[1], sys.argv[2]))
    except (OSError, ValueError) as error:
        sys.exit(f"error: invalid scan report: {error}")
