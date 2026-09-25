#!/usr/bin/env python3
# Legacy full-framework gate: requires the pre-redesign analyzer.
# Current syntax-pattern scans do not satisfy these semantic contracts.
# See docs/redesign-2026-09-22.md for the recovery point and active gates.
"""Compare scan binaries with alternating runs and report-equivalence checks."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import time


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def findings_key(report):
    findings = report.get("findings")
    if not isinstance(findings, list):
        raise ValueError("report is missing its findings array")
    normalized = []
    for finding in findings:
        if not isinstance(finding, dict):
            raise ValueError("finding is not an object")
        entry = dict(finding)
        entry["file"] = str(Path(entry["file"]).resolve())
        normalized.append(json.dumps(entry, sort_keys=True, ensure_ascii=False))
    errors = report.get("errors")
    if not isinstance(errors, list):
        raise ValueError("report is missing its errors array")
    files = report.get("files_scanned")
    if type(files) is not int or files < 0:
        raise ValueError("files_scanned must be a nonnegative integer")
    return sorted(normalized), sorted(errors), files


def run(binary, project, timeout):
    started = time.perf_counter()
    result = subprocess.run(
        [str(binary), "--format", "json", str(project)],
        capture_output=True, text=True, encoding="utf-8", timeout=timeout,
    )
    elapsed = time.perf_counter() - started
    if result.returncode not in (0, 2):
        raise ValueError(f"scan exited {result.returncode}: {result.stderr[-500:]}")
    report = json.loads(result.stdout)
    if not isinstance(report, dict):
        raise ValueError("report must be a JSON object")
    key = findings_key(report)
    # Older versions returned 0 on parse errors; preserve that distinction.
    if result.returncode == 2 and not report["errors"]:
        raise ValueError("scan failed without structured file diagnostics")
    return elapsed, report, key, result.returncode


def project_state(path):
    revision = subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"], capture_output=True, text=True)
    status = subprocess.run(["git", "-C", str(path), "status", "--porcelain", "--untracked-files=no"], capture_output=True, text=True)
    return {"git_revision": revision.stdout.strip() if revision.returncode == 0 else None,
            "tracked_worktree_status": status.stdout.splitlines() if status.returncode == 0 else None}


def describe_binary(path):
    return {"path": str(path), "sha256": digest(path)}


def save(path, result):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-bin", type=Path, required=True)
    parser.add_argument("--candidate-bin", type=Path, required=True)
    parser.add_argument("--project", type=Path, action="append", required=True)
    parser.add_argument("--iterations", type=int, default=5)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--timeout", type=float, default=180)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.iterations < 2 or args.warmups < 0 or args.timeout <= 0:
        parser.error("iterations must be >= 2, warmups >= 0, and timeout > 0")
    binaries = {"baseline": args.baseline_bin.resolve(), "candidate": args.candidate_bin.resolve()}
    for binary in binaries.values():
        if not binary.is_file() or not os.access(binary, os.X_OK):
            parser.error(f"not an executable: {binary}")
    projects = [p.resolve() for p in args.project]
    for project in projects:
        if not project.is_dir():
            parser.error(f"not a project directory: {project}")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    result = {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "platform": platform.platform(), "cpu_count": os.cpu_count(),
        "binaries": {role: describe_binary(binary) for role, binary in binaries.items()},
        "method": {
            "clock": "time.perf_counter wall seconds, includes process startup and JSON output",
            "order": "alternating baseline/candidate then candidate/baseline",
            "warmup_pairs": args.warmups, "measured_pairs": args.iterations,
            "timeout_seconds": args.timeout,
            "equivalence": "all finding fields, multiplicity, file errors, and files_scanned; excludes analysis_scope metadata",
            "limitations": "same local host; filesystem cache warm; no CPU isolation or release-build inference; source revision/status checked, ignored dependency contents must remain unchanged",
        },
        "projects": [], "complete": False,
    }
    save(args.output, result)
    failed = False
    for project in projects:
        row = {"path": str(project), "source_state": project_state(project),
               "samples_seconds": {role: [] for role in binaries}, "equivalent": True}
        result["projects"].append(row)
        expected = None
        try:
            for index in range(args.warmups + args.iterations):
                roles = ["baseline", "candidate"] if index % 2 == 0 else ["candidate", "baseline"]
                for role in roles:
                    elapsed, report, key, exit_code = run(binaries[role], project, args.timeout)
                    if expected is None:
                        expected = key
                    if key != expected:
                        raise ValueError(f"{role} report differs from the first baseline scan")
                    row.setdefault("exit_codes", {})[role] = exit_code
                    row["findings"] = len(report["findings"])
                    row["file_errors"] = len(report["errors"])
                    row["files_scanned"] = report["files_scanned"]
                    if index >= args.warmups:
                        row["samples_seconds"][role].append(elapsed)
                    save(args.output, result)
            if project_state(project) != row["source_state"]:
                raise ValueError("tracked source state changed during measurement")
            row["statistics"] = {
                role: {"median_seconds": statistics.median(samples), "min_seconds": min(samples), "max_seconds": max(samples)}
                for role, samples in row["samples_seconds"].items()
            }
            row["speedup_baseline_over_candidate"] = row["statistics"]["baseline"]["median_seconds"] / row["statistics"]["candidate"]["median_seconds"]
        except (OSError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
            row["equivalent"] = False
            row["error"] = str(error)
            failed = True
        save(args.output, result)
        print(json.dumps(row, ensure_ascii=False), flush=True)
    # Hash both artifacts again so a rebuild during measurement cannot go unnoticed.
    for role, binary in binaries.items():
        if digest(binary) != result["binaries"][role]["sha256"]:
            result["error"] = "binary changed during measurement: " + role
            failed = True
    result["complete"] = not failed
    result["finished_at"] = datetime.now(timezone.utc).isoformat()
    save(args.output, result)
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
