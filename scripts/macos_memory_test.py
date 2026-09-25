#!/usr/bin/env python3
"""Darwin production-worker memory injection; Python is only the CI driver."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

from native_semantic_test import Acceptance, HINT_ID, require


def alive(pid):
    result = subprocess.run(["ps", "-p", str(pid), "-o", "stat="],
                            capture_output=True, text=True, timeout=5)
    return result.returncode == 0 and bool(result.stdout.strip()) and not result.stdout.strip().startswith("Z")


def diagnostics(text):
    events = []
    for line in text.splitlines():
        marker = "MOON_AUDIT_MEMORY "
        if marker in line:
            try:
                events.append(json.loads(line.split(marker, 1)[1]))
            except json.JSONDecodeError:
                pass
    return events


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("analyzer", "helper", "toolchain", "corpus", "output"):
        parser.add_argument("--" + option, required=True, type=Path)
    args = parser.parse_args()
    if sys.platform != "darwin":
        parser.error("Run on real macOS; Linux cannot validate Darwin memory supervision")
    record = {"schema": "moon-audit.macos-memory-acceptance.v1", "platform": sys.platform,
              "status": "failed", "threshold_bytes": 2048 * 1024 * 1024,
              "limits": ["50ms sampling threshold; allocations and scheduler delays can cause transient overshoot.",
                         "Physical footprint is summed over the isolated process group; it is not an allocation-time hard cap."]}
    started = time.monotonic()
    pids = set()
    try:
        with tempfile.TemporaryDirectory(prefix="moon-audit-mac-memory-") as temp:
            work = Path(temp)
            acceptance = Acceptance(args, work)
            marker, sentinel = work / "allocators.jsonl", work / "survived"
            env = os.environ | {
                "MOON_HOME": str(args.toolchain.resolve()),
                "PATH": str(args.toolchain.resolve() / "bin") + os.pathsep + os.environ.get("PATH", ""),
                "MOON_AUDIT_TEST_MODE": "semantic-memory",
                "MOON_AUDIT_TEST_REAL_MOON": str(args.toolchain.resolve() / "bin/moon"),
                "MOON_AUDIT_TEST_MEMORY_LOG": str(marker),
                "MOON_AUDIT_TEST_SENTINEL": str(sentinel),
            }
            command = [str(acceptance.analyzer), "--analysis", "semantic", "--verify-project",
                       "--semantic-scope", "mocket-get-callbacks", "--project-moon",
                       str(args.helper.resolve()), "--timeout-seconds", "45", "--format", "json",
                       str(acceptance.project)]
            result = subprocess.run(command, env=env, capture_output=True, text=True,
                                    encoding="utf-8", timeout=90)
            entries = [json.loads(line) for line in marker.read_text().splitlines()] if marker.exists() else []
            pids = {entry["pid"] for entry in entries}
            report = json.loads(result.stdout)
            reason = (report.get("semantic_analysis") or {}).get("reason", "")
            events = diagnostics(result.stderr + "\n" + reason)
            record.update(analyzer_sha256=acceptance.record["analyzer_sha256"], command=command,
                          exit_code=result.returncode, stderr=result.stderr, report=report,
                          allocations=entries, diagnostics=events)
            require(result.returncode == 2, "Oversized group must return incomplete exit 2")
            require(report["project_verification"]["status"] == "compiler_verified", "Injection ran before project compilation")
            require(any(f["rule_id"] == HINT_ID and f["evidence"] == "syntax_hint" for f in report["findings"]),
                    "Memory cancellation discarded the basic syntax finding")
            require(report.get("errors") and report.get("semantic_analysis", {}).get("status") == "incomplete",
                    "Memory cancellation did not disclose incomplete semantic analysis")
            exhausted = [event for event in events if event.get("event") == "budget_exhausted"]
            require(exhausted, "Missing production watchdog budget_exhausted diagnostic")
            require(any(event.get("event") == "monitor_started" for event in events), "Watchdog startup was not recorded")
            event = exhausted[-1]
            require(event["limit_bytes"] == record["threshold_bytes"] and event["observed_bytes"] > event["limit_bytes"],
                    "Recorded physical footprint did not exceed the real 2 GiB threshold")
            require(event["sample_interval_ms"] == 50 and event["sample_gap_ms"] > 0 and event["elapsed_ms"] > 0,
                    "Sampling/scheduling diagnostic missing")
            require(len(pids) >= 3, "Native parent/child/grandchild allocator chain was not reached")
            require(all(entry["group"] == event["group"] for entry in entries), "Allocator escaped the supervised group")
            require(any(entry["parent"] in pids and any(parent["pid"] == entry["parent"] and parent["parent"] in pids
                        for parent in entries) for entry in entries), "No actual native grandchild was observed")
            deadline = time.monotonic() + 5
            while any(alive(pid) for pid in pids) and time.monotonic() < deadline:
                time.sleep(0.05)
            survivors = [pid for pid in pids if alive(pid)]
            record["surviving_allocator_pids"] = survivors
            require(not survivors and not sentinel.exists(), "Memory cancellation leaked a live descendant")
            require(not any(entry["event"] in ("allocation_failed", "survived") for entry in entries),
                    "Host allocation failure or allocator survival replaced watchdog termination")
            record["status"] = "passed"
    except Exception as error:
        record["error"] = str(error)
    finally:
        # A failing acceptance must not leave its own memory consumers alive.
        for pid in pids:
            if alive(pid):
                try:
                    os.kill(pid, 9)
                except ProcessLookupError:
                    pass
        record["seconds"] = round(time.monotonic() - started, 3)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"status": record["status"], "seconds": record["seconds"], "error": record.get("error")}))
    return 0 if record["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
