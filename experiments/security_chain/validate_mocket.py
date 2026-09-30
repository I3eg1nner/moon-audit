#!/usr/bin/env python3
"""Run real mocket dispatch tests in a disposable copy; never fetch dependencies."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import tarfile
import time


HERE = Path(__file__).resolve().parent
IGNORED = {".git", "_build", "target", ".moon-audit-cache", "__pycache__"}
REVIEWED_COMMIT = "af354b7a031ee8e0a7e62e76875b82a0a39ac71b"
EXPECTED = {
    "raw": "<p><img src=x onerror=alert(1)></p>",
    "escaped": "<p>&lt;img src=x onerror=alert(1)&gt;</p>",
    "plain": "<img src=x onerror=alert(1)>",
    "constant": "<p>constant</p>",
    "discarded": "<p>retained</p>",
    "overwritten": "<p>replacement</p>",
    "absent": "<p>missing</p>",
    "script_context": "<script>alert(1)</script>",
}


def fingerprint(root: Path, *, exclude_dependencies: bool = False) -> dict:
    files = {}
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if any(part in IGNORED for part in rel.parts):
            continue
        if exclude_dependencies and ".mooncakes" in rel.parts:
            continue
        if path.is_file():
            files[rel.as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    digest = hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()
    return {"sha256": digest, "file_count": len(files), "files": files}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mocket", type=Path, required=True,
                        help="Existing mocket 0.9.1 checkout/copy with populated .mooncakes")
    parser.add_argument("--moon-wrapper", type=Path, required=True)
    parser.add_argument("--reference-checkout", type=Path, required=True,
                        help="Git checkout containing the reviewed commit, used to verify source provenance")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = args.mocket.resolve()
    wrapper = args.moon_wrapper.resolve()
    if not (source / ".mooncakes").is_dir():
        parser.error("mocket must already contain dependencies; this experiment never installs them")
    manifest = (source / "moon.mod").read_text()
    if 'name = "oboard/mocket"' not in manifest or 'version = "0.9.1"' not in manifest:
        parser.error("this experiment requires the reviewed mocket 0.9.1 source")
    fixture = HERE / "mocket_chain_test.mbt.txt"
    archive = subprocess.check_output([
        "git", "-C", str(args.reference_checkout.resolve()), "archive", REVIEWED_COMMIT,
    ])
    tracked = set()
    with tarfile.open(fileobj=io.BytesIO(archive)) as snapshot:
        for member in snapshot.getmembers():
            if not member.isfile():
                continue
            tracked.add(member.name)
            actual = source / member.name
            if not actual.is_file() or actual.read_bytes() != snapshot.extractfile(member).read():
                parser.error("source differs from reviewed commit: " + member.name)
    source_fingerprint = fingerprint(source, exclude_dependencies=True)
    extra_code = [name for name in source_fingerprint["files"]
                  if name not in tracked and Path(name).suffix in {".mbt", ".mbti", ".c", ".h"}]
    if extra_code:
        parser.error("unexpected code outside reviewed commit: " + ", ".join(extra_code))
    version = subprocess.run([str(wrapper), "moon", "version", "--all"],
                             text=True, capture_output=True, check=True).stdout
    dependencies = {}
    for module in sorted((source / ".mooncakes").glob("*/*")):
        if module.is_dir():
            key = module.relative_to(source / ".mooncakes").as_posix()
            dependencies[key] = fingerprint(module)
            for name in ("moon.mod", "moon.mod.json"):
                if (module / name).exists():
                    dependencies[key]["manifest"] = (module / name).read_text()
    record = {
        "schema_version": 1,
        "purpose": "runtime_model_validation_not_analyzer_acceptance",
        "library": "oboard/mocket", "library_version": "0.9.1",
        "reviewed_corpus_commit": REVIEWED_COMMIT,
        "source_commit_verified": True,
        "source": str(source), "source_fingerprint": source_fingerprint,
        "dependency_fingerprints": dependencies,
        "fixture_sha256": hashlib.sha256(fixture.read_bytes()).hexdigest(),
        "toolchain": version, "target": "native", "dependency_policy": "frozen_no_install",
        "expected_output": EXPECTED,
        "limitations": [
            "No browser executed; output bytes do not establish browser exploitability.",
            "Library dispatch is exercised directly; no listening network server is started.",
            "This is runtime API evidence, not evidence of analyzer binding or IR coverage.",
            "HTML text escaping is not accepted as JavaScript or URL neutralization.",
            "Only the source and dependency hashes recorded here are verified.",
        ],
    }
    with tempfile.TemporaryDirectory(prefix="moon-audit-mocket-chain-") as temp:
        work = Path(temp) / "mocket"
        shutil.copytree(source, work, ignore=shutil.ignore_patterns(*IGNORED))
        shutil.copy2(fixture, work / "mocket_chain_test.mbt")
        command = [str(wrapper), "moon", "test", "--frozen", "--target", "native",
                   "mocket_chain_test.mbt", "--diagnostic-limit", "3"]
        start = time.monotonic()
        result = subprocess.run(command, cwd=work, text=True, capture_output=True)
        record.update(command=command, elapsed_seconds=round(time.monotonic()-start, 3),
                      exit_code=result.returncode, stdout=result.stdout, stderr=result.stderr)
    observed = dict(re.findall(r"SECURITY_CHAIN (\w+) ([^\r\n]*)", result.stdout))
    record["observed_output"] = observed
    test_summary = re.search(r"Total tests: (\d+), passed: (\d+), failed: (\d+)\.",
                             result.stdout + result.stderr)
    record["test_summary"] = test_summary.group(0) if test_summary else None
    passed = result.returncode == 0 and observed == EXPECTED and test_summary is not None
    if test_summary:
        passed = passed and test_summary.groups() == ("8", "8", "0")
    record["status"] = "runtime_api_verified" if passed else "failed"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({"status": record["status"], "tests": record["test_summary"],
                      "output": str(args.output), "observed": observed}, ensure_ascii=False))
    if not passed:
        print(result.stdout)
        print(result.stderr)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
