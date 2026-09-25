#!/usr/bin/env python3
"""Reproduce one unchanged 2025 project and real compiler scope counterexamples.

Python is a development evidence driver, not a moon-audit runtime dependency.
Downloads are pinned and confined to --work-dir; no project source migration.
"""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import shutil
import shlex
import subprocess
import tarfile
import urllib.request
import zipfile


COMMIT = "04e4d54c0b3cb5a53f2c2530f7eadf546a903f60"
RELEASE = "v0.6.30%2B07d9d2445"
DOWNLOADS = {
    "toolchain.tar.gz": (
        f"https://github.com/chawyehsu/moonbit-binaries/releases/download/{RELEASE}/moonbit-{RELEASE}-x86_64-unknown-linux.tar.gz",
        "c8b1b39daedb64d3fa55364aeafc2d7e74d01564468b1a7145c3369742e6471b",
    ),
    "core.zip": (
        f"https://github.com/chawyehsu/moonbit-binaries/releases/download/{RELEASE}/moonbit-core-{RELEASE}-universal.zip",
        "30b1a2302ce4cb2e3c264bcdce56b41e89f048a0df5594919d37d76ef3913ff9",
    ),
    "project.tar.gz": (
        f"https://codeload.github.com/moonbitlang/quickcheck/tar.gz/{COMMIT}",
        "31d630383cd7b535b5f26c0a6f8e68eaea16b1f5b836a742363858745a212016",
    ),
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fetch(work, allow_download):
    evidence = []
    for name, (url, expected) in DOWNLOADS.items():
        path = work / name
        if not path.is_file():
            if not allow_download:
                raise RuntimeError(f"Missing {path}; use --download to fetch pinned archives")
            request = urllib.request.Request(url, headers={"User-Agent": "moon-audit-historical-evidence"})
            with urllib.request.urlopen(request, timeout=180) as response:
                path.write_bytes(response.read())
        data = path.read_bytes()
        assert sha(data) == expected, f"Checksum mismatch: {name}"
        evidence.append({"name": name, "url": url, "sha256": expected, "bytes": len(data)})
    return evidence


def prepare(work):
    toolchain = work / "toolchain"
    if not (toolchain / "bin/moon").exists():
        with tarfile.open(work / "toolchain.tar.gz") as archive:
            archive.extractall(toolchain, filter="data")
    # The archived original executable modes need restoration on extraction.
    for executable in (toolchain / "bin").iterdir():
        if executable.is_file():
            executable.chmod(executable.stat().st_mode | 0o111)
    if not (toolchain / "lib/core/moon.mod.json").exists():
        with zipfile.ZipFile(work / "core.zip") as archive:
            archive.extractall(work / "core-unpacked")
        shutil.copytree(work / "core-unpacked/core", toolchain / "lib/core", dirs_exist_ok=True)
    project = work / "project" / f"quickcheck-{COMMIT}"
    if not project.exists():
        with tarfile.open(work / "project.tar.gz") as archive:
            archive.extractall(work / "project", filter="data")
    return toolchain, project


def originals(work, project):
    """Compare all archived tracked bytes, excluding nothing based on suffix."""
    results = {}
    with tarfile.open(work / "project.tar.gz") as archive:
        for member in archive:
            if member.isfile():
                relative = Path(member.name).relative_to(f"quickcheck-{COMMIT}")
                expected = sha(archive.extractfile(member).read())
                assert sha((project / relative).read_bytes()) == expected, f"Source changed: {relative}"
                results[str(relative)] = expected
    return results


def environment(toolchain, minimal=False):
    base_path = "" if minimal else os.environ.get("PATH", "")
    search_path = str(toolchain / "bin") + (os.pathsep + base_path if base_path else "")
    return os.environ | {"MOON_HOME": str(toolchain), "PATH": search_path}


def command(args, cwd, env, output, name):
    result = subprocess.run(list(map(str, args)), cwd=cwd, env=env, text=True,
                            capture_output=True, timeout=180, shell=False)
    (output / f"{name}.stdout").write_text(result.stdout, encoding="utf-8")
    (output / f"{name}.stderr").write_text(result.stderr, encoding="utf-8")
    return result


def raw_plan_files(output, project):
    """Independent POSIX transcript parser for this Linux evidence driver."""
    result = set()
    for line in output.splitlines():
        words = shlex.split(line)
        if len(words) >= 2 and Path(words[0]).name in ("moonc", "moonc.exe") and words[1] == "check":
            for word in words[2:]:
                if word.endswith(".mbt"):
                    full = (project / word).resolve()
                    if full.is_relative_to(project) and ".mooncakes" not in full.relative_to(project).parts:
                        result.add(str(full.relative_to(project)))
    return result


def scan_summary(result, project):
    report = json.loads(result.stdout)
    manifest = report["analysis_manifest"]
    verification = report.get("project_verification")
    def relative(path):
        return str(Path(path).relative_to(project))
    return {
        "exit_code": result.returncode,
        "verification_status": verification["status"] if verification else None,
        "toolchain_identity": verification["toolchain"] if verification else None,
        "files_selected": report["files_selected"], "files_parsed": report["files_parsed"],
        "file_status_counts": dict(Counter(f["status"] for f in manifest["files"])),
        "rule_status_counts": dict(Counter(r["status"] for f in manifest["files"] for r in f["rules"])),
        "findings": [{"file": relative(f["file"]), "rule_id": f["rule_id"], "line": f["line"]}
                     for f in report["findings"]],
        "parse_failed": [relative(f["path"]) for f in manifest["files"] if f["status"] == "parse_failed"],
        "compiler_files": [relative(p) for p in verification["compiler_files"]] if verification else [],
        "policy_excluded_files": [relative(p) for p in verification["policy_excluded_files"]] if verification else [],
        "compiler_files_not_parsed": [relative(p) for p in verification["compiler_files_not_parsed"]] if verification else [],
        "errors": [e.replace(str(project), "$PROJECT") for e in report["errors"]],
    }


def scope_cases(base, toolchain, analyzer, output, label):
    source = 'pub fn escape(s : String) -> String { s.replace(old="<", new="&lt;") }\n'
    cases = {
        "backend_package": {"src/main/moon.pkg.json": {}, "src/main/danger.mbt": source,
                            "src/other/moon.pkg.json": {"supported-targets": ["js"]}, "src/other/danger.mbt": source},
        "test_files": {"src/main/moon.pkg.json": {}, "src/main/danger.mbt": source,
                       "src/main/black_test.mbt": "test { assert_eq(1, 1) }\n",
                       "src/main/white_wbtest.mbt": "test { assert_eq(1, 1) }\n"},
        "policy_excluded": {"src/main/moon.pkg.json": {}, "src/main/danger.mbt": source,
                            "src/other/moon.pkg.json": {}, "src/other/danger.mbt": source,
                            ".moon-audit.json": {"exclude": ["other"]}},
        "empty": {"src/main/moon.pkg.json": {}},
    }
    summaries = {}
    for name, files in cases.items():
        project = base / label / name
        project.mkdir(parents=True, exist_ok=True)
        files = {"moon.mod.json": {"name": "fixture/" + name, "source": "src"}, **files}
        for relative, value in files.items():
            path = project / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(value) if isinstance(value, dict) else value, encoding="utf-8")
        env = environment(toolchain)
        prefix = f"{label}-{name}"
        check = command([toolchain / "bin/moon", "check", "--frozen", "--target", "native"], project, env, output, prefix + "-check")
        plan = command([toolchain / "bin/moon", "check", "--frozen", "--target", "native", "--dry-run", "--verbose"], project, env, output, prefix + "-plan")
        assert check.returncode == plan.returncode == 0, (prefix, check.stderr, plan.stderr)
        result = command([analyzer, "--format", "json", "--verify-project", "--project-toolchain", toolchain,
                          "--target", "native", project], base, env, output, prefix + "-scan")
        summary = scan_summary(result, project)
        summary.update(check_exit_code=check.returncode, plan_exit_code=plan.returncode)
        assert set(summary["compiler_files"]) == raw_plan_files(plan.stdout, project), summary
        if name == "empty":
            assert summary["exit_code"] == 2 and summary["verification_status"] == "scope_incomplete", summary
            assert summary["files_selected"] == 0 and summary["compiler_files"] == [], summary
        else:
            assert summary["exit_code"] == 0 and summary["verification_status"] == "compiler_verified", summary
            # The 2025 moon ignores package supported-targets. Follow its real
            # plan rather than applying 2026 manifest semantics to old tools.
            old_backend = name == "backend_package" and label == "historical"
            selected = 2 if old_backend else 1
            assert summary["files_selected"] == summary["files_parsed"] == selected, summary
            assert len(summary["findings"]) == selected, summary
            expected_findings = {"src/main/danger.mbt", "src/other/danger.mbt"} if old_backend else {"src/main/danger.mbt"}
            assert {f["file"] for f in summary["findings"]} == expected_findings, summary
            expected = {"backend_package": (selected, 0), "test_files": (3, 2), "policy_excluded": (2, 1)}[name]
            assert (len(summary["compiler_files"]), len(summary["policy_excluded_files"])) == expected, summary
            assert not summary["compiler_files_not_parsed"], summary
        summaries[name] = summary
    return summaries


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--analyzer", type=Path, required=True)
    parser.add_argument("--scope-toolchain", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--download", action="store_true")
    args = parser.parse_args()
    work, output = args.work_dir.resolve(), args.output.resolve()
    work.mkdir(parents=True, exist_ok=True)
    output.mkdir(parents=True, exist_ok=True)
    downloads = fetch(work, args.download)
    toolchain, project = prepare(work)
    source_before = originals(work, project)
    analyzer = work / "analyzer-under-test"
    shutil.copy2(args.analyzer.resolve(), analyzer)
    env = environment(toolchain)
    bundle = command([toolchain / "bin/moon", "bundle", "--warn-list", "-a", "--all"], toolchain / "lib/core", env, output, "core-bundle")
    assert bundle.returncode == 0, bundle.stderr
    check = command([toolchain / "bin/moon", "check", "--frozen", "--target", "native"], project, env, output, "historical-check")
    plan = command([toolchain / "bin/moon", "check", "--frozen", "--target", "native", "--dry-run", "--verbose"], project, env, output, "historical-plan")
    assert check.returncode == plan.returncode == 0, (check.stderr, plan.stderr)
    scans = {}
    verify_args = ["--verify-project", "--project-toolchain", toolchain, "--target", "native"]
    for name, extra, scan_env in [("syntax", [], env), ("verified", verify_args, env),
                                  ("verified-minimal-path", verify_args, environment(toolchain, minimal=True))]:
        result = command([analyzer, "--format", "json", *extra, project], work, scan_env, output, name)
        scans[name] = scan_summary(result, project)
    verified = scans["verified"]
    assert shutil.which("node", path=environment(toolchain, minimal=True)["PATH"]) is None
    minimal = scans["verified-minimal-path"]
    for key in ("verification_status", "files_selected", "files_parsed", "compiler_files_not_parsed"):
        assert minimal[key] == verified[key], (key, minimal, verified)
    assert "moon 0.1.20251030" in minimal["toolchain_identity"], minimal
    assert "v0.6.30+07d9d2445" in minimal["toolchain_identity"], minimal
    # This acceptance intentionally permits a future parser improvement, never a false clean result.
    assert len(verified["compiler_files"]) == 30, verified
    assert set(verified["compiler_files"]) == raw_plan_files(plan.stdout, project), verified
    assert set(verified["compiler_files"]) == {p for p in source_before if p.endswith(".mbt")}, verified
    assert verified["verification_status"] in ("scope_incomplete", "compiler_verified"), verified
    if verified["parse_failed"]:
        assert verified["exit_code"] == 2 and verified["verification_status"] == "scope_incomplete", verified
        assert set(verified["parse_failed"]) == set(verified["compiler_files_not_parsed"]), verified
    else:
        assert verified["files_parsed"] == 30 and verified["verification_status"] == "compiler_verified", verified
    scopes = {label: scope_cases(work / "scope-fixtures", t, analyzer, output, label)
              for label, t in [("historical", toolchain), ("current", args.scope_toolchain.resolve())]}
    assert originals(work, project) == source_before
    metric = {"schema": "moon-audit.historical-project-evidence.v1", "observed_date": "2026-09-25",
              "platform": "linux-x86_64", "analyzer_sha256": sha(analyzer.read_bytes()),
              "project": {"repository": "https://github.com/moonbitlang/quickcheck", "commit": COMMIT,
                          "commit_date": "2025-10-31T08:55:27Z", "external_dependencies": [],
                          "unchanged_archive_files": len(source_before), "source_hashes": source_before},
              "archives": downloads, "historical_check_exit_code": check.returncode,
              "historical_plan_exit_code": plan.returncode, "scans": scans, "scope_counterexamples": scopes,
              "limits": ["One historical project and Linux only; not blanket backward compatibility",
                         "Compiler verification proves selected project compilation, not security semantics",
                         "Archived toolchain mirror used because original historical endpoint returned HTTP 403",
                         "Parser failures are explicit incomplete results, not successful historical syntax support"]}
    (output / "metrics.json").write_text(json.dumps(metric, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"historical": {k: {f: v[f] for f in ["exit_code", "verification_status", "files_selected", "files_parsed"]} for k,v in scans.items()},
                      "scope_cases": sum(len(v) for v in scopes.values()), "metrics": str(output / "metrics.json")}, indent=2))


if __name__ == "__main__":
    main()
