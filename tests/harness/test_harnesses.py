#!/usr/bin/env python3
"""Offline harness regression tests; no MoonBit installation or build required."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[2]
FAKE_TOOL = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys
import time

args = sys.argv[1:]
with open(os.environ["FAKE_LOG"], "a", encoding="utf-8") as log:
    log.write(json.dumps(args) + "\n")
if args == ["check"]:
    print("Finished. 0 errors, 0 warnings.")
    sys.exit(int(os.environ.get("FAKE_CHECK_RC", "0")))
if args[:1] == ["run"]:
    args = args[args.index("--") + 1:]
mode = "scan"
if args[0] == "ir-stats":
    mode = "irstats"
elif args[0] == "call-graph":
    mode = "callgraph"
path = Path(args[-1])
if mode == "scan" and path.name.endswith(".mbt"):
    mode = "isolated"
count = int(os.environ.get("FAKE_COUNT", "0"))
if mode == "irstats":
    n = 2 if os.environ.get("FAKE_C8_GAP") else 3
    output = f"call sites:     {n}\n  bound sites:     {n}/{n}\n"
elif mode == "callgraph":
    output = "site coverage:      0/1 = 0%\n"
elif "--format" in args:
    fmt = args[args.index("--format") + 1]
    if fmt == "json":
        output = json.dumps({"findings": [{"rule_id": "r", "snippet": '"rule_id"'}] * count, "files_scanned": 1})
    elif fmt == "sarif":
        output = json.dumps({"runs": [{"results": [{"ruleId": "r"}] * count}]})
    else:
        output = f"1 files scanned, {count} issues found\n" if count else "No issues found.\n"
else:
    counts = {
        "c1_shadowed_component.mbt": 0, "c2_double_evaluation.mbt": 1,
        "c3_raise_payload.mbt": 2, "c4_loop_propagation.mbt": 1,
        "c5_branch_heap.mbt": 1, "c6_uncalled_closure.mbt": 0,
        "c7_defer_order.mbt": 0, "c8_default_param_call.mbt": 0,
        "c9_orig_same_name_destructure.mbt": 2, "c10_c12_scope_cases.mbt": 3,
        "c13_c14_error_and_dispatch.mbt": 1,
        "deep_c15_summary_collision.mbt": 2,
    }
    if mode == "isolated":
        count = counts[path.name] + int(bool(os.environ.get("FAKE_MISMATCH")))
        output = "".join(f"{path.name}:1:1: warning[r] finding\n" for _ in range(count))
        output += f"1 files scanned, {count} issues found\n" if count else "No issues found.\n"
    else:
        output = "14 files scanned, 12 issues found\n"
    output += "analysis-scope: unsupported-semantics=unknown(not-measured)\n"
if os.environ.get("FAKE_OMIT") == mode:
    output = ""
if os.environ.get("FAKE_JSON") is not None and mode == "scan":
    output = os.environ["FAKE_JSON"]
if "-o" in args:
    Path(args[args.index("-o") + 1]).write_text(output, encoding="utf-8")
else:
    print(output)
if os.environ.get("FAKE_SLEEP") == mode:
    time.sleep(60)
if os.environ.get("FAKE_FAIL") == mode:
    print("injected analyzer failure", file=sys.stderr)
    sys.exit(7)
'''


class HarnessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="moon-audit-harness-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for name in ("moon", "analyzer"):
            tool = self.bin / name
            tool.write_text(FAKE_TOOL, encoding="utf-8")
            tool.chmod(0o755)
        self.tempdir = self.root / "temporary"
        self.tempdir.mkdir()
        self.corpus = self.root / "corpus"
        self.corpus.mkdir()
        self.project = self.corpus / "owner_quoted:' case"
        self.project.mkdir()
        (self.project / "moon.mod").write_text('name = "fake"\n')
        self.log = self.root / "calls.jsonl"
        self.output = self.root / "github-output"
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.env = dict(os.environ)
        for key in list(self.env):
            if key.startswith(("FAKE_", "AUDIT_")):
                del self.env[key]
        self.env.update({
            "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}",
            "MOON_BIN": str(self.bin / "moon"),
            "ANALYZER": str(self.bin / "analyzer"),
            "MOON_AUDIT_BIN": str(self.bin / "analyzer"),
            "MOON_AUDIT_REPO": str(REPO),
            "CORPUS_DIR": str(self.corpus),
            "RESULTS_DIR": str(self.root / "results with ' quotes"),
            "COMMAND_TIMEOUT": "2",
            "TMPDIR": str(self.tempdir),
            "FAKE_LOG": str(self.log),
            "GITHUB_ACTION_PATH": str(REPO),
            "GITHUB_WORKSPACE": str(self.workspace),
            "GITHUB_OUTPUT": str(self.output),
            "AUDIT_UPLOAD_SARIF": "false",
        })

    def run_script(self, script, expected=0, args=(), **env):
        result = subprocess.run(
            ["bash", str(script), *args], cwd=self.root,
            env={**self.env, **env}, text=True, capture_output=True, timeout=15,
        )
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result

    def gate(self, expected=0, **env):
        result = self.run_script(REPO / "tests/cases/run.sh", expected, **env)
        self.assertEqual(list(self.tempdir.iterdir()), [], "temporary projects leaked")
        return result

    def corpus_run(self, expected=0, **env):
        return self.run_script(REPO / "scripts/regression.sh", expected, **env)

    def action(self, expected=0, **env):
        self.output.unlink(missing_ok=True)
        result = self.run_script(REPO / "scripts/action-scan.sh", expected, **env)
        self.assertEqual(list(self.tempdir.iterdir()), [], "temporary reports leaked")
        self.assertEqual(list(self.workspace.glob(".moon-audit.*")), [], "workspace staging directories leaked")
        return result

    def test_cases_success_and_cleanup(self):
        self.assertIn("GATE-OK", self.gate().stdout)

    def test_compiler_failure_despite_success_shaped_output(self):
        self.assertIn("failed to compile", self.gate(2, FAKE_CHECK_RC="7").stderr)

    def test_isolated_failure_cannot_pass_as_zero_findings(self):
        result = self.gate(2, FAKE_FAIL="isolated")
        self.assertIn("injected analyzer failure", result.stderr)
        self.assertIn("c1_shadowed_component.mbt", result.stderr)

    def test_isolated_timeout_is_infrastructure_failure(self):
        self.gate(2, FAKE_SLEEP="isolated", COMMAND_TIMEOUT="1")

    def test_isolated_missing_output_is_infrastructure_failure(self):
        self.gate(2, FAKE_OMIT="isolated")

    def test_missing_case_file_is_infrastructure_failure(self):
        copy = self.root / "repo/tests/cases"
        shutil.copytree(REPO / "tests/cases", copy, ignore=shutil.ignore_patterns("_build", ".mooncakes"))
        (copy / "c1_shadowed_component.mbt").unlink()
        self.run_script(copy / "run.sh", 2)
        self.assertEqual(list(self.tempdir.iterdir()), [])

    def test_case_expectation_mismatch(self):
        self.assertIn("expectation mismatch", self.gate(1, FAKE_MISMATCH="1").stderr)

    def test_c8_requires_default_argument_call(self):
        self.assertIn("C8:", self.gate(1, FAKE_C8_GAP="1").stderr)

    def test_c14_command_failure_cleans_temporary_project(self):
        self.gate(2, FAKE_FAIL="callgraph")

    def test_corpus_paths_with_quotes_spaces_and_colons(self):
        result = self.corpus_run()
        self.assertIn("clean", result.stdout)
        report = Path(self.env["RESULTS_DIR"]) / self.project.name
        self.assertEqual((report / "scan.exit-code").read_text(), "0\n")
        self.assertEqual(json.loads((report / "scan.json").read_text())["files_scanned"], 1)

    def test_corpus_findings_are_successful_measurements(self):
        self.assertIn("findings", self.corpus_run(FAKE_COUNT="2").stdout)

    def test_corpus_command_failures_are_retained(self):
        for mode in ("scan", "irstats", "callgraph"):
            with self.subTest(mode=mode):
                result = self.corpus_run(1, FAKE_FAIL=mode)
                self.assertIn("ERR", result.stdout)
                report = Path(self.env["RESULTS_DIR"]) / self.project.name
                self.assertEqual((report / f"{mode}.exit-code").read_text(), "7\n")
                self.assertIn("injected analyzer failure", (report / f"{mode}.stderr").read_text())

    def test_corpus_rejects_malformed_reports(self):
        for report in ("not json", "[]", "{}", '{"findings":[],"files_scanned":true}', '{"findings":{},"files_scanned":1}'):
            with self.subTest(report=report):
                self.assertIn("invalid scan report", self.corpus_run(1, FAKE_JSON=report).stderr)

    def test_corpus_rejects_missing_measurements(self):
        for mode in ("irstats", "callgraph"):
            with self.subTest(mode=mode):
                self.corpus_run(1, FAKE_OMIT=mode)

    def test_corpus_timeout(self):
        self.corpus_run(1, FAKE_SLEEP="scan", COMMAND_TIMEOUT="1")

    def test_corpus_continues_after_errors(self):
        second = self.corpus / "second"
        second.mkdir()
        (second / "moon.mod").write_text('name = "second"\n')
        result = self.corpus_run(1, FAKE_FAIL="scan")
        self.assertIn(self.project.name, result.stdout)
        self.assertIn("second", result.stdout)
        self.assertEqual(len(self.log.read_text().splitlines()), 6)

    def test_empty_corpus_does_not_include_machine_local_extras(self):
        shutil.rmtree(self.project)
        self.assertIn("no corpus projects", self.corpus_run(2).stderr)

    def test_record_pins_respects_corpus_and_repo_overrides(self):
        repo = self.root / "pin-repo"
        (repo / "docs/ir").mkdir(parents=True)
        self.run_script(REPO / "scripts/regression.sh", args=("--record-commit",), MOON_AUDIT_REPO=str(repo))
        pins = (repo / "docs/ir/regression-baseline.md").read_text()
        self.assertIn(self.project.name + ": no-git", pins)

    def test_action_zero_findings_are_one_valid_output(self):
        for fmt in ("json", "sarif", "text"):
            with self.subTest(format=fmt):
                self.action(AUDIT_FORMAT=fmt, AUDIT_FAIL_ON_FINDINGS="true")
                lines = self.output.read_text().splitlines()
                self.assertEqual([line for line in lines if line.startswith("findings-count=")], ["findings-count=0"])
                self.assertEqual(len(lines), 2)

    def test_action_counts_compact_json_and_sarif_exactly(self):
        for fmt in ("json", "sarif", "text"):
            with self.subTest(format=fmt):
                self.action(AUDIT_FORMAT=fmt, FAKE_COUNT="2")
                self.assertIn("findings-count=2\n", self.output.read_text())

    def test_action_treats_path_input_as_literal_data(self):
        marker = self.root / "command-was-executed"
        target = f"project ' $(touch {marker})"
        self.action(AUDIT_PATH=target, AUDIT_FORMAT="json")
        self.assertFalse(marker.exists())
        call = json.loads(self.log.read_text().splitlines()[-1])
        self.assertEqual(call[-1], str(self.workspace / target))

    def test_action_findings_failure_preserves_report_and_sarif_outputs(self):
        self.action(1, AUDIT_FORMAT="json", FAKE_COUNT="2", AUDIT_FAIL_ON_FINDINGS="true", AUDIT_UPLOAD_SARIF="true")
        self.assertIn("findings-count=2\n", self.output.read_text())
        self.assertIn("sarif-file=", self.output.read_text())
        self.assertTrue((self.workspace / "moon-audit-results.sarif").is_file())

    def test_action_invalid_report_does_not_accept_stale_artifact(self):
        stale = self.workspace / "moon-audit-results.json"
        stale.write_text('{"findings":[]}')
        self.action(1, AUDIT_FORMAT="json", FAKE_JSON="invalid")
        self.assertFalse(self.output.exists())
        self.assertEqual(stale.read_text(), '{"findings":[]}')

    def test_action_command_failure_does_not_publish_outputs(self):
        self.action(7, AUDIT_FORMAT="json", FAKE_FAIL="scan")
        self.assertFalse(self.output.exists())

    def test_action_validates_enumerated_inputs(self):
        for env in ({"AUDIT_FORMAT": "../unexpected"}, {"AUDIT_SEVERITY": "bogus"}, {"AUDIT_FAIL_ON_FINDINGS": "yes"}):
            with self.subTest(env=env):
                self.action(2, **env)
                self.assertFalse(self.output.exists())
        self.assertFalse(self.log.exists())

    def test_action_report_directory_is_not_published_as_a_file(self):
        target = self.workspace / "moon-audit-results.json"
        target.mkdir()
        self.action(1, AUDIT_FORMAT="json")
        self.assertFalse(self.output.exists())
        self.assertEqual(list(target.iterdir()), [])

    def test_action_sarif_directory_does_not_upload_stale_reports(self):
        target = self.workspace / "moon-audit-results.sarif"
        target.mkdir()
        stale = target / "previous.sarif"
        stale.write_text('{"runs": [{"results": []}]}')
        self.action(1, AUDIT_FORMAT="json", AUDIT_UPLOAD_SARIF="true")
        self.assertIn("findings-count=0\n", self.output.read_text())
        self.assertNotIn("sarif-file=", self.output.read_text())
        self.assertEqual(list(target.iterdir()), [stale])

    def test_action_atomically_replaces_a_report_symlink(self):
        stale = self.root / "previous.json"
        stale.write_text("previous report")
        target = self.workspace / "moon-audit-results.json"
        target.symlink_to(stale)
        self.action(AUDIT_FORMAT="json")
        self.assertFalse(target.is_symlink())
        self.assertEqual(json.loads(target.read_text())["findings"], [])
        self.assertEqual(stale.read_text(), "previous report")

    def install(self, expected=0, **env):
        curl = self.bin / "curl"
        curl.write_text(r'''#!/usr/bin/env python3
import os
from pathlib import Path
import sys

log = Path(os.environ["FAKE_DOWNLOAD_LOG"])
attempt = int(log.read_text()) + 1 if log.exists() else 1
log.write_text(str(attempt))
installer = Path(sys.argv[sys.argv.index("--output") + 1])
installer.write_text("""#!/usr/bin/env bash
attempt=0
[ ! -f "$FAKE_INSTALL_LOG" ] || attempt=$(cat "$FAKE_INSTALL_LOG")
attempt=$((attempt + 1))
printf '%s' "$attempt" > "$FAKE_INSTALL_LOG"
[ "$attempt" -gt "${FAKE_INSTALL_FAILURES:-0}" ]
""")
if attempt <= int(os.environ.get("FAKE_DOWNLOAD_FAILURES", "0")):
    print("injected download failure", file=sys.stderr)
    sys.exit(22)
''', encoding="utf-8")
        curl.chmod(0o755)
        result = self.run_script(
            REPO / "scripts/install-moon.sh", expected,
            FAKE_DOWNLOAD_LOG=str(self.root / "downloads"),
            FAKE_INSTALL_LOG=str(self.root / "installs"),
            MOON_INSTALL_ATTEMPTS="3", MOON_INSTALL_RETRY_DELAY="0", **env,
        )
        self.assertEqual(list(self.tempdir.iterdir()), [], "temporary installer leaked")
        return result

    def test_install_retries_a_failed_download(self):
        self.install(FAKE_DOWNLOAD_FAILURES="1")
        self.assertEqual((self.root / "downloads").read_text(), "2")
        self.assertEqual((self.root / "installs").read_text(), "1")

    def test_install_retries_failed_core_installation(self):
        self.install(FAKE_INSTALL_FAILURES="1")
        self.assertEqual((self.root / "downloads").read_text(), "2")
        self.assertEqual((self.root / "installs").read_text(), "2")

    def test_install_never_executes_a_partial_download(self):
        self.install(1, FAKE_DOWNLOAD_FAILURES="3")
        self.assertEqual((self.root / "downloads").read_text(), "3")
        self.assertFalse((self.root / "installs").exists())

    def test_install_fails_after_bounded_installer_attempts(self):
        self.install(1, FAKE_INSTALL_FAILURES="3")
        self.assertEqual((self.root / "downloads").read_text(), "3")
        self.assertEqual((self.root / "installs").read_text(), "3")

    def test_sarif_counter_adds_multiple_runs(self):
        report = self.root / "multiple.sarif"
        report.write_text(json.dumps({"runs": [{"results": [{}]}, {"results": [{}, {}]}]}))
        result = subprocess.run(["python3", str(REPO / "scripts/count-findings.py"), "sarif", str(report)], text=True, capture_output=True, check=True)
        self.assertEqual(result.stdout, "3\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
