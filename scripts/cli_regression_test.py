#!/usr/bin/env python3
"""Exercise the built CLI's output, incremental scope, rules, and failure status."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
ANALYZER = Path(os.environ.get("ANALYZER", REPO / "_build/native/debug/build/src/main/main.exe")).resolve()


class CliRegression(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="moon-audit-cli-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "moon.mod").write_text('name = "fixture/cli"\n', encoding="utf-8")
        (self.root / "moon.pkg").write_text("", encoding="utf-8")
        self.source = 'fn html(s : String) -> String { s.replace(old="<", new="&lt;") }\n'
        (self.root / "foo.mbt").write_text(self.source, encoding="utf-8")
        (self.root / "myfoo.mbt").write_text(self.source, encoding="utf-8")

    def run_cli(self, *args, code=0, target=None, cwd=REPO):
        result = subprocess.run(
            [str(ANALYZER), *map(str, args), str(self.root if target is None else target)],
            cwd=cwd, capture_output=True, text=True, encoding="utf-8", timeout=60,
        )
        self.assertEqual(result.returncode, code, f"{args}\nstdout={result.stdout}\nstderr={result.stderr}")
        return result

    def test_incremental_json_exact_and_empty(self):
        changed = self.root / "changed.txt"
        changed.write_text("foo.mbt\n", encoding="utf-8")
        report = json.loads(self.run_cli("--changed-files", changed, "--format", "json").stdout)
        self.assertEqual(report["files_scanned"], 1)
        self.assertEqual(len(report["findings"]), 1)
        self.assertTrue(report["findings"][0]["file"].endswith("/foo.mbt"))
        self.assertIn("incremental=true", report["analysis_scope"])
        for content in ["", "README.md\n", "deleted.mbt\n"]:
            with self.subTest(content=content):
                changed.write_text(content, encoding="utf-8")
                report = json.loads(self.run_cli("--changed-files", changed, "--format", "json").stdout)
                self.assertEqual(report["files_scanned"], 0)
                self.assertEqual(report["findings"], [])
                self.assertIn("incremental=true", report["analysis_scope"])

    def test_incremental_does_not_report_unselected_parse_errors(self):
        (self.root / "broken.mbt").write_text("fn broken( {", encoding="utf-8")
        changed = self.root / "changed.txt"
        for content, expected in [("", 0), ("foo.mbt\n", 1)]:
            with self.subTest(content=content):
                changed.write_text(content, encoding="utf-8")
                report = json.loads(self.run_cli("--format", "json", "--changed-files", changed).stdout)
                self.assertEqual(report["files_scanned"], expected)
                self.assertEqual(report["errors"], [])

    def test_machine_diagnostics_stay_structured(self):
        previous = self.root / "previous.json"
        previous.write_text(self.run_cli("--format", "json").stdout, encoding="utf-8")
        for output_format in ["json", "sarif"]:
            with self.subTest(format=output_format):
                report = json.loads(self.run_cli(
                    "--format", output_format, "--timing", "--ledger", "--baseline-report", previous,
                    "--mode", "deep", "--context-strategy", "call-site-1",
                ).stdout)
                metadata = report["diagnostics"] if output_format == "json" else report["runs"][0]["properties"]
                self.assertIn("timing", metadata)
                self.assertIn("ledger", metadata)
                self.assertTrue(any("not implemented" in message for message in metadata["messages"]))

    def test_rules_enable_disabled_and_accumulate(self):
        (self.root / "cast.mbt").write_text("fn cast_it(value : Int) -> Int { value.cast() }\n", encoding="utf-8")
        report = json.loads(self.run_cli("--format", "json", "--rule", "CWE-704/unsafe-cast").stdout)
        self.assertEqual({f["rule_id"] for f in report["findings"]}, {"CWE-704/unsafe-cast"})
        report = json.loads(self.run_cli(
            "--format", "json", "--rule", "CWE-704/unsafe-cast", "--rule", "CWE-116/replace-escaping",
        ).stdout)
        self.assertEqual({f["rule_id"] for f in report["findings"]}, {"CWE-704/unsafe-cast", "CWE-116/replace-escaping"})

    def test_output_rule_can_run_without_header_rule(self):
        (self.root / "taint-rules.json").write_text(json.dumps({
            "sinks": [{"method": "emit", "kind": "Output", "value_slot": 0}]
        }), encoding="utf-8")
        (self.root / "output.mbt").write_text(
            'fn f(value : String) -> Unit { emit(value) }\n', encoding="utf-8")
        report = json.loads(self.run_cli("--format", "json", "--rule", "CWE-116/tainted-output").stdout)
        self.assertEqual({f["rule_id"] for f in report["findings"]}, {"CWE-116/tainted-output"})

    def test_deep_mode_respects_selected_rules(self):
        (self.root / "cross.mbt").write_text(
            'fn set_custom(resp : Response, value : String) -> Unit { resp.set_header("X", value) }\n'
            'fn go(req : Request, resp : Response) -> Unit { let value = req.query("x"); set_custom(resp, value) }\n',
            encoding="utf-8")
        report = json.loads(self.run_cli("--format", "json", "--mode", "deep", "--rule", "CWE-704/unsafe-cast").stdout)
        self.assertEqual(report["findings"], [])

    def test_baseline_paths_survive_relative_absolute_and_new_checkout(self):
        baseline = self.root / "baseline.json"
        self.run_cli("generate-baseline", "--output", baseline, target=".", cwd=self.root)
        entries = json.loads(baseline.read_text(encoding="utf-8"))
        self.assertEqual({entry["file"] for entry in entries}, {"foo.mbt", "myfoo.mbt"})
        for target, cwd in [(self.root, REPO), (".", self.root)]:
            with self.subTest(target=target):
                report = json.loads(self.run_cli("--format", "json", "--baseline", baseline, target=target, cwd=cwd).stdout)
                self.assertEqual(report["findings"], [])
        with tempfile.TemporaryDirectory(prefix="moon-audit-cli-copy-") as copy_dir:
            copy_root = Path(copy_dir)
            for name in ["moon.mod", "moon.pkg", "foo.mbt", "myfoo.mbt"]:
                (copy_root / name).write_bytes((self.root / name).read_bytes())
            report = json.loads(self.run_cli("--format", "json", "--baseline", baseline, target=copy_root).stdout)
            self.assertEqual(report["findings"], [])

    def test_operational_and_argument_failures(self):
        missing = self.root / "missing"
        invalid = self.root / "invalid.json"
        invalid.write_text("not json", encoding="utf-8")
        for args in [
            ("--changed-files", missing), ("--baseline", missing), ("--baseline", invalid),
            ("--config", missing), ("--config", invalid),
            ("--baseline-report", missing), ("--baseline-report", invalid),
            ("--output", missing / "out.json"), ("--format", "nope"), ("--severity", "nope"),
            ("--mode", "nope"), ("--context-strategy", "nope"), ("--rule", "CWE-000/nope"),
        ]:
            with self.subTest(args=args):
                result = self.run_cli(*args, code=2)
                self.assertNotIn("Output written to:", result.stdout)
        self.run_cli("--format", "json", target=missing, code=2)

    def test_parse_failure_is_a_failed_scan_with_json_report(self):
        (self.root / "broken.mbt").write_text("fn broken( {", encoding="utf-8")
        report = json.loads(self.run_cli("--format", "json", code=2).stdout)
        self.assertGreater(len(report["errors"]), 0)

    def test_incomplete_scan_cannot_replace_baseline(self):
        baseline = self.root / "baseline.json"
        baseline.write_text("existing baseline", encoding="utf-8")
        (self.root / "broken.mbt").write_text("fn broken( {", encoding="utf-8")
        result = self.run_cli("generate-baseline", "--output", baseline, code=2)
        self.assertEqual(baseline.read_text(encoding="utf-8"), "existing baseline")
        self.assertNotIn("Baseline written to:", result.stdout)

    def test_pipeline_reports_parse_failure_without_success(self):
        (self.root / "broken.mbt").write_text("fn broken( {", encoding="utf-8")
        output = self.root / "pipeline"
        result = self.run_cli("pipeline", "--output-dir", output, code=2)
        report = json.loads((output / "scan-results.json").read_text(encoding="utf-8"))
        self.assertTrue(report["errors"])
        self.assertNotIn("pipeline complete", result.stdout.lower())
        self.assertFalse((output / "summary.json").exists())

    def test_report_commands_reject_incomplete_scan(self):
        (self.root / "broken.mbt").write_text("fn broken( {", encoding="utf-8")
        for command in ["summary", "generate-poc", "remediate"]:
            with self.subTest(command=command):
                self.run_cli(command, code=2)

    def test_analysis_commands_reject_missing_target(self):
        for command in ["ir-stats", "call-graph", "dump-analyses"]:
            with self.subTest(command=command):
                result = self.run_cli(command, target=self.root / "missing", code=2, cwd=self.root)
                self.assertIn("path not found", result.stdout)

    def test_scan_subcommands_validate_explicit_config(self):
        missing = self.root / "missing-config.json"
        for command in ["summary", "generate-poc", "remediate", "generate-baseline", "pipeline"]:
            with self.subTest(command=command):
                result = self.run_cli(command, "--config", missing, code=2, cwd=self.root)
                self.assertIn("cannot read config", result.stdout)

    def test_llm_generators_reject_incomplete_scan_before_configuration(self):
        (self.root / "broken.mbt").write_text("fn broken( {", encoding="utf-8")
        for command in ["llm-analyze", "deep-audit"]:
            with self.subTest(command=command):
                result = self.run_cli(command, code=2, cwd=self.root)
                self.assertNotIn("LLM Config:", result.stdout)
                self.assertNotIn("LLM:", result.stdout)
                self.assertFalse((self.root / "deep_audit.py").exists())

    def test_findings_are_informational_unless_requested(self):
        report = json.loads(self.run_cli("--format", "json").stdout)
        self.assertGreater(len(report["findings"]), 0)
        self.run_cli("--format", "json", "--fail-on-error", code=1)

    def test_baseline_does_not_hide_same_code_in_new_file(self):
        (self.root / "myfoo.mbt").unlink()
        baseline = self.root / "baseline.json"
        self.run_cli("generate-baseline", "--output", baseline)
        (self.root / "myfoo.mbt").write_text(self.source, encoding="utf-8")
        report = json.loads(self.run_cli("--format", "json", "--baseline", baseline).stdout)
        self.assertEqual(len(report["findings"]), 1)
        self.assertTrue(report["findings"][0]["file"].endswith("/myfoo.mbt"))

    def test_cross_package_summary_collision(self):
        """IDENT-1: cross-package fn name collision must not pollute summaries.

        a::pick returns first arg; b::pick returns second arg.
        should_alert (b.mbt:5) picks tainted source → must fire.
        should_be_clean (b.mbt:8) picks safe constant → must NOT fire.
        """
        pkg_a = self.root / "a"
        pkg_b = self.root / "b"
        pkg_a.mkdir()
        pkg_b.mkdir()
        (pkg_a / "moon.pkg").write_text("", encoding="utf-8")
        (pkg_b / "moon.pkg").write_text("", encoding="utf-8")
        (self.root / "taint-rules.json").write_text(
            json.dumps({
                "sources": [{"method": "source", "kind": "RequestData"}],
                "sinks": [{"method": "sink", "kind": "HeaderValue", "value_slot": 0}],
            }),
            encoding="utf-8",
        )
        (pkg_a / "a.mbt").write_text(
            "pub fn pick(a : String, b : String) -> String { ignore(b); a }\n",
            encoding="utf-8",
        )
        (pkg_b / "b.mbt").write_text(
            "fn pick(a : String, b : String) -> String { ignore(a); b }\n"
            "fn source() -> String { \"dirty\" }\n"
            "fn sink(value : String) -> Unit { ignore(value) }\n"
            "pub fn should_alert() -> Unit {\n"
            "  sink(pick(\"safe\", source()))\n"
            "}\n"
            "pub fn should_be_clean() -> Unit {\n"
            "  sink(pick(source(), \"safe\"))\n"
            "}\n",
            encoding="utf-8",
        )
        report = json.loads(self.run_cli("--format", "json", "--mode", "deep").stdout)
        findings = report["findings"]
        b_findings = [f for f in findings if f["file"].endswith("/b/b.mbt")]
        alert_lines = [f["line"] for f in b_findings]
        self.assertIn(5, alert_lines, f"should_alert (b.mbt:5) must fire; got lines {alert_lines}")
        self.assertNotIn(8, alert_lines, f"should_be_clean (b.mbt:8) must NOT fire; got lines {alert_lines}")

    def test_sarif_reports_current_version(self):
        report = json.loads(self.run_cli("--format", "sarif").stdout)
        self.assertEqual(report["runs"][0]["tool"]["driver"]["version"], "0.4.0")

    # ── review contract probes (2026-09-20): --cfg-engine identity/dedup ──

    def _new_project(self, rules, files):
        root = self.root / f"proj{len(list(self.root.iterdir()))}"
        root.mkdir()
        (root / "moon.mod").write_text('name = "fixture/contract"\n', encoding="utf-8")
        (root / "moon.pkg").write_text("", encoding="utf-8")
        if rules:
            (root / "taint-rules.json").write_text(json.dumps(rules), encoding="utf-8")
        for name, source in files.items():
            (root / name).write_text(source, encoding="utf-8")
        return root

    def _cfg_findings(self, root, *flags):
        report = json.loads(self.run_cli("--cfg-engine", "--format", "json", *flags, target=root).stdout)
        return report["findings"]

    SINK_RULES = {"sources": [{"method": "source", "kind": "RequestData"}],
                  "sinks": [{"method": "sink", "kind": "HeaderValue", "value_slot": 0}],
                  "sanitizers": [{"method": "sanitize", "kind": "HeaderValue"}]}

    def test_rc_sanitizer_no_fp_under_cfg_engine(self):
        # review case cfg_sanitizer: sanitize(value) must clean before sink
        root = self._new_project(self.SINK_RULES, {"main.mbt": (
            'fn sanitize(value : String) -> String { ignore(value); "safe" }\n'
            'fn sink(value : String) -> Unit { ignore(value) }\n'
            'pub fn go(value : String) -> Unit { sink(sanitize(value)) }\n')})
        self.assertEqual(self._cfg_findings(root), [])

    def test_rc_two_files_two_findings(self):
        # review case cfg_two_files: same-shape sink in two files must not
        # collide into one finding (file must be part of identity)
        src = 'fn sink(value : String) -> Unit { ignore(value) }\nfn source() -> String { "dirty" }\npub fn go() -> Unit { sink(source()) }\n'
        root = self._new_project(self.SINK_RULES, {"a.mbt": src, "b.mbt": src})
        findings = self._cfg_findings(root)
        self.assertEqual(len(findings), 2)
        self.assertEqual({f["file"] for f in findings}, {str(root / "a.mbt"), str(root / "b.mbt")})

    def test_rc_same_line_two_sinks(self):
        # review case dedup_same_line: two call sites on one line report both
        root = self._new_project(self.SINK_RULES, {"main.mbt": (
            'fn sink(value : String) -> Unit { ignore(value) }\n'
            'fn source() -> String { "dirty" }\n'
            'pub fn go() -> Unit { sink(source()); sink(source()) }\n')})
        self.assertEqual(len(self._cfg_findings(root)), 2)

    def test_rc_receiver_sink_single_finding_real_line(self):
        # review case dedup_receiver: method-form sink fires once at real
        # line — no line-0 duplicate
        rules = {"sources": [{"method": "source", "kind": "RequestData"}],
                 "sinks": [{"method": "set_header", "kind": "HeaderValue", "value_slot": 0}]}
        root = self._new_project(rules, {"main.mbt": (
            'fn source() -> String { "dirty" }\n'
            'pub struct Req { }\n'
            'pub fn go(r : Req) -> Unit { r.set_header(source()) }\n')})
        findings = self._cfg_findings(root)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["line"], 3)
        self.assertTrue(findings[0]["file"].endswith("main.mbt"))

    def test_rc_trait_dispatch_exact_lines(self):
        # review case dispatch: only Second impls (lines 8, 10) report;
        # First impls (9, 11) stay clean — summary query must resolve the
        # trait-qualified key via impl_methods
        rules = {"sources": [{"method": "source", "kind": "RequestData"}],
                 "sinks": [{"method": "sink", "kind": "HeaderValue", "value_slot": 0}]}
        root = self._new_project(rules, {"main.mbt": (
            'pub trait Pick { fn pick(Self, String, String) -> String }\n'
            'pub struct First { }\n'
            'pub struct Second { }\n'
            'pub impl Pick for First with fn pick(self, a, b) -> String { ignore(self); ignore(b); a }\n'
            'pub impl Pick for Second with fn pick(self, a, b) -> String { ignore(self); ignore(a); b }\n'
            'fn source() -> String { "dirty" }\n'
            'fn sink(value : String) -> Unit { ignore(value) }\n'
            'pub fn dirty_dot() -> Unit { let x = Second::{}; sink(x.pick("safe", source())) }\n'
            'pub fn clean_dot() -> Unit { let x = First::{}; sink(x.pick("safe", source())) }\n'
            'pub fn dirty_static() -> Unit { sink(Second::pick(Second::{}, "safe", source())) }\n'
            'pub fn clean_static() -> Unit { sink(First::pick(First::{}, "safe", source())) }\n')})
        for engine_flags in ([], ["--cfg-engine"]):
            with self.subTest(engine=engine_flags or ["default"]):
                report = json.loads(self.run_cli("--format", "json", "--mode", "deep", *engine_flags, target=root).stdout)
                self.assertEqual([f["line"] for f in report["findings"]], [8, 10],
                                 f"engine={engine_flags}: {report['findings']}")

    def test_rc_cfg_verify_strict_even_with_cfg_engine(self):
        # review case: --cfg-verify must still run the strict comparison when
        # --cfg-engine is on (safe program must exit 2, not silently pass)
        root = self._new_project(self.SINK_RULES, {"main.mbt": (
            'fn sanitize(value : String) -> String { ignore(value); "safe" }\n'
            'fn sink(value : String) -> Unit { ignore(value) }\n'
            'pub fn go(value : String) -> Unit { sink(sanitize(value)) }\n')})
        # strict verify may legitimately exit 2 on divergence — the CONTRACT
        # is that --cfg-engine must not change the strictness: both runs
        # must produce the SAME exit code (review: engine silently exited 0)
        base = subprocess.run([str(ANALYZER), "--cfg-verify", str(root)], capture_output=True, text=True)
        eng = subprocess.run([str(ANALYZER), "--cfg-verify", "--cfg-engine", str(root)], capture_output=True, text=True)
        self.assertEqual(eng.returncode, base.returncode,
                         f"verify bypassed: base={base.returncode} engine={eng.returncode}")


if __name__ == "__main__":
    if not ANALYZER.is_file():
        raise SystemExit(f"Build moon-audit first or set ANALYZER: {ANALYZER}")
    unittest.main(verbosity=2)
