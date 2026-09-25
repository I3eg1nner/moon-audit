#!/usr/bin/env python3
"""Exercise the built CLI's output, incremental scope, rules, and failure status."""
import json
import os
import shutil
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
        checked = subprocess.run(["moon", "check"], cwd=root, capture_output=True, text=True, timeout=120)
        self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
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
        root = self._new_project(self.SINK_RULES, {
            "helpers.mbt": 'fn sink(value : String) -> Unit { ignore(value) }\nfn source() -> String { "dirty" }\n',
            "a.mbt": 'pub fn a() -> Unit { sink(source()) }\n',
            "b.mbt": 'pub fn b() -> Unit { sink(source()) }\n',
        })
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
            'fn Req::set_header(self : Req, value : String) -> Unit { ignore(self); ignore(value) }\n'
            'pub fn go(r : Req) -> Unit { r.set_header(source()) }\n')})
        findings = self._cfg_findings(root)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["line"], 4)
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

    def test_review_cfg_reassignment(self):
        root = self._new_project(json.loads('{"sources": [{"method": "source", "kind": "RequestData"}], "sinks": [{"method": "sink", "kind": "HeaderValue", "value_slot": 0}]}'), {"main.mbt": 'fn sink(value : String) -> Unit { ignore(value) }\npub fn go(value : String) -> Unit {\n  let mut x = value\n  sink(x)\n  x = "safe"\n  sink(x)\n}\n'})
        for flags in ([], ["--cfg-engine"]):
            with self.subTest(engine=flags):
                report = json.loads(self.run_cli("--format", "json", "--mode", "deep", *flags, target=root).stdout)
                self.assertEqual([f["line"] for f in report["findings"]], [4])

    def test_review_cfg_branch_assignment(self):
        root = self._new_project(json.loads('{"sources": [{"method": "source", "kind": "RequestData"}], "sinks": [{"method": "sink", "kind": "HeaderValue", "value_slot": 0}]}'), {"main.mbt": 'fn sink(value : String) -> Unit { ignore(value) }\npub fn go(value : String, cond : Bool) -> Unit {\n  let mut x = value\n  if cond { x = "safe" }\n  sink(x)\n}\n'})
        for flags in ([], ["--cfg-engine"]):
            with self.subTest(engine=flags):
                report = json.loads(self.run_cli("--format", "json", "--mode", "deep", *flags, target=root).stdout)
                self.assertEqual([f["line"] for f in report["findings"]], [5])

    def test_review_cfg_clean_receiver(self):
        root = self._new_project(json.loads('{"sinks": [{"method": "set_header", "kind": "HeaderValue", "value_slot": 0}]}'), {"main.mbt": 'pub struct Response {}\nfn Response::set_header(self : Response, value : String) -> Unit { ignore(self); ignore(value) }\npub fn go(r : Response) -> Unit { r.set_header("safe") }\n'})
        for flags in ([], ["--cfg-engine"]):
            with self.subTest(engine=flags):
                report = json.loads(self.run_cli("--format", "json", "--mode", "deep", *flags, target=root).stdout)
                self.assertEqual([f["line"] for f in report["findings"]], [])

    def test_review_trait_receivers(self):
        root = self._new_project(json.loads('{"sources": [{"method": "source", "kind": "RequestData"}], "sinks": [{"method": "sink", "kind": "HeaderValue", "value_slot": 0}]}'), {"main.mbt": 'pub trait Pick { fn pick(Self, String, String) -> String }\npub struct First {}\npub struct Second {}\npub impl Pick for First with fn pick(self, a, b) -> String { ignore(self); ignore(b); a }\npub impl Pick for Second with fn pick(self, a, b) -> String { ignore(self); ignore(a); b }\nfn source() -> String { "dirty" }\nfn sink(value : String) -> Unit { ignore(value) }\npub fn dirty_dot() -> Unit { let x = Second::{}; sink(x.pick("safe", source())) } // alert\npub fn clean_dot() -> Unit { let x = First::{}; sink(x.pick("safe", source())) }\npub fn dirty_static() -> Unit { sink(Second::pick(Second::{}, "safe", source())) } // alert\npub fn clean_static() -> Unit { sink(First::pick(First::{}, "safe", source())) }\npub fn dirty_alias() -> Unit { let x = Second::{}; let y = x; sink(y.pick("safe", source())) }\npub fn clean_alias() -> Unit { let x = First::{}; let y = x; sink(y.pick("safe", source())) }\npub fn dirty_parameter(x : Second) -> Unit { sink(x.pick("safe", source())) }\npub fn clean_parameter(x : First) -> Unit { sink(x.pick("safe", source())) }\npub fn dirty_shadow() -> Unit { let x = Second::{}; let _ = { let x = First::{}; ignore(x) }; sink(x.pick("safe", source())) }\npub fn clean_shadow() -> Unit { let x = First::{}; let _ = { let x = Second::{}; ignore(x) }; sink(x.pick("safe", source())) }\n'})
        for flags in ([], ["--cfg-engine"]):
            with self.subTest(engine=flags):
                report = json.loads(self.run_cli("--format", "json", "--mode", "deep", *flags, target=root).stdout)
                self.assertEqual([f["line"] for f in report["findings"]], [8, 10, 12, 14, 16])

    def assert_summary_sinks(self, source, imports="", *, cold=True, expected_lines=None):
        """Check a compilable package through the production CLI, cold cache."""
        for name in ["foo.mbt", "myfoo.mbt"]:
            (self.root / name).unlink(missing_ok=True)
        pkg = self.root / "b"
        pkg.mkdir(exist_ok=True)
        (pkg / "moon.pkg").write_text(imports, encoding="utf-8")
        (pkg / "main.mbt").write_text(source, encoding="utf-8")
        (self.root / "taint-rules.json").write_text(json.dumps({
            "sources": [{"method": "source", "kind": "RequestData"}],
            "sinks": [{"method": "sink", "kind": "HeaderValue", "value_slot": 0}],
        }), encoding="utf-8")
        checked = subprocess.run([os.environ.get("MOON_BIN", "moon"), "check"],
                                 cwd=self.root, capture_output=True, text=True, timeout=60)
        self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
        if cold:
            shutil.rmtree(self.root / ".moon-audit-cache", ignore_errors=True)
        expected = [(i, "CWE-113/crlf-injection") for i, line in
                    enumerate(source.splitlines(), 1) if "// alert" in line]
        if expected_lines is not None:
            expected = [(line, "CWE-113/crlf-injection") for line in expected_lines]
        for flags in ([], ["--cfg-engine"]):
            with self.subTest(engine=flags):
                report = json.loads(self.run_cli("--format", "json", "--mode", "deep", *flags).stdout)
                self.assertEqual(report["errors"], [])
                actual = [(f["line"], f["rule_id"]) for f in report["findings"]
                          if f["file"].endswith("/b/main.mbt")]
                self.assertEqual(sorted(actual), expected)

    def test_package_summary_transitivity(self):
        # A root-package homonym must not become b::wrap's callee.
        (self.root / "pick.mbt").write_text(
            'pub fn pick(a : String, b : String) -> String { ignore(b); a }\n',
            encoding="utf-8")
        helper = 'fn pick(a : String, b : String) -> String { ignore(a); b }\n'
        wrapper = 'fn wrap(a : String, b : String) -> String { pick(a, b) }\n'
        uses = (
            'fn source() -> String { "dirty" }\n'
            'fn sink(value : String) -> Unit { ignore(value) }\n'
            'pub fn dirty() -> Unit { sink(wrap("safe", source())) } // alert\n'
            'pub fn clean() -> Unit { sink(wrap(source(), "safe")) }\n')
        for root_name in ["pick", "unrelated_pick"]:
            (self.root / "pick.mbt").write_text(
                f'pub fn {root_name}(a : String, b : String) -> String {{ ignore(b); a }}\n',
                encoding="utf-8")
            for reverse in [False, True]:
                with self.subTest(root_name=root_name, reverse=reverse):
                    self.assert_summary_sinks((wrapper + helper if reverse else helper + wrapper) + uses)

    def test_import_alias_summary_target(self):
        target = self.root / "z"
        target.mkdir()
        (target / "moon.pkg").write_text("", encoding="utf-8")
        (target / "lib.mbt").write_text(
            'pub fn pick(a : String, b : String) -> String { ignore(a); b }\n',
            encoding="utf-8")
        for alias in ["remote", "renamed"]:
            with self.subTest(alias=alias):
                source = (
                    'pub fn pick(a : String, b : String) -> String { ignore(b); a }\n'
                    f'fn wrap(a : String, b : String) -> String {{ @{alias}.pick(a, b) }}\n'
                    'fn source() -> String { "dirty" }\n'
                    'fn sink(value : String) -> Unit { ignore(value) }\n'
                    f'pub fn dirty_direct() -> Unit {{ sink(@{alias}.pick("safe", source())) }} // alert\n'
                    f'pub fn clean_direct() -> Unit {{ sink(@{alias}.pick(source(), "safe")) }}\n'
                    'pub fn dirty_wrap() -> Unit { sink(wrap("safe", source())) } // alert\n'
                    'pub fn clean_wrap() -> Unit { sink(wrap(source(), "safe")) }\n')
                self.assert_summary_sinks(source, f'import {{\n  "fixture/cli/z" @{alias},\n}}\n')

    def test_imported_static_method_summary_target(self):
        target = self.root / "z"
        target.mkdir()
        (target / "moon.pkg").write_text("", encoding="utf-8")
        (target / "lib.mbt").write_text(
            'pub struct Picker {}\n'
            'pub fn Picker::pick(a : String, b : String) -> String { ignore(a); b }\n',
            encoding="utf-8")
        self.assert_summary_sinks(
            'pub struct Picker {}\n'
            'pub fn Picker::pick(a : String, b : String) -> String { ignore(b); a }\n'
            'fn wrap(a : String, b : String) -> String { @remote.Picker::pick(a, b) }\n'
            'fn source() -> String { "dirty" }\n'
            'fn sink(value : String) -> Unit { ignore(value) }\n'
            'pub fn dirty() -> Unit { sink(wrap("safe", source())) } // alert\n'
            'pub fn clean() -> Unit { sink(wrap(source(), "safe")) }\n',
            'import {\n  "fixture/cli/z" @remote,\n}\n')

    def test_imported_root_package_summary(self):
        (self.root / "pick.mbt").write_text(
            'pub fn pick(a : String, b : String) -> String { ignore(a); b }\n',
            encoding="utf-8")
        self.assert_summary_sinks(
            'pub fn pick(a : String, b : String) -> String { ignore(b); a }\n'
            'fn wrap(a : String, b : String) -> String { @base.pick(a, b) }\n'
            'fn source() -> String { "dirty" }\n'
            'fn sink(value : String) -> Unit { ignore(value) }\n'
            'pub fn dirty() -> Unit { sink(wrap("safe", source())) } // alert\n'
            'pub fn clean() -> Unit { sink(wrap(source(), "safe")) }\n',
            'import {\n  "fixture/cli" @base,\n}\n')

    def test_import_alias_change_invalidates_cached_clean_result(self):
        for pkg, ignored, returned in [("a", "b", "a"), ("z", "a", "b")]:
            directory = self.root / pkg
            directory.mkdir()
            (directory / "moon.pkg").write_text("", encoding="utf-8")
            (directory / "lib.mbt").write_text(
                f'pub fn pick(a : String, b : String) -> String {{ ignore({ignored}); {returned} }}\n',
                encoding="utf-8")
        source = (
            'fn source() -> String { "dirty" }\n'
            'fn sink(value : String) -> Unit { ignore(value) }\n'
            'pub fn check() -> Unit { sink(@remote.pick("safe", source())) } // alert\n')
        self.assert_summary_sinks(source, 'import {\n  "fixture/cli/a" @remote,\n}\n',
                                  expected_lines=[])
        cache = self.root / ".moon-audit-cache" / "fn-cache.txt"
        self.assertTrue(cache.is_file())
        before = cache.read_bytes()
        # Only moon.pkg changes: function bodies and callee summaries stay fixed.
        self.assert_summary_sinks(source, 'import {\n  "fixture/cli/z" @remote,\n}\n', cold=False)
        self.assertNotEqual(cache.read_bytes(), before)


    def test_cfg_instruction_scope_and_loop_fixpoint(self):
        prefix = 'fn sink(value : String) -> Unit { ignore(value) }\n'
        cases = [
            ('pub fn go(value : String) -> Unit {\n  let x = value\n  { let x = "safe"; sink(x) }\n  sink(x) // alert\n}\n'),
            ('pub fn go(value : String) -> Unit {\n  let mut x = value\n  x += "safe"\n  sink(x) // alert\n}\n'),
        ]
        declarations = ''.join(f'  let mut v{i} = "safe"\n' for i in range(10))
        transfers = ''.join(f'    v{i} = v{i+1}\n' for i in range(9)) + '    v9 = value\n'
        cases.append('pub fn go(value : String, n : Int) -> Unit {\n' + declarations +
                     '  let mut i = 0\n  while i < n {\n' + transfers +
                     '    i += 1\n  }\n  sink(v0) // alert\n}\n')
        for body in cases:
            with self.subTest(body=body):
                source = prefix + body
                root = self._new_project(self.SINK_RULES, {"main.mbt": source})
                expected = [n for n, line in enumerate(source.splitlines(), 1) if '// alert' in line]
                findings = self._cfg_findings(root)
                self.assertEqual([f['line'] for f in findings], expected)
                report = json.loads(self.run_cli('--format', 'json', '--cfg-engine', target=root).stdout)
                self.assertIn('ast-fallback=0', report['analysis_scope'])

    def test_cfg_verify_checks_independent_values(self):
        source = ('fn sink(value : String) -> Unit { ignore(value) }\n'
                  'pub fn go(value : String) -> Unit {\n'
                  '  let mut x = value\n  sink(x)\n  x = "safe"\n  sink(x)\n}\n')
        root = self._new_project(self.SINK_RULES, {"main.mbt": source})
        for flags in ([], ["--cfg-engine"]):
            report = json.loads(self.run_cli('--format', 'json', '--cfg-verify', *flags, target=root).stdout)
            self.assertEqual([f['line'] for f in report['findings']], [4])
            self.assertIn('cfg-divergent=0', report['analysis_scope'])
            self.assertIn('cfg-independent-unsupported=0', report['analysis_scope'])

    def test_cfg_unsupported_call_discloses_whole_function_fallback(self):
        source = ('fn sink(value : String) -> Unit { ignore(value) }\n'
                  'fn helper(value : String) -> Unit { sink(value) }\n'
                  'pub fn go(value : String) -> Unit { helper(value) }\n')
        root = self._new_project(self.SINK_RULES, {"main.mbt": source})
        expected = json.loads(self.run_cli('--format', 'json', '--mode', 'deep', target=root).stdout)
        actual = json.loads(self.run_cli('--format', 'json', '--mode', 'deep', '--cfg-engine', target=root).stdout)
        self.assertEqual([(f['line'], f['rule_id']) for f in actual['findings']],
                         [(f['line'], f['rule_id']) for f in expected['findings']])
        self.assertIn('call effects: helper', actual['analysis_scope'])
        self.assertNotIn('ast-fallback=0', actual['analysis_scope'])
        for flags in ([], ['--cfg-engine']):
            self.run_cli('--cfg-verify', '--mode', 'deep', *flags, code=2, target=root)

    def assert_review_program(self, source, strict=False):
        root = self._new_project(self.SINK_RULES, {"main.mbt": source})
        expected = [n for n, line in enumerate(source.splitlines(), 1) if "// alert" in line]
        for flags in ([], ["--cfg-engine"]):
            report = json.loads(self.run_cli('--format', 'json', '--mode', 'deep', *flags, target=root).stdout)
            self.assertEqual([f['line'] for f in report['findings']], expected, (flags, report))
            if strict:
                verified = json.loads(self.run_cli('--format', 'json', '--mode', 'deep', '--cfg-verify', *flags, target=root).stdout)
                self.assertEqual([f['line'] for f in verified['findings']], expected)
        return root

    def test_review_method_field_effects_and_alias(self):
        self.assert_review_program('''fn sink(value : String) -> Unit { ignore(value) }
struct Box { mut value : String }
fn Box::put(self : Box, value : String) -> Unit { self.value = value }
pub fn go(value : String) -> Unit {
  let box = Box::{ value: "safe" }
  let alias = box
  alias.put(value)
  sink(box.value) // alert
  let clean = Box::{ value: "safe" }
  clean.put("safe")
  sink(clean.value)
}
''')

    def test_review_function_parameter_shadowing(self):
        for parameter in ('pick', 'callback'):
            with self.subTest(parameter=parameter):
                self.assert_review_program('''fn sink(value : String) -> Unit { ignore(value) }
fn pick(a : String, b : String) -> String { ignore(a); b }
pub fn go(PARAM : (String, String) -> String, value : String) -> Unit {
  sink(PARAM(value, "safe")) // alert
}
'''.replace('PARAM', parameter))

    def test_review_return_facts(self):
        self.assert_review_program('''fn source() -> String { "dirty" }
fn sink(value : String) -> Unit { ignore(value) }
fn sanitize(value : String) -> String { ignore(value); "safe" }
fn first() -> String { source() }
fn second() -> String { first() }
fn clean(value : String) -> String { ignore(value); "safe" }
fn sanitized(value : String) -> String { sanitize(value) }
fn mixed(flag : Bool, value : String) -> String { if flag { source() } else { value } }
fn combined(a : String, b : String) -> String { a + b }
fn recursive(n : Int) -> String { if n == 0 { source() } else { recursive(n - 1) } }
fn explicit() -> String { return source() }
pub fn go(flag : Bool) -> Unit {
  sink(first()) // alert
  sink(second()) // alert
  sink(clean(source()))
  sink(sanitized(source()))
  sink(mixed(flag, "safe")) // alert
  sink(combined("safe", "safe"))
  sink(combined(source(), "safe")) // alert
  sink(combined("safe", source())) // alert
  sink(recursive(1)) // alert
  sink(explicit()) // alert
}
''', strict=True)

    def test_review_labelled_defaults_and_forwarding(self):
        root = self.assert_review_program('''fn source() -> String { "dirty" }
fn sink(value : String) -> Unit { ignore(value) }
fn pick(first~ : String, second : String) -> String { ignore(first); second }
fn default_dirty(value~ : String = source()) -> String { value }
fn default_clean(value~ : String = "safe") -> String { value }
pub fn go(value : String) -> Unit {
  sink(pick(first="safe", value)) // alert
  sink(pick(first=value, "safe"))
  let first = value
  sink(pick("safe", first~))
  sink(default_dirty()) // alert
  sink(default_dirty(value="safe"))
  sink(default_clean())
  let missing : String? = None
  sink(default_dirty(value?=missing)) // alert
}
''')
        for flags in ([], ['--cfg-engine']):
            verified = json.loads(self.run_cli('--format', 'json', '--mode', 'deep', '--cfg-verify', *flags, code=2, target=root).stdout)
            self.assertEqual([f['line'] for f in verified['findings']], [7, 11, 15])
            self.assertIn('default argument:', verified['analysis_scope'])

    def test_interpolation_scope_nested_holes_and_invalid_expression(self):
        source = r'''fn sink(value : String) -> Unit { ignore(value) }
pub fn go(value : String) -> Unit {
  let clean = "safe"
  sink("header:\{clean}")
  sink("header:\{value}") // alert
  ignore("\{ { sink(value); "safe" } }") // alert
  let nested = "outer:\{"inner:\{clean}"}"
  sink(nested)
}
'''
        root = self._new_project(self.SINK_RULES, {"main.mbt": source})
        checked = subprocess.run([os.environ.get("MOON_BIN", "moon"), "check"],
                                 cwd=root, capture_output=True, text=True, timeout=60)
        self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
        for flags in ([], ["--cfg-engine"]):
            report = json.loads(self.run_cli('--format', 'json', '--mode', 'deep', *flags, target=root).stdout)
            self.assertEqual(report['errors'], [])
            self.assertEqual([f['line'] for f in report['findings']], [5, 6])
        (root / 'main.mbt').write_text(r'pub fn broken() -> Bytes { b"\{1 + }" }', encoding='utf-8')
        report = json.loads(self.run_cli('--format', 'json', '--mode', 'deep', target=root, code=2).stdout)
        self.assertTrue(any('Parse error' in error for error in report['errors']))

    def test_byte_interpolation_taint_and_expression_effects(self):
        source = r'''fn sink(value : Bytes) -> Unit { ignore(value) }
pub fn go(value : Bytes) -> Unit {
  sink(b"prefix\{value}") // alert
  let clean = b"safe"
  sink(b"prefix\{clean}")
  ignore(b"\{ { sink(value); b"safe" } }") // alert
}
'''
        root = self._new_project(self.SINK_RULES, {"main.mbt": source})
        checked = subprocess.run([os.environ.get("MOON_BIN", "moon"), "check"],
                                 cwd=root, capture_output=True, text=True, timeout=60)
        self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
        for flags in ([], ["--cfg-engine"]):
            report = json.loads(self.run_cli('--format', 'json', '--mode', 'deep', *flags, target=root).stdout)
            self.assertEqual(report['errors'], [])
            self.assertEqual([f['line'] for f in report['findings']], [3, 6])
        # A simple interpolation has an independently executable CFG value.
        (root / 'main.mbt').write_text(source.replace('  ignore(b"\\{ { sink(value); b"safe" } }") // alert\n', ''), encoding='utf-8')
        report = json.loads(self.run_cli('--format', 'json', '--mode', 'deep', '--cfg-verify', target=root).stdout)
        self.assertEqual([f['line'] for f in report['findings']], [3])
        self.assertIn('cfg-independent-unsupported=0', report['analysis_scope'])

    def test_byte_return_frontend_across_summaries_and_cache(self):
        source = '''fn sink(value : Bytes) -> Unit { ignore(value) }
fn clean() -> Bytes { return b"" }
fn pass(value : Bytes) -> Bytes { if false { return b"" }; value }
pub fn go(value : Bytes) -> Unit {
  sink(clean())
  sink(pass(value)) // alert
}
'''
        root = self._new_project(self.SINK_RULES, {"main.mbt": source})
        checked = subprocess.run([os.environ.get("MOON_BIN", "moon"), "check"],
                                 cwd=root, capture_output=True, text=True, timeout=60)
        self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
        for flags in ([], ["--cfg-engine"]):
            shutil.rmtree(root / ".moon-audit-cache", ignore_errors=True)
            for phase in ("cold", "warm"):
                with self.subTest(engine=flags, phase=phase):
                    report = json.loads(self.run_cli('--format', 'json', '--mode', 'deep', *flags, target=root).stdout)
                    self.assertEqual(report['errors'], [])
                    self.assertEqual([f['line'] for f in report['findings']], [6])
                    self.assertIn('parser-policy=handrolled-moonyacc-interpolation-v2', report['analysis_scope'])
        (root / 'main.mbt').write_text('pub fn broken() -> Bytes { return b"" + }\n', encoding='utf-8')
        report = json.loads(self.run_cli('--format', 'json', '--mode', 'deep', target=root, code=2).stdout)
        self.assertTrue(any('Parse error' in error for error in report['errors']))

    def test_exception_constructor_identity_across_packages(self):
        root = self.root / "exception-packages"
        root.mkdir()
        (root / "moon.mod").write_text('name = "fixture/errors"\n', encoding='utf-8')
        (root / "moon.pkg").write_text('import { "fixture/errors/a" @a, "fixture/errors/b" @b }\n', encoding='utf-8')
        (root / "taint-rules.json").write_text(json.dumps(self.SINK_RULES), encoding='utf-8')
        for name in ('a', 'b'):
            package = root / name
            package.mkdir()
            (package / 'moon.pkg').write_text('', encoding='utf-8')
            (package / 'lib.mbt').write_text(
                'pub(all) suberror Problem { Bad(String) }\n'
                'pub fn fail(value : String) -> Unit raise { raise Bad(value) }\n', encoding='utf-8')
        source = '''fn sink(value : String) -> Unit { ignore(value) }
pub fn go(value : String) -> Unit {
  try { @a.fail(value) } catch {
    @b.Bad(text) => sink(text)
    @a.Bad(text) => sink(text) // alert
    _ => ()
  }
}
pub fn caught(value : String) -> Unit {
  errdefer sink(value)
  try { @a.fail(value) } catch { @a.Problem::_ => (); _ => () }
}
'''
        (root / 'main.mbt').write_text(source, encoding='utf-8')
        checked = subprocess.run(['moon', 'check'], cwd=root, capture_output=True, text=True, timeout=60)
        self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
        for flags in ([], ["--cfg-engine"]):
            report = json.loads(self.run_cli('--format', 'json', '--mode', 'deep', *flags, target=root).stdout)
            self.assertEqual([(Path(f['file']).name, f['line']) for f in report['findings']], [('main.mbt', 5)])

    def test_exception_summary_invalidates_warm_cache(self):
        prefix = 'fn sink(value : String) -> Unit { ignore(value) }\nsuberror Bad { Bad(String) }\n'
        helper = 'fn maybe(value : String) -> Unit raise Bad { ignore(value) }\n'
        caller = 'pub fn go(value : String) -> Unit raise Bad { errdefer sink(value); maybe(value) }\n'
        root = self._new_project(self.SINK_RULES, {"main.mbt": prefix + helper + caller})
        def scan(expected):
            for flags in ([], ["--cfg-engine"]):
                report = json.loads(self.run_cli('--format', 'json', '--mode', 'deep', *flags, target=root).stdout)
                self.assertEqual([f['line'] for f in report['findings']], expected)
        scan([])
        scan([])
        helper = 'fn maybe(value : String) -> Unit raise Bad { raise Bad(value) }\n'
        (root / 'main.mbt').write_text(prefix + helper + caller, encoding='utf-8')
        checked = subprocess.run(['moon', 'check'], cwd=root, capture_output=True, text=True)
        self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
        scan([4])
        scan([4])

    def test_normal_return_summary_invalidates_warm_cache(self):
        prefix = 'fn sink(value : String) -> Unit { ignore(value) }\nsuberror Bad { Bad(String) }\n'
        helper = 'fn maybe(value : String, flag : Bool) -> Unit raise Bad { if flag { raise Bad(value) } }\n'
        caller = 'pub fn go(value : String, flag : Bool) -> Unit raise Bad { maybe(value, flag); sink(value) }\n'
        root = self._new_project(self.SINK_RULES, {"main.mbt": prefix + helper + caller})
        for flags in ([], ["--cfg-engine"]):
            report = json.loads(self.run_cli('--format', 'json', '--mode', 'deep', *flags, target=root).stdout)
            self.assertEqual([f['line'] for f in report['findings']], [4])
        # Same error type/payload summary; only the normal continuation disappears.
        helper = 'fn maybe(value : String, flag : Bool) -> Unit raise Bad { ignore(flag); raise Bad(value) }\n'
        (root / 'main.mbt').write_text(prefix + helper + caller, encoding='utf-8')
        checked = subprocess.run(['moon', 'check'], cwd=root, capture_output=True, text=True)
        self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
        for flags in ([], ["--cfg-engine"]):
            report = json.loads(self.run_cli('--format', 'json', '--mode', 'deep', *flags, target=root).stdout)
            self.assertEqual(report['findings'], [])

    def test_recursive_default_budget_is_disclosed(self):
        root = self._new_project(self.SINK_RULES, {"main.mbt": '''fn recur(value~ : String = recur()) -> String { value }
pub fn go() -> Unit { ignore(recur()) }
'''})
        for flags in ([], ["--cfg-engine"]):
            report = json.loads(self.run_cli('--format', 'json', '--mode', 'deep', *flags, target=root).stdout)
            self.assertEqual(report["errors"], [])
            marker = "default-argument-expansion-exhausted="
            count = int(report["analysis_scope"].split(marker, 1)[1].split("(", 1)[0])
            self.assertGreater(count, 0)
            self.assertIn("taint-policy=bounded-field-exit-facts-v2", report["analysis_scope"])

    def test_summary_field_fact_budget_is_disclosed(self):
        fields = [f"v{i}" for i in range(65)]
        wide = ('fn source() -> String { "dirty" }\n'
                'fn sink(value : String) -> Unit { ignore(value) }\n'
                'pub struct Wide { ' + '; '.join(f'{name} : String' for name in fields) + ' }\n'
                'fn combine(value : Wide) -> String { ' + ' + '.join(f'value.{name}' for name in fields) + ' }\n'
                'fn wrap(value : Wide) -> String { combine(value) }\n'
                'pub fn go() -> Unit { sink(wrap(Wide::{ ' +
                ', '.join(f'{name}: ' + ('source()' if i == 0 else '\"safe\"') for i, name in enumerate(fields)) + ' })) } // alert\n')
        recursive = '''fn source() -> String { "dirty" }
fn sink(value : String) -> Unit { ignore(value) }
pub struct Node { left : Node?; right : Node?; value : String }
fn first(node : Node) -> String { match node.left { Some(child) => second(child); None => node.value } }
fn second(node : Node) -> String { match node.right { Some(child) => first(child); None => node.value } }
pub fn go() -> Unit {
  sink(first(Node::{left: None, right: None, value: source()})) // alert
}
'''
        for kind, source in (("width", wide), ("depth", recursive)):
            root = self._new_project(self.SINK_RULES, {"main.mbt": source})
            checked = subprocess.run(["moon", "check"], cwd=root, capture_output=True, text=True, timeout=60)
            self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
            expected = [i for i, line in enumerate(source.splitlines(), 1) if "// alert" in line]
            for flags in ([], ["--cfg-engine"]):
                with self.subTest(kind=kind, engine=flags):
                    report = json.loads(self.run_cli('--format', 'json', '--mode', 'deep', *flags, target=root).stdout)
                    self.assertEqual(report["errors"], [])
                    self.assertEqual([f["line"] for f in report["findings"]], expected)
                    count = int(report["analysis_scope"].split("summary-fact-widened=", 1)[1].split("(", 1)[0])
                    self.assertGreater(count, 0)
                    self.assertIn("max-sources=64,max-field-depth=4", report["analysis_scope"])

    def test_field_postconditions_closed_boundaries(self):
        result = subprocess.run(
            [os.sys.executable, str(REPO / "docs/review-fixtures/2026-09-22/field_probe.py"),
             str(self.root / "field-boundaries"), str(ANALYZER)],
            capture_output=True, text=True, timeout=240,
        )
        # The complete probe retains the open alias-order precision and dependency cases.
        # This gate checks every other case and does not pin the open bug's output.
        self.assertIn(result.returncode, (0, 1), result.stdout + result.stderr)
        results = json.loads((self.root / "field-boundaries/results.json").read_text())
        for name, report in results.items():
            self.assertEqual(report["compile"], 0, name)
            if name in ("two_formals_alias_clean_last", "two_formals_alias_read_after_write"):
                continue
            with self.subTest(case=name):
                for mode in ("ast", "cfg", "strict"):
                    self.assertEqual(report[mode]["lines"], report["expected"], result.stdout)
                    self.assertEqual(report[mode]["rc"], 2 if mode == "strict" else 0)

    def test_field_exit_effects_and_getter_invalidate_cache(self):
        root = self._new_project(self.SINK_RULES, {})
        (root / "moon.mod").write_text('name = "fixture/fields"\n', encoding="utf-8")
        (root / "moon.pkg").write_text('import { "fixture/fields/lib" @lib, "fixture/fields/other" @other }\n', encoding="utf-8")
        for package in ("lib", "other"):
            (root / package).mkdir()
            (root / package / "moon.pkg").write_text("", encoding="utf-8")
        (root / "other/lib.mbt").write_text('''pub(all) struct Box { mut value : String }
pub fn fill(box : Box) -> Unit { box.value = "safe" }
pub fn get(box : Box) -> String { box.value }
''', encoding="utf-8")
        main = '''fn source() -> String { "dirty" }
fn sink(value : String) -> Unit { ignore(value) }
pub fn go(flag : Bool) -> Unit {
  let box = @lib.Box::{value: "safe"}
  try {
    @lib.fill(box, flag)
    sink(@lib.get(box)) // normal
  } catch { _ => sink(@lib.get(box)) } // exceptional
  let other = @other.Box::{value: source()}
  @other.fill(other)
  sink(@other.get(other))
}
'''
        (root / "main.mbt").write_text(main, encoding="utf-8")
        template = '''fn source() -> String { "dirty" }
pub(all) struct Box { mut value : String }
pub suberror Boom { Boom }
pub fn fill(box : Box, flag : Bool) -> Unit raise Boom {
  if flag { box.value = ERROR_VALUE; raise Boom }
  box.value = NORMAL_VALUE
}
pub fn get(box : Box) -> String { box.value }
'''
        normal_line = next(i for i, line in enumerate(main.splitlines(), 1) if "// normal" in line)
        error_line = next(i for i, line in enumerate(main.splitlines(), 1) if "// exceptional" in line)
        for flags in ([], ["--cfg-engine"]):
            shutil.rmtree(root / ".moon-audit-cache", ignore_errors=True)
            for normal, error, expected in [('"safe"', '"safe"', []),
                                            ('source()', '"safe"', [normal_line]),
                                            ('"safe"', 'source()', [error_line]),
                                            ('"safe"', '"safe"', [])]:
                (root / "lib/lib.mbt").write_text(template.replace("NORMAL_VALUE", normal).replace("ERROR_VALUE", error), encoding="utf-8")
                checked = subprocess.run(["moon", "check"], cwd=root, capture_output=True, text=True, timeout=60)
                self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
                for phase in ("changed", "warm"):
                    with self.subTest(engine=flags, normal=normal, error=error, phase=phase):
                        report = json.loads(self.run_cli('--format', 'json', '--mode', 'deep', *flags, target=root).stdout)
                        self.assertEqual(report["errors"], [])
                        self.assertEqual([(Path(f["file"]).name, f["line"]) for f in report["findings"]],
                                         [("main.mbt", line) for line in expected])

    def test_default_argument_semantics(self):
        result = subprocess.run(
            [os.sys.executable, str(REPO / "docs/review-fixtures/2026-09-22/default_probe.py"),
             str(self.root / "default-boundaries"), str(ANALYZER)],
            capture_output=True, text=True, timeout=240,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        results = json.loads((self.root / "default-boundaries/results.json").read_text())
        for name, result in results.items():
            with self.subTest(case=name):
                self.assertEqual(result["strict"]["lines"], result["expected"])
                self.assertEqual(result["strict"]["rc"], 0 if name == "default_all_overridden" else 2)

    def test_default_show_type_identity_across_packages(self):
        root = self._new_project(self.SINK_RULES, {})
        (root / "moon.mod").write_text('name = "fixture/defaultshow"\n', encoding="utf-8")
        (root / "moon.pkg").write_text('import { "fixture/defaultshow/fmt" @fmt, "fixture/defaultshow/types" @types }\n', encoding="utf-8")
        for package in ("fmt", "types"):
            (root / package).mkdir()
            (root / package / "moon.pkg").write_text("", encoding="utf-8")
        (root / "fmt/lib.mbt").write_text(
            'pub fn[T : Show] pick(value : T, text~ : String = value.to_string()) -> String { text }\n', encoding="utf-8")
        (root / "types/lib.mbt").write_text('''fn source() -> String { "dirty" }
pub(all) struct Box {}
pub impl Show for Box with fn output(self, logger) -> Unit { ignore(self); logger.write_string(source()) }
''', encoding="utf-8")
        (root / "main.mbt").write_text('''fn sink(value : String) -> Unit { ignore(value) }
pub fn go() -> Unit {
  sink(@fmt.pick(@types.Box::{}))
  let safe = "safe"
  sink(@fmt.pick(safe))
}
''', encoding="utf-8")
        checked = subprocess.run(["moon", "check"], cwd=root, capture_output=True, text=True, timeout=60)
        self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
        for flags in ([], ["--cfg-engine"]):
            shutil.rmtree(root / ".moon-audit-cache", ignore_errors=True)
            for phase in ("cold", "warm"):
                with self.subTest(engine=flags, phase=phase):
                    report = json.loads(self.run_cli('--format', 'json', '--mode', 'deep', *flags, target=root).stdout)
                    self.assertEqual(report["errors"], [])
                    self.assertEqual([(Path(f["file"]).name, f["line"]) for f in report["findings"]], [("main.mbt", 3)])

    def test_default_lexical_scope_and_effect_cache(self):
        root = self._new_project(self.SINK_RULES, {})
        (root / "moon.mod").write_text('name = "fixture/defaults"\n', encoding="utf-8")
        (root / "moon.pkg").write_text('import { "fixture/defaults/lib" @lib }\n', encoding="utf-8")
        package = root / "lib"
        package.mkdir()
        (package / "moon.pkg").write_text("", encoding="utf-8")
        (root / "main.mbt").write_text('''fn source() -> String { "dirty" }
fn sink(value : String) -> Unit { ignore(value) }
fn base() -> String { source() }
pub fn go() -> Unit {
  sink(@lib.pick())
  ignore(@lib.pick())
  sink(@lib.pick(value="safe"))
}
''', encoding="utf-8")
        template = '''fn source() -> String { "dirty" }
fn sink(value : String) -> Unit { ignore(value) }
fn base() -> String { "safe" }
pub fn pick(value~ : String = DEFAULT) -> String { value }
'''
        for flags in ([], ["--cfg-engine"]):
            shutil.rmtree(root / ".moon-audit-cache", ignore_errors=True)
            for default, expected in [("base()", []), ("source()", [5]),
                                      ('{ sink(source()); "safe" }', [5, 6]), ("base()", [])]:
                (package / "lib.mbt").write_text(template.replace("DEFAULT", default), encoding="utf-8")
                checked = subprocess.run(["moon", "check"], cwd=root, capture_output=True, text=True, timeout=60)
                self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
                for phase in ("changed", "warm"):
                    with self.subTest(engine=flags, default=default, phase=phase):
                        report = json.loads(self.run_cli('--format', 'json', '--mode', 'deep', *flags, target=root).stdout)
                        self.assertEqual(report["errors"], [])
                        self.assertEqual([(Path(f["file"]).name, f["line"]) for f in report["findings"]],
                                         [("main.mbt", line) for line in expected])

    def test_conversion_semantics(self):
        result = subprocess.run(
            [os.sys.executable, str(REPO / "docs/review-fixtures/2026-09-22/conversion_probe.py"),
             str(self.root / "conversion-boundaries"), str(ANALYZER)],
            capture_output=True, text=True, timeout=240,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_show_summary_and_sink_effect_invalidate_cache(self):
        root = self._new_project(self.SINK_RULES, {})
        (root / "main.mbt").write_text( '''fn sink(value : String) -> Unit { ignore(value) }
fn[T : Show] wrap(value : T) -> String { value.to_string() }
fn[T : Show] emit(value : T) -> Unit { sink(value.to_string()) }
pub fn go() -> Unit {
  sink(wrap(Box::{}))
  emit(Box::{})
  sink(wrap("safe"))
  emit("safe")
}
''', encoding='utf-8')
        helper = '''fn source() -> String { "dirty" }
pub struct Box {}
pub impl Show for Box with fn output(self, logger) -> Unit { ignore(self); logger.write_string(CONTENT) }
'''
        for flags in ([], ["--cfg-engine"]):
            shutil.rmtree(root / ".moon-audit-cache", ignore_errors=True)
            for content, expected in [('"safe"', []), ("source()", [5, 6]), ('"safe"', [])]:
                (root / "types.mbt").write_text(helper.replace("CONTENT", content), encoding="utf-8")
                checked = subprocess.run(["moon", "check"], cwd=root, capture_output=True, text=True, timeout=60)
                self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
                for phase in ("changed", "warm"):
                    with self.subTest(engine=flags, content=content, phase=phase):
                        report = json.loads(self.run_cli('--format', 'json', '--mode', 'deep', *flags, target=root).stdout)
                        self.assertEqual(report["errors"], [])
                        self.assertEqual([(Path(f["file"]).name, f["line"]) for f in report["findings"]],
                                         [("main.mbt", line) for line in expected])

    def test_show_cross_package_type_identity(self):
        root = self._new_project(self.SINK_RULES, {})
        (root / "main.mbt").write_text( '''fn sink(value : String) -> Unit { ignore(value) }
fn[T : Show] wrap(value : T) -> String { value.to_string() }
pub fn go() -> Unit {
  sink(wrap(@a.Box::{}))
  sink(wrap(@b.Box::{}))
}
''', encoding='utf-8')
        (root / "moon.mod").write_text('name = "fixture/show"\n', encoding="utf-8")
        (root / "moon.pkg").write_text('import { "fixture/show/a" @a, "fixture/show/b" @b }\n', encoding="utf-8")
        for name, content in [("a", "source()"), ("b", '"safe"')]:
            package = root / name
            package.mkdir()
            (package / "moon.pkg").write_text("", encoding="utf-8")
            (package / "lib.mbt").write_text('fn source() -> String { "dirty" }\npub(all) struct Box {}\n'
                + 'pub impl Show for Box with fn output(self, logger) -> Unit { ignore(self); logger.write_string('
                + content + ') }\n', encoding="utf-8")
        checked = subprocess.run(["moon", "check"], cwd=root, capture_output=True, text=True, timeout=60)
        self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
        for flags in ([], ["--cfg-engine"]):
            for phase in ("cold", "warm"):
                with self.subTest(engine=flags, phase=phase):
                    report = json.loads(self.run_cli('--format', 'json', '--mode', 'deep', *flags, target=root).stdout)
                    self.assertEqual(report["errors"], [])
                    self.assertEqual([(Path(f["file"]).name, f["line"]) for f in report["findings"]], [("main.mbt", 4)])

    def test_upgrade_exception_semantics(self):
        result = subprocess.run(
            [os.sys.executable, str(REPO / "docs/review-fixtures/2026-09-22/upgrade_probe.py"),
             str(self.root / "exception-boundaries"), str(ANALYZER)],
            capture_output=True, text=True, timeout=180,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_explicit_models_apply_to_callback_parameters(self):
        self.assert_review_program('''pub fn go(source : () -> String, sink : (String) -> Unit) -> Unit {
  sink(source()) // alert
}
''')

    def test_joint_factory_method_returns(self):
        self.assert_review_program('''fn source() -> String { "dirty" }
fn sink(value : String) -> Unit { ignore(value) }
struct Dirty {}
struct Safe {}
fn make_dirty() -> Dirty { Dirty::{} }
fn make_safe() -> Safe { Safe::{} }
fn Dirty::read(self : Dirty) -> String { ignore(self); source() }
fn Safe::read(self : Safe) -> String { ignore(self); "safe" }
pub fn go() -> Unit {
  sink(make_dirty().read()) // alert
  sink(make_safe().read())
}
''')

    def test_review_constant_control_flow(self):
        self.assert_review_program('''fn sink(value : String) -> Unit { ignore(value) }
pub fn go(value : String) -> Unit {
  if false { sink(value) }
  while false { sink(value) }
  if true { sink(value) } // alert
}
''', strict=True)



if __name__ == "__main__":
    if not ANALYZER.is_file():
        raise SystemExit(f"Build moon-audit first or set ANALYZER: {ANALYZER}")
    unittest.main(verbosity=2)
