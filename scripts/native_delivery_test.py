#!/usr/bin/env python3
"""Acceptance tests for relocated native releases (Python is only a test driver).

Set ANALYZER to the built/extracted moon-audit executable. Optional PROJECT_MOON
or PROJECT_TOOLCHAIN enables real project compiler checks; neither is downloaded.
Run this on each advertised operating system using its native release artifact.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[1]
ANALYZER = Path(os.environ.get(
    "ANALYZER", REPO / "_build/native/debug/build/src/main/main.exe",
)).resolve()
RULE = "CWE-116/replace-escaping"
SOURCE = 'pub fn escape(s : String) -> String { s.replace(old="<", new="&lt;") }\n'


class NativeDelivery(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not ANALYZER.is_file():
            raise RuntimeError(f"Build/extract a native binary and set ANALYZER: {ANALYZER}")
        cls.sandbox = tempfile.TemporaryDirectory(prefix="moon-audit-native-delivery-")
        cls.addClassCleanup(cls.sandbox.cleanup)
        cls.base = Path(cls.sandbox.name)
        artifact = cls.base / "download 解压 with spaces"
        artifact.mkdir()
        cls.binary = artifact / ("moon-audit.exe" if os.name == "nt" else "moon-audit")
        shutil.copy2(ANALYZER, cls.binary)
        cls.empty_path = cls.base / "empty PATH"
        cls.empty_path.mkdir()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=self.base, prefix="case-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.project = self.work / "项目 source with spaces"
        self.project.mkdir()
        self.cwd = self.work / "outside checkout"
        self.cwd.mkdir()
        (self.project / "moon.mod").write_text('name = "fixture/delivery"\n', encoding="utf-8")
        (self.project / "moon.pkg").write_text("", encoding="utf-8")
        (self.project / "danger.mbt").write_text(SOURCE, encoding="utf-8")

    def run_cli(self, *args, code=0, isolated=True, target=None, timeout=30):
        environment = os.environ.copy()
        if isolated:
            # Keep OS runtime variables (notably SystemRoot on Windows), while
            # preventing discovery of Python, moon, shell launchers or packages.
            environment["PATH"] = str(self.empty_path)
            for key in ("MOON_HOME", "MOON_TOOLCHAIN", "PYTHONHOME", "PYTHONPATH"):
                environment.pop(key, None)
        result = subprocess.run(
            [str(self.binary), *map(str, args), str(target if target is not None else self.project)],
            cwd=self.cwd, env=environment, capture_output=True, timeout=timeout,
            shell=False,
        )
        result.stdout = result.stdout.decode("utf-8")
        result.stderr = result.stderr.decode("utf-8")
        self.assertEqual(result.returncode, code,
                         f"args={args!r}\nstdout={result.stdout}\nstderr={result.stderr}")
        self.assertNotIn("Traceback (most recent call last)", result.stdout + result.stderr)
        return result

    def json_report(self, *args, **kwargs):
        result = self.run_cli("--format", "json", *args, **kwargs)
        report = json.loads(result.stdout)
        self.assertIsInstance(report, dict)
        self.assertIsInstance(report["findings"], list)
        return report

    def assert_base_finding(self, report):
        self.assertEqual([(Path(f["file"]).name, f["rule_id"], f["line"])
                          for f in report["findings"]], [("danger.mbt", RULE, 1)])
        self.assertEqual(report["findings"][0]["evidence"], "syntax_hint")

    def assert_verification(self, report, status):
        verification = report["project_verification"]
        self.assertEqual(verification["status"], status, verification)
        self.assertEqual(verification["target"], "native")
        if status == "compiler_verified":
            self.assertIn("moonc", verification["toolchain"])
            self.assertEqual(verification["unsupported_files"], [])
            self.assertEqual({Path(p).name for p in verification["compiler_files"]},
                             {"danger.mbt"})
        else:
            self.assertTrue(report["errors"], report)
        return verification

    def compiler_arguments(self):
        toolchain = os.environ.get("PROJECT_TOOLCHAIN")
        executable = os.environ.get("PROJECT_MOON")
        if toolchain:
            return ["--project-toolchain", str(Path(toolchain).resolve())]
        if executable:
            return ["--project-moon", str(Path(executable).resolve())]
        self.skipTest("Set PROJECT_TOOLCHAIN or PROJECT_MOON for real compiler acceptance")

    def test_relocated_binary_without_toolchain_or_python(self):
        self.assertIsNone(shutil.which("moon", path=str(self.empty_path)))
        self.assertIsNone(shutil.which("python3", path=str(self.empty_path)))
        report = self.json_report()
        self.assert_base_finding(report)
        self.assertEqual(report["files_parsed"], 1)
        self.assertEqual(report["errors"], [])
        self.assertIsNone(report["project_verification"])

    def test_explicit_syntax_matches_default(self):
        default = self.json_report()
        explicit = self.json_report("--analysis", "syntax")
        self.assertEqual(explicit["findings"], default["findings"])
        self.assertEqual(explicit["files_parsed"], default["files_parsed"])

    def test_outside_checkout_relative_project_path(self):
        relative = os.path.relpath(self.project, self.cwd)
        report = self.json_report("--analysis", "syntax", target=relative)
        self.assert_base_finding(report)

    def test_findings_policy_exit_one(self):
        self.assert_base_finding(self.json_report("--fail-on-error", code=1))

    def test_clean_source_exit_zero(self):
        (self.project / "danger.mbt").write_text(
            'pub fn safe() -> String { "literal" }\n', encoding="utf-8")
        report = self.json_report("--fail-on-error")
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["files_parsed"], 1)

    def test_partial_parse_failure_keeps_findings(self):
        (self.project / "broken.mbt").write_text("fn broken( {", encoding="utf-8")
        report = self.json_report(code=2)
        self.assert_base_finding(report)
        self.assertEqual(report["files_selected"], 2)
        self.assertEqual(report["files_parsed"], 1)
        self.assertTrue(report["errors"])

    def test_unverified_scan_discloses_every_known_unsupported_format(self):
        (self.project / "说明.mbt.md").write_text("```mbt check\n" + SOURCE + "```\n", encoding="utf-8")
        (self.project / "tool.mbtx").write_text(SOURCE, encoding="utf-8")
        (self.project / "README.md").write_text("```mbt\n" + SOURCE + "```\n", encoding="utf-8")
        report = self.json_report(code=2)
        self.assert_base_finding(report)
        self.assertEqual((report["files_selected"], report["files_parsed"], report["files_scanned"]), (3, 1, 1))
        entries = {Path(f["path"]).name: f for f in report["analysis_manifest"]["files"]}
        self.assertEqual(set(entries), {"danger.mbt", "说明.mbt.md", "tool.mbtx"})
        for name, reason in (("说明.mbt.md", "literate_input_requires_versioned_adapter"),
                             ("tool.mbtx", "script_input_not_supported")):
            self.assertEqual((entries[name]["status"], entries[name]["reason"], entries[name]["rules"]),
                             ("unsupported", reason, []))
        sarif = json.loads(self.run_cli("--format", "sarif", code=2).stdout)["runs"][0]
        self.assertFalse(sarif["invocations"][0]["executionSuccessful"])
        self.assertEqual([r["ruleId"] for r in sarif["results"]], [RULE])

    def test_unsupported_only_directory_is_not_an_empty_success(self):
        (self.project / "danger.mbt").unlink()
        (self.project / "README.mbt.md").write_text("# 文档\n", encoding="utf-8")
        report = self.json_report(code=2)
        self.assertEqual((report["files_selected"], report["files_parsed"]), (1, 0))
        self.assertEqual(report["findings"], [])
        self.assertTrue(report["errors"])

    def test_unsupported_inputs_follow_incremental_and_exclusion_selection(self):
        for name in ("README.mbt.md", "tool.mbtx"):
            (self.project / name).write_text("unsupported input", encoding="utf-8")
        changed = self.work / "changed.txt"
        changed.write_text("README.mbt.md\ntool.mbtx\n", encoding="utf-8")
        report = self.json_report("--changed-files", changed, code=2)
        self.assertEqual((report["files_selected"], report["files_parsed"]), (2, 0))
        self.assertEqual(report["findings"], [])
        changed.write_text("danger.mbt\n", encoding="utf-8")
        report = self.json_report("--changed-files", changed)
        self.assert_base_finding(report)
        self.assertEqual(report["files_selected"], 1)
        config = self.work / "config.json"
        config.write_text(json.dumps({"exclude": ["*.mbt.md", "*.mbtx"]}), encoding="utf-8")
        report = self.json_report("--config", config)
        self.assert_base_finding(report)
        self.assertEqual(report["files_selected"], 1)
        self.assertEqual(report["analysis_manifest"]["selection"]["configured_excludes"], ["*.mbt.md", "*.mbtx"])

    def test_nested_modules_do_not_inherit_stdlib_rule_exemption(self):
        (self.project / "danger.mbt").write_text('fn f() { unsafe_from_int(42) }\n', encoding="utf-8")
        (self.project / "moon.mod").write_text('name = "moonbitlang/core"\n', encoding="utf-8")
        nested = self.project / "modules" / "nested"
        nested.mkdir(parents=True)
        (nested / "moon.mod.json").write_text(json.dumps({"name": "consumer/app"}), encoding="utf-8")
        (nested / "moon.pkg.json").write_text("{}", encoding="utf-8")
        (nested / "app.mbt").write_text('fn f() { unsafe_from_int(42) }\n', encoding="utf-8")
        report = self.json_report("--rule", "CWE-676/unsafe-call")
        self.assertEqual([Path(f["file"]).name for f in report["findings"]], ["app.mbt"])
        self.assertEqual(report["files_parsed"], 2)
        # Reversing module identities must also reverse the rule gate.
        (self.project / "moon.mod").write_text('name = "consumer/root"\n', encoding="utf-8")
        (nested / "moon.mod.json").write_text(json.dumps({"name": "moonbitlang/core"}), encoding="utf-8")
        report = self.json_report("--rule", "CWE-676/unsafe-call")
        self.assertEqual([Path(f["file"]).name for f in report["findings"]], ["danger.mbt"])

    def test_invalid_nested_module_is_visible_without_dropping_findings(self):
        nested = self.project / "nested"
        nested.mkdir()
        (nested / "moon.mod.json").write_text('{"name":', encoding="utf-8")
        (nested / "app.mbt").write_text(SOURCE, encoding="utf-8")
        report = self.json_report(code=2)
        self.assertEqual({Path(f["file"]).name for f in report["findings"]}, {"danger.mbt", "app.mbt"})
        self.assertTrue(any("moon.mod.json" in error for error in report["errors"]))

    def test_legacy_jsonc_metadata_matches_real_compiler(self):
        (self.project / "moon.mod").unlink()
        (self.project / "moon.pkg").unlink()
        (self.project / "moon.pkg.json").write_text('{ /* package */ "import": [], }', encoding="utf-8")
        for content in ('{ // module\n "name": "fixture/delivery" }',
                        '{ /* module */ "name": "fixture/delivery" }',
                        '{ "name": "fixture/delivery", }'):
            (self.project / "moon.mod.json").write_text(content, encoding="utf-8")
            with self.subTest(content=content):
                report = self.json_report("--verify-project", *self.compiler_arguments(), isolated=False, timeout=90)
                self.assert_base_finding(report)
                self.assert_verification(report, "compiler_verified")

    def test_semantic_and_unknown_analysis_are_rejected(self):
        for mode in ("semantic", "unknown"):
            with self.subTest(mode=mode):
                result = self.run_cli("--analysis", mode, code=2)
                self.assertIn(mode, result.stdout + result.stderr)

    def test_invalid_timeout_and_target_are_rejected(self):
        for args in (("--timeout-seconds", "0"), ("--timeout-seconds", "-1"),
                     ("--timeout-seconds", "abc"), ("--target", "invalid")):
            with self.subTest(args=args):
                self.run_cli("--verify-project", *args, code=2)

    def test_conflicting_toolchain_selectors_are_rejected(self):
        self.run_cli("--verify-project", "--project-toolchain", self.work,
                     "--project-moon", self.work / "moon", code=2)

    def test_missing_toolchain_preserves_source_findings(self):
        for selector in ("--project-toolchain", "--project-moon"):
            with self.subTest(selector=selector):
                report = self.json_report("--verify-project", selector,
                                          self.work / "missing toolchain", code=2)
                self.assert_base_finding(report)
                self.assert_verification(report, "toolchain_unavailable")

    def test_no_path_toolchain_preserves_source_findings(self):
        report = self.json_report("--verify-project", "--target", "native", code=2)
        self.assert_base_finding(report)
        self.assert_verification(report, "toolchain_unavailable")

    def test_toolchain_path_never_uses_shell(self):
        executable = self.work / "missing & mkdir injected-marker & missing"
        report = self.json_report("--verify-project", "--project-moon", executable,
                                  "--timeout-seconds", "2", code=2)
        self.assert_base_finding(report)
        self.assert_verification(report, "toolchain_unavailable")
        self.assertFalse((self.cwd / "injected-marker").exists())
        self.assertFalse((self.project / "injected-marker").exists())

    def test_report_file_outside_project(self):
        destination = self.cwd / "结果 with spaces.json"
        self.run_cli("--analysis", "syntax", "--format", "json", "--output", destination)
        self.assert_base_finding(json.loads(destination.read_text(encoding="utf-8")))

    def test_sarif_failed_verification_retains_findings(self):
        result = self.run_cli("--format", "sarif", "--verify-project",
                              "--project-moon", self.work / "missing", code=2)
        run = json.loads(result.stdout)["runs"][0]
        self.assert_verification(run["properties"], "toolchain_unavailable")
        self.assertEqual([item["ruleId"] for item in run["results"]], [RULE])
        self.assertFalse(run["invocations"][0]["executionSuccessful"])

    def test_baseline_cannot_drop_requested_verification(self):
        baseline = self.cwd / "baseline.json"
        invalid_compiler = self.work / "missing compiler"
        variants = [
            ["generate-baseline", "--verify-project", "--project-moon", invalid_compiler],
            ["--verify-project", "--project-moon", invalid_compiler, "generate-baseline"],
            ["--analysis", "semantic", "generate-baseline"],
        ]
        for args in variants:
            with self.subTest(args=args):
                baseline.write_text("preserve baseline", encoding="utf-8")
                self.run_cli(*args, "--output", baseline, code=2)
                self.assertEqual(baseline.read_text(encoding="utf-8"), "preserve baseline")

    def test_baseline_does_not_hide_verification_failure(self):
        baseline = self.cwd / "baseline.json"
        self.run_cli("generate-baseline", "--output", baseline)
        report = self.json_report("--verify-project", "--project-moon",
                                  self.work / "missing compiler", "--baseline", baseline, code=2)
        self.assertEqual(report["findings"], [])
        self.assert_verification(report, "toolchain_unavailable")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "POSIX special-file acceptance")
    def test_fifo_source_is_rejected_without_blocking(self):
        os.mkfifo(self.project / "pipe.mbt")
        report = self.json_report("--verify-project", "--project-moon",
                                  self.work / "missing compiler", "--timeout-seconds", "1",
                                  code=2, timeout=5)
        self.assert_base_finding(report)
        self.assert_verification(report, "snapshot_unavailable")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "POSIX special-file acceptance")
    def test_fifo_project_metadata_is_rejected_without_blocking(self):
        for name in ("moon.mod", "moon.pkg", ".moon-audit.json"):
            path = self.project / name
            original = path.read_bytes() if path.exists() else None
            with self.subTest(name=name):
                path.unlink(missing_ok=True)
                os.mkfifo(path)
                try:
                    self.run_cli("--verify-project", "--project-moon",
                                 self.work / "missing compiler", "--timeout-seconds", "1",
                                 code=2, timeout=5)
                finally:
                    path.unlink()
                    if original is not None:
                        path.write_bytes(original)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "POSIX special-file acceptance")
    def test_fifo_cli_inputs_are_rejected_without_blocking(self):
        fifo = self.cwd / "input.pipe"
        os.mkfifo(fifo)
        for option in ("--config", "--baseline", "--changed-files"):
            with self.subTest(option=option):
                self.run_cli(option, fifo, code=2, timeout=5)

    @unittest.skipUnless(os.name == "posix", "POSIX selected-symlink acceptance")
    def test_selected_symlink_is_rejected_before_canonicalization(self):
        destination = self.work / "linked-target.mbt"
        destination.write_text('pub fn linked() -> String { "value" }\n', encoding="utf-8")
        (self.project / "linked.mbt").symlink_to(destination)
        report = self.json_report("--verify-project", "--project-moon",
                                  self.work / "missing compiler", code=2)
        self.assert_base_finding(report)
        self.assert_verification(report, "snapshot_unavailable")

    def make_link(self, path, target, directory=False):
        try:
            path.symlink_to(target, target_is_directory=directory)
        except OSError as exc:
            self.skipTest(f"symlink creation unavailable: {exc}")

    def test_document_file_alias_does_not_block_real_verification(self):
        note = self.project / "NOTES.md"
        note.write_text("Documentation only", encoding="utf-8")
        self.make_link(self.project / "README.md", note)
        report = self.json_report("--verify-project", *self.compiler_arguments(),
                                 isolated=False, timeout=90)
        self.assert_base_finding(report)
        verification = self.assert_verification(report, "compiler_verified")
        self.assertFalse(any(p.endswith("/README.md") for p in verification["snapshot_sha256"]))
        self.assertTrue(any(p.endswith("/danger.mbt") for p in verification["snapshot_sha256"]))

    def test_directory_alias_named_as_document_still_rejected(self):
        outside = self.work / "other-source"
        outside.mkdir()
        (outside / "hidden.mbt").write_text(SOURCE, encoding="utf-8")
        self.make_link(self.project / "README.md", outside, directory=True)
        report = self.json_report("--verify-project", "--project-moon",
                                 self.work / "missing compiler", code=2)
        self.assert_verification(report, "snapshot_unavailable")

    def test_source_metadata_and_dependency_aliases_still_rejected(self):
        cases = ("linked.mbt", "docs.mbt.md", "draft.mbtx", "moon.lock",
                 "moon.work", "moon.work.json", "moon.pkg", ".mooncakes/lib/source.mbt")
        target = self.work / "linked-input"
        target.write_text(SOURCE, encoding="utf-8")
        for name in cases:
            path = self.project / name
            old = path.read_bytes() if path.exists() else None
            path.parent.mkdir(parents=True, exist_ok=True)
            path.unlink(missing_ok=True)
            self.make_link(path, target)
            try:
                with self.subTest(name=name):
                    report = self.json_report("--verify-project", "--project-moon",
                                             self.work / "missing compiler", code=2)
                    self.assert_verification(report, "snapshot_unavailable")
            finally:
                path.unlink()
                if old is not None:
                    path.write_bytes(old)

    def test_unsupported_literate_input_keeps_target_file_plan_and_explanation(self):
        (self.project / "moon.pkg").unlink()
        (self.project / "moon.pkg.json").write_text(
            json.dumps({"targets": {"js_only.mbt": ["js"]}}), encoding="utf-8")
        (self.project / "js_only.mbt").write_text(SOURCE.replace("escape", "js_escape"), encoding="utf-8")
        (self.project / "README.mbt.md").write_text(
            "# Documentation\n\n```mbt check\ntest { assert_eq(1, 1) }\n```\n", encoding="utf-8")
        report = self.json_report("--verify-project", *self.compiler_arguments(),
                                 code=2, isolated=False, timeout=90)
        verification = self.assert_verification(report, "scope_incomplete")
        self.assertIn("unsupported", verification["detail"])
        self.assertTrue(any(p.endswith("/README.mbt.md") for p in verification["unsupported_files"]))
        self.assertTrue(any("unsupported" in e for e in report["errors"]))
        self.assertEqual(report["files_selected"], 2)
        self.assertEqual(report["files_parsed"], 1)
        self.assert_base_finding(report)
        unsupported = [f for f in report["analysis_manifest"]["files"] if f["status"] == "unsupported"]
        self.assertEqual([Path(f["path"]).name for f in unsupported], ["README.mbt.md"])
        self.assertFalse(any(p.endswith("/js_only.mbt") for p in verification["compiler_files"]))

    def test_literate_only_plan_does_not_scan_other_backend_sources(self):
        (self.project / "danger.mbt").unlink()
        (self.project / "moon.pkg").unlink()
        (self.project / "moon.pkg.json").write_text(
            json.dumps({"targets": {"js_only.mbt": ["js"]}}), encoding="utf-8")
        (self.project / "js_only.mbt").write_text(SOURCE, encoding="utf-8")
        (self.project / "README.mbt.md").write_text(
            "```mbt check\ntest { assert_eq(1, 1) }\n```\n", encoding="utf-8")
        report = self.json_report("--verify-project", *self.compiler_arguments(),
                                 code=2, isolated=False, timeout=90)
        verification = self.assert_verification(report, "scope_incomplete")
        self.assertEqual(verification["compiler_files"], [])
        self.assertTrue(verification["unsupported_files"])
        self.assertEqual(report["files_selected"], 1)
        self.assertEqual(report["files_parsed"], 0)
        self.assertEqual(report["findings"], [])
        self.assertEqual([Path(f["path"]).name for f in report["analysis_manifest"]["files"]
                          if f["status"] == "unsupported"], ["README.mbt.md"])

    def test_real_document_named_directory_keeps_source_in_snapshot(self):
        directory = self.project / "README.md"
        directory.mkdir()
        source = directory / "extra.mbt"
        source.write_text(SOURCE, encoding="utf-8")
        report = self.json_report("--verify-project", *self.compiler_arguments(),
                                 isolated=False, timeout=90)
        verification = self.assert_verification(report, "compiler_verified")
        self.assertTrue(any(p.endswith("/README.md/extra.mbt") for p in verification["snapshot_sha256"]))

    @unittest.skipUnless(os.name == "posix", "POSIX parent-directory alias acceptance")
    def test_existing_parent_directory_alias_keeps_project_identity(self):
        alias = self.work / "parent-alias"
        alias.symlink_to(self.project.parent, target_is_directory=True)
        alias_project = alias / self.project.name
        report = self.json_report("--verify-project", *self.compiler_arguments(),
                                  target=alias_project, isolated=False, timeout=90)
        self.assert_base_finding(report)
        self.assert_verification(report, "compiler_verified")
        self.assertEqual(Path(report["findings"][0]["file"]).resolve(),
                         (self.project / "danger.mbt").resolve())

    def test_real_project_toolchain_and_findings_exit_policy(self):
        args = ["--verify-project", *self.compiler_arguments(), "--target", "native",
                "--analysis", "syntax", "--timeout-seconds", "60"]
        report = self.json_report(*args, isolated=False, timeout=90)
        self.assert_base_finding(report)
        self.assertEqual(report["errors"], [])
        self.assert_verification(report, "compiler_verified")
        report = self.json_report(*args, "--fail-on-error", code=1,
                                  isolated=False, timeout=90)
        self.assert_base_finding(report)
        self.assert_verification(report, "compiler_verified")

    def test_real_toolchain_sarif_verification(self):
        result = self.run_cli("--format", "sarif", "--verify-project",
                              *self.compiler_arguments(), "--target", "native",
                              "--timeout-seconds", "60", isolated=False, timeout=90)
        run = json.loads(result.stdout)["runs"][0]
        self.assert_verification(run["properties"], "compiler_verified")
        self.assertEqual([item["ruleId"] for item in run["results"]], [RULE])
        self.assertTrue(run["invocations"][0]["executionSuccessful"])

    def test_real_compiler_rejection_keeps_source_findings(self):
        args = self.compiler_arguments()
        (self.project / "type_error.mbt").write_text(
            'pub fn invalid() -> Int { "wrong type" }\n', encoding="utf-8")
        report = self.json_report("--verify-project", *args, "--target", "native",
                                  "--timeout-seconds", "60", code=2,
                                  isolated=False, timeout=90)
        self.assert_base_finding(report)
        self.assert_verification(report, "compiler_rejected")


if __name__ == "__main__":
    unittest.main(verbosity=2)
