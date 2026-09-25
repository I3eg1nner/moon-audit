#!/usr/bin/env python3
"""Regression gates for the reduced syntax-pattern scanner; legacy semantic gates are archived."""
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


    def test_rules_enable_disabled_and_accumulate(self):
        (self.root / "cast.mbt").write_text("fn cast_it(value : Int) -> Int { value.cast() }\n", encoding="utf-8")
        report = json.loads(self.run_cli("--format", "json", "--rule", "CWE-704/unsafe-cast").stdout)
        self.assertEqual({f["rule_id"] for f in report["findings"]}, {"CWE-704/unsafe-cast"})
        report = json.loads(self.run_cli(
            "--format", "json", "--rule", "CWE-704/unsafe-cast", "--rule", "CWE-116/replace-escaping",
        ).stdout)
        self.assertEqual({f["rule_id"] for f in report["findings"]}, {"CWE-704/unsafe-cast", "CWE-116/replace-escaping"})


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
        self.assertEqual(report["files_selected"], 3)
        self.assertEqual(report["files_scanned"], 3)
        self.assertEqual(report["files_parsed"], 2)
        self.assertIn("implicit-excludes=", report["analysis_scope"])
        text = self.run_cli(code=2).stdout
        self.assertNotIn("No issues found.", text)
        self.assertIn("Parse error", text)


    def test_compiler_accepted_new_syntax_is_explicitly_incomplete(self):
        # The selected moonc versions accept tuple patterns in for-in, but
        # parser 0.4.0 cannot parse them yet. No clean scan may be reported.
        (self.root / "new_syntax.mbt").write_text(
            'pub fn destructure() -> Unit {\n'
            '  for (x, y) in [(1, 2)] { ignore(x); ignore(y) }\n'
            '}\n', encoding='utf-8',
        )
        report = json.loads(self.run_cli('--format', 'json', code=2).stdout)
        self.assertTrue(any('new_syntax.mbt' in error for error in report['errors']))
        self.assertIn('parse-failures=1', report['analysis_scope'])
        self.assertGreater(len(report['findings']), 0)

    def test_lexical_errors_in_legacy_source_remain_incomplete(self):
        for body in ['loop 1 { x => x } `', 'try? g() $']:
            with self.subTest(body=body):
                (self.root / 'invalid.mbt').write_text('fn broken() { ' + body + ' }\n', encoding='utf-8')
                report = json.loads(self.run_cli('--format', 'json', code=2).stdout)
                self.assertTrue(any('Lexer:' in error for error in report['errors']))
                self.assertEqual(report['files_parsed'], 2)
                self.assertEqual(report['files_selected'], 3)
                self.assertEqual(len(report['findings']), 2)

    def test_incomplete_scan_cannot_replace_baseline(self):
        baseline = self.root / "baseline.json"
        baseline.write_text("existing baseline", encoding="utf-8")
        (self.root / "broken.mbt").write_text("fn broken( {", encoding="utf-8")
        result = self.run_cli("generate-baseline", "--output", baseline, code=2)
        self.assertEqual(baseline.read_text(encoding="utf-8"), "existing baseline")
        self.assertNotIn("Baseline written to:", result.stdout)


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


    def test_sarif_reports_current_version(self):
        report = json.loads(self.run_cli("--format", "sarif").stdout)
        self.assertEqual(report["runs"][0]["tool"]["driver"]["version"], "0.5.0-dev")


    def test_scope_is_explicit_even_with_no_findings(self):
        for p in self.root.glob('*.mbt'):
            p.write_text('pub fn safe() -> String { "safe" }\n', encoding='utf-8')
        for fmt in ['json', 'sarif']:
            report = json.loads(self.run_cli('--format', fmt).stdout)
            scope = report['analysis_scope'] if fmt == 'json' else report['runs'][0]['properties']['analysis_scope']
            self.assertIn('engine=syntax-pattern', scope)
            self.assertIn('(moonbitlang/parser 0.4.0+moon-audit-legacy.1)', scope)
            self.assertIn('interprocedural=false', scope)
            self.assertIn('unanalyzed-is-not-safe', scope)

    def test_manifest_records_file_and_rule_scope(self):
        (self.root / 'broken.mbt').write_text('fn broken( {', encoding='utf-8')
        changed = self.root / 'changed.txt'
        changed.write_text('foo.mbt\nbroken.mbt\n', encoding='utf-8')
        report = json.loads(self.run_cli(
            '--format', 'json', '--changed-files', changed,
            '--rule', 'CWE-116/replace-escaping', code=2,
        ).stdout)
        manifest = report['analysis_manifest']
        self.assertEqual(manifest['schema'], 'moon-audit.analysis-manifest.v1')
        self.assertEqual(manifest['verification'], 'syntax_only')
        self.assertEqual(manifest['selection']['incremental'], True)
        self.assertEqual(manifest['selection']['enumerated_scope'], 'eligible_mbt_files_after_directory_exclusions')
        files = {Path(f['path']).name: f for f in manifest['files']}
        self.assertEqual(files['foo.mbt']['status'], 'parsed')
        self.assertEqual(files['broken.mbt']['status'], 'parse_failed')
        self.assertEqual(files['broken.mbt']['reason'], 'parser_rejected')
        self.assertEqual(files['myfoo.mbt']['status'], 'skipped')
        self.assertEqual(files['myfoo.mbt']['reason'], 'not_in_changed_files')
        rules = {r['id']: r for r in files['foo.mbt']['rules']}
        self.assertEqual(len(rules), 14)
        self.assertEqual(rules['CWE-116/replace-escaping']['status'], 'evaluated')
        self.assertEqual(rules['CWE-113/crlf-injection']['status'], 'disabled')
        self.assertEqual(rules['CWE-79/cmark-unsafe']['status'], 'disabled')
        self.assertEqual(manifest['rule_capabilities'][0]['evidence'], 'syntax_hint')
        self.assertIn('scan_errors', manifest['incomplete_reasons'])
        self.assertEqual(report['findings'][0]['evidence'], 'syntax_hint')

    def test_manifest_marks_missing_package_gate_and_sarif_matches(self):
        report = json.loads(self.run_cli('--format', 'json').stdout)
        manifest = report['analysis_manifest']
        files = {Path(f['path']).name: f for f in manifest['files']}
        rules = {r['id']: r for r in files['foo.mbt']['rules']}
        self.assertEqual(rules['CWE-79/cmark-unsafe']['status'], 'gated_out')
        self.assertEqual(rules['CWE-79/cmark-unsafe']['reason'], 'cmark_import_hint_absent')
        self.assertEqual(rules['CWE-116/replace-escaping']['status'], 'evaluated')
        self.assertNotIn('scan_errors', manifest['incomplete_reasons'])
        sarif = json.loads(self.run_cli('--format', 'sarif').stdout)
        run = sarif['runs'][0]
        self.assertEqual(run['properties']['analysis_manifest'], manifest)
        self.assertEqual(run['results'][0]['properties']['evidence'], 'syntax_hint')

    def test_legacy_package_imports_activate_only_matching_rule(self):
        (self.root / 'moon.pkg').unlink()
        (self.root / 'foo.mbt').write_text(
            'fn render_doc(md : String) -> String { render(safe=false, md) }\n',
            encoding='utf-8',
        )
        (self.root / 'myfoo.mbt').write_text('pub fn safe() -> String { "safe" }\n', encoding='utf-8')
        cases = [
            {'import': ['moonbit-community/cmark']},
            {'import': [{'path': 'moonbit-community/cmark', 'alias': 'cmark'}]},
            {'import': {'moonbit-community/cmark': 'cmark'}},
        ]
        for package in cases:
            with self.subTest(package=package):
                (self.root / 'moon.pkg.json').write_text(json.dumps(package), encoding='utf-8')
                report = json.loads(self.run_cli('--format', 'json', '--rule', 'CWE-79/cmark-unsafe').stdout)
                self.assertEqual({f['rule_id'] for f in report['findings']}, {'CWE-79/cmark-unsafe'})
                rules = {r['id']: r for r in report['analysis_manifest']['files'][0]['rules']}
                self.assertEqual(rules['CWE-79/cmark-unsafe']['status'], 'evaluated')
        (self.root / 'moon.pkg.json').write_text('{"import": ["unrelated/pkg"]}', encoding='utf-8')
        report = json.loads(self.run_cli('--format', 'json', '--rule', 'CWE-79/cmark-unsafe').stdout)
        self.assertEqual(report['findings'], [])
        rules = {r['id']: r for r in report['analysis_manifest']['files'][0]['rules']}
        self.assertEqual(rules['CWE-79/cmark-unsafe']['status'], 'gated_out')

    def test_module_dependency_does_not_enable_package_rule(self):
        (self.root / 'moon.mod').unlink()
        (self.root / 'moon.mod.json').write_text(
            '{"name":"fixture/cli","deps":{"moonbit-community/cmark":"0.1.0"}}',
            encoding='utf-8',
        )
        (self.root / 'moon.pkg').unlink()
        (self.root / 'moon.pkg.json').write_text('{"import": []}', encoding='utf-8')
        (self.root / 'foo.mbt').write_text(
            'fn render_doc(md : String) -> String { render(safe=false, md) }\n',
            encoding='utf-8',
        )
        report = json.loads(self.run_cli('--format', 'json', '--rule', 'CWE-79/cmark-unsafe').stdout)
        self.assertEqual(report['findings'], [])
        rules = {r['id']: r for r in report['analysis_manifest']['files'][0]['rules']}
        self.assertEqual(rules['CWE-79/cmark-unsafe']['status'], 'gated_out')
        (self.root / 'moon.pkg.json').write_text(
            '{"import": ["moonbit-community/cmark"]}', encoding='utf-8',
        )
        report = json.loads(self.run_cli('--format', 'json', '--rule', 'CWE-79/cmark-unsafe').stdout)
        self.assertEqual({f['rule_id'] for f in report['findings']}, {'CWE-79/cmark-unsafe'})

    def test_malformed_legacy_package_is_an_incomplete_scan(self):
        (self.root / 'moon.pkg').unlink()
        for content, expected in [('{"import": [', 'Invalid package JSON'),
                                  ('{"import": 42}', 'Invalid package import field'),
                                  ('{"import": {"moonbit-community/cmark": 42}}',
                                   'Invalid package import field')]:
            with self.subTest(content=content):
                (self.root / 'moon.pkg.json').write_text(content, encoding='utf-8')
                report = json.loads(self.run_cli('--format', 'json', code=2).stdout)
                self.assertEqual(sum(expected in e for e in report['errors']), 1)
                self.assertEqual(report['files_parsed'], 2)
                self.assertIn('scan_errors', report['analysis_manifest']['incomplete_reasons'])

    def test_strict_scan_respects_legacy_backend_targets(self):
        from scan_compatible import scan as compatible_scan
        (self.root / 'moon.mod').unlink()
        (self.root / 'moon.mod.json').write_text(
            '{"name":"fixture/cli","preferred-target":"native"}', encoding='utf-8',
        )
        (self.root / 'moon.pkg').unlink()
        (self.root / 'moon.pkg.json').write_text(
            '{"targets":{"myfoo.mbt":["js"],"native_only.mbt":["native"]}}',
            encoding='utf-8',
        )
        (self.root / 'foo.mbt').write_text('pub fn safe() -> String { "safe" }\n', encoding='utf-8')
        (self.root / 'native_only.mbt').write_text('pub fn native_only() -> Int { 1 }\n', encoding='utf-8')
        native = compatible_scan(self.root, ANALYZER, ['moon'], 'native', [])
        self.assertEqual(native['status'], 'compiled_and_parsed', native)
        self.assertEqual(native['file_selection']['compiler_files'], ['foo.mbt', 'native_only.mbt'])
        self.assertEqual(native['scan']['findings'], [])
        files = {Path(f['path']).name: f['status']
                 for f in native['scan']['analysis_manifest']['files']}
        self.assertEqual(files['myfoo.mbt'], 'skipped')
        js = compatible_scan(self.root, ANALYZER, ['moon'], 'js', [])
        self.assertEqual(js['status'], 'compiled_and_parsed', js)
        self.assertEqual(js['file_selection']['compiler_files'], ['foo.mbt', 'myfoo.mbt'])
        self.assertEqual([(Path(f['file']).name, f['rule_id']) for f in js['scan']['findings']],
                         [('myfoo.mbt', 'CWE-116/replace-escaping')])
        self.assertEqual(js['file_selection']['compiler_files_not_parsed'], [])

    def test_retired_semantic_options_are_rejected(self):
        for args in [('--cfg-engine',), ('--cfg-verify',), ('--mode', 'deep'), ('--context-strategy', 'insensitive')]:
            with self.subTest(args=args):
                self.run_cli(*args, code=2)
        (self.root / 'taint-rules.json').write_text('{}')
        self.assertIn('unsupported', self.run_cli(code=2).stdout)
        (self.root / 'taint-rules.json').unlink()
        (self.root / '.moon-audit.json').write_text('{"taint": {}}')
        self.assertIn('retired', self.run_cli(code=2).stdout)

    def test_sarif_incomplete_is_not_successful(self):
        (self.root / 'broken.mbt').write_text('fn broken( {')
        run = json.loads(self.run_cli('--format', 'sarif', code=2).stdout)['runs'][0]
        self.assertFalse(run['invocations'][0]['executionSuccessful'])
        self.assertTrue(run['properties']['errors'])

    def test_header_pattern_is_a_review_hint_with_literal_control(self):
        (self.root / 'header.mbt').write_text('pub fn set(r : R, value : String) -> Unit { r.set_header("X", value); r.set_header("X", "safe") }')
        report = json.loads(self.run_cli('--format', 'json', '--rule', 'CWE-113/crlf-injection').stdout)
        self.assertEqual(len(report['findings']), 1)
        self.assertEqual(report['findings'][0]['confidence'], 'low')
        self.assertEqual(report['findings'][0]['evidence'], 'syntax_hint')
        self.assertEqual(report['findings'][0]['dataflow'], [])
        self.assertIn('Confirm API identity', report['findings'][0]['message'])

if __name__ == '__main__':
    unittest.main()
