#!/usr/bin/env python3
"""Exercise the native compiler supervisor; Python is only the test harness."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
ANALYZER = Path(os.environ.get('ANALYZER', ROOT / '_build/native/debug/build/src/main/main.exe')).resolve()
DEFAULT_HELPER = ROOT / '_build/native/release/build/tests/native_process_helper/native_process_helper.exe'
HELPER = Path(os.environ.get('PROCESS_HELPER', DEFAULT_HELPER)).resolve()

class Supervision(unittest.TestCase):
    def setUp(self):
        if not HELPER.is_file():
            self.fail(f'Build native release test helper first: {HELPER}')
        self.temp = tempfile.TemporaryDirectory(prefix='moon-audit-supervision-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'moon.mod').write_text('name = "fixture/supervision"\n', encoding='utf-8')
        (self.root / 'moon.pkg').write_text('', encoding='utf-8')
        (self.root / 'danger.mbt').write_text('pub fn f(s : String) -> String { s.replace(old="<", new="&lt;") }\n', encoding='utf-8')

    def run_mode(self, mode, timeout=1):
        env = os.environ.copy()
        env['MOON_AUDIT_TEST_MODE'] = mode
        env['MOON_AUDIT_TEST_SENTINEL'] = str(self.root / 'survived')
        result = subprocess.run([str(ANALYZER), '--verify-project', '--project-moon', str(HELPER),
                                 '--timeout-seconds', str(timeout), '--format', 'json', str(self.root)],
                                env=env, capture_output=True, text=True, encoding='utf-8', timeout=20)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertTrue(report['findings'], report)
        return report

    def test_timeout_reaps_descendants(self):
        report = self.run_mode('timeout')
        self.assertEqual(report['project_verification']['status'], 'compiler_execution_failed')
        time.sleep(3.5)
        self.assertFalse((self.root / 'survived').exists(), 'Compiler descendant survived cancellation')

    def test_both_output_streams_are_bounded(self):
        report = self.run_mode('flood', timeout=10)
        self.assertIn('compiler_output_limit', report['project_verification']['detail'])

    def test_source_change_invalidates_verification(self):
        report = self.run_mode('change')
        self.assertEqual(report['project_verification']['status'], 'project_changed')

    def test_unknown_plan_cannot_succeed(self):
        report = self.run_mode('bad-plan')
        self.assertEqual(report['project_verification']['status'], 'compiler_plan_unavailable')

if __name__ == '__main__':
    unittest.main(verbosity=2)
