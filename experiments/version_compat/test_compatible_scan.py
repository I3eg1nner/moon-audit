"""Real compiler and scanner checks for the strict cross-version entry point."""
import os
from pathlib import Path
import tempfile
import unittest

from scripts.scan_compatible import scan
from verify import FILES, GAP_SOURCE, ROOT

SCANNER = ROOT / '_build/native/debug/build/src/main/main.exe'
PROJECT_MOON = ([os.environ['PROJECT_MOON_WRAPPER'], 'moon']
                if 'PROJECT_MOON_WRAPPER' in os.environ else ['moon'])


class CompatibleScanTests(unittest.TestCase):
    def project(self):
        temporary = tempfile.TemporaryDirectory(prefix='moon-audit-strict-scan-')
        self.addCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        for name, content in FILES.items():
            (directory / name).write_text(content)
        return directory

    def test_compiler_checked_portable_subset(self):
        result = scan(self.project(), SCANNER, PROJECT_MOON, 'native', [])
        self.assertEqual(result['status'], 'compiled_and_parsed', result)
        locations = {(Path(f['file']).name, f['line'], f['rule_id'])
                     for f in result['scan']['findings']}
        self.assertIn(('danger.mbt', 2, 'CWE-116/replace-escaping'), locations)
        self.assertIn(('static_call.mbt', 2, 'CWE-116/replace-escaping'), locations)
        self.assertFalse(any(name in ('safe.mbt', 'static_safe.mbt')
                             for name, _, _ in locations))
        self.assertEqual(result['scan']['errors'], [])
        self.assertEqual(result['scan']['files_selected'], 4)
        self.assertEqual(result['scan']['files_parsed'], 4)
        self.assertIn('moonc v', result['project_toolchain'])

    def test_compiler_accepted_parser_gap_is_incomplete(self):
        project = self.project()
        (project / 'new_syntax.mbt').write_text(GAP_SOURCE)
        result = scan(project, SCANNER, PROJECT_MOON, 'native', [])
        self.assertEqual(result['status'], 'scanner_incomplete', result)
        self.assertTrue(any('new_syntax.mbt' in error
                            for error in result['scan']['errors']))
        self.assertEqual(result['scan']['files_selected'], 5)
        self.assertEqual(result['scan']['files_parsed'], 4)
        locations = {(Path(f['file']).name, f['line'], f['rule_id'])
                     for f in result['scan']['findings']}
        self.assertIn(('danger.mbt', 2, 'CWE-116/replace-escaping'), locations)
        self.assertIn(('static_call.mbt', 2, 'CWE-116/replace-escaping'), locations)
        self.assertFalse(any(name in ('safe.mbt', 'static_safe.mbt')
                             for name, _, _ in locations))


if __name__ == '__main__':
    unittest.main()
