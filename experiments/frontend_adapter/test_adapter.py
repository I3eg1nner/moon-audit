"""Compiler-backed source witnesses and rejection checks for the bounded frontend."""
from pathlib import Path
import os
import unittest

from adapter import Reject, analyze

ANALYZER_MOON = [os.environ['ANALYZER_MOON_WRAPPER'], 'moon'] if 'ANALYZER_MOON_WRAPPER' in os.environ else ['moon']
PROJECT_MOON = [os.environ['PROJECT_MOON_WRAPPER'], 'moon'] if 'PROJECT_MOON_WRAPPER' in os.environ else ANALYZER_MOON
FIXTURES = Path(__file__).parent / 'fixtures'


class AdapterTests(unittest.TestCase):
    def check_case(self, name, expected):
        source = (FIXTURES / f'{name}.mbt.txt').read_text()
        report = analyze(source, ANALYZER_MOON, project_moon=PROJECT_MOON, fixture=name)
        self.assertEqual(report['status'], 'fixed_point')
        sink_calls = [line for line in source.splitlines() if line.strip().startswith('sink(')]
        actual = [bool(report['result']['findings'].get(f'sink@{line}:3'))
                  for line, text in enumerate(source.splitlines(), 1)
                  if text.strip().startswith('sink(')]
        self.assertEqual(len(sink_calls), len(expected))
        self.assertEqual(actual, expected)
        self.assertEqual(len(report['lookups']), source.count('source()') - 1 + len(sink_calls) + (1 if 'fill(' in source else 0))
        return report

    def test_read_after_write_same_object(self):
        self.check_case('read_after_write_alias', [True, True])

    def test_clean_last_same_object(self):
        self.check_case('clean_last_alias', [False, False])

    def test_dirty_last_same_object(self):
        self.check_case('dirty_last_alias', [True, False])

    def test_distinct_objects(self):
        self.check_case('read_after_write_distinct', [True, False, False, False])

    def test_shadowed_local(self):
        self.check_case('shadow', [False, True])

    def test_string_only_direct_call_return_flow(self):
        source = (FIXTURES / 'string_direct_positive.mbt.txt').read_text()
        report = analyze(source, ANALYZER_MOON, project_moon=PROJECT_MOON)
        self.assertEqual(report['status'], 'fixed_point')
        self.assertEqual(set(report['result']['findings']), {'sink@5:3'})
        self.assertTrue(report['result']['findings']['sink@5:3'])
        self.assertEqual(len(report['lookups']), 3)
        self.assertFalse(any(op['op'] in {'alloc', 'load', 'store'}
                             for func in report['ir']['functions'].values()
                             for block in func['blocks'].values() for op in block))

    def test_string_only_safe_return_and_literal(self):
        source = (FIXTURES / 'string_direct_safe.mbt.txt').read_text()
        report = analyze(source, ANALYZER_MOON, project_moon=PROJECT_MOON)
        self.assertEqual(report['status'], 'fixed_point')
        self.assertEqual(report['result']['findings'], {})
        self.assertEqual(len(report['lookups']), 6)

    def test_string_return_with_box_stays_out_of_scope(self):
        source = (FIXTURES / 'read_after_write_alias.mbt.txt').read_text()
        source += '\nfn get(box : Box) -> String { box.value }\n'
        with self.assertRaises(Reject) as caught:
            analyze(source, ANALYZER_MOON, project_moon=PROJECT_MOON)
        self.assertEqual(caught.exception.status, 'unsupported_semantics')

    def test_comments_and_spacing_keep_semantics(self):
        source = (FIXTURES / 'shadow.mbt.txt').read_text()
        changed = source.replace('  let old = box', '  // benign comment\n  let old  =  box')
        report = analyze(changed, ANALYZER_MOON, project_moon=PROJECT_MOON)
        self.assertEqual(len(report['result']['findings']), 1)
        self.assertEqual(report['status'], 'fixed_point')

    def test_unknown_semantics_rejected(self):
        source = (FIXTURES / 'read_after_write_alias.mbt.txt').read_text()
        source = source.replace('second.safe = second.value',
                                'if true { second.safe = second.value }')
        with self.assertRaises(Reject) as caught:
            analyze(source, ANALYZER_MOON, project_moon=PROJECT_MOON)
        self.assertEqual(caught.exception.status, 'unsupported_syntax')

    def test_analyzer_build_version_rejected(self):
        import adapter
        old = adapter.ANALYZER_COMPILER
        try:
            adapter.ANALYZER_COMPILER = 'moonc v0.0.0-impossible'
            with self.assertRaises(Reject) as caught:
                analyze((FIXTURES / 'shadow.mbt.txt').read_text(), ANALYZER_MOON, project_moon=PROJECT_MOON)
            self.assertEqual(caught.exception.status, 'analyzer_toolchain_mismatch')
        finally:
            adapter.ANALYZER_COMPILER = old


if __name__ == '__main__':
    unittest.main()
