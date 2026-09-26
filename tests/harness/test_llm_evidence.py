#!/usr/bin/env python3
"""Compiler-linked LLM context invariants; offline, isolated synthetic reports."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest

import test_llm_review as fixtures
sys.path.insert(0, str(fixtures.REPO / 'scripts'))
import llm_review as contract


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.fx = fixtures.LlmReviewContractTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.project = self.fx.project.resolve()
        self.source = self.fx.source.resolve()
        self.helper = self.project / 'bridge/helper.mbt'
        self.helper.parent.mkdir()
        self.helper.write_text('pub fn relay(value : String) -> String {\n' +
                               ''.join(f'  let _v{n} = "常量{n}"\n' for n in range(32)) +
                               '  value\n}\n', encoding='utf-8')
        self.dependency = self.project / '.mooncakes/vendor/dep.mbt'
        self.dependency.parent.mkdir(parents=True)
        self.dependency.write_text('pub fn behavior() -> Int { 1 }\n')
        self.entry = self.source.as_posix() + ':1:1'
        self.callee = self.helper.as_posix() + ':1:8'
        self.unit = {'id': 'unit:test', 'module_root': self.project.as_posix(), 'module_name': 'demo',
                     'package_name': 'demo', 'package_root': self.project.as_posix(), 'package_kind': 'library',
                     'target': 'native', 'role': 'production',
                     'inputs': [{'path': p.as_posix(), 'mode': 'source'} for p in (self.source, self.helper)]}
        trace = [self.source.as_posix() + ':2:1', self.helper.as_posix() + ':34:3',
                 self.source.as_posix() + ':3:3', self.entry + ':route_response']
        finding = self.fx.make_finding(dataflow=trace, evidence='verified_dataflow')
        semantic = {'schema': 'moon-audit.scoped-dataflow.v1', 'status': 'complete_within_declared_scope',
                    'entry_scope': 'registration/middleware are assumptions',
                    'routes': [{'entry': self.entry, 'route': '/raw',
                                'result': {'status': 'complete', 'reason': '', 'source_paths': [trace]}}],
                    'functions': [{'id': self.entry, 'parameters': [0], 'operations': [
                        ['Call', 1, self.callee, [0], self.source.as_posix() + ':3:3'], ['Return', 1]]},
                        {'id': self.callee, 'parameters': [2], 'operations': [['Return', 2]]}],
                    'function_units': [self.mapping(self.entry, self.source, 1, 5),
                                       self.mapping(self.callee, self.helper, 1, 35)],
                    'compilation_units': [copy.deepcopy(self.unit)],
                    'bindings': [{'query': self.source.as_posix() + ':3:7',
                                  'definition': self.helper.as_posix(), 'range': '1:8-1:13'}],
                    'models': [{'operation': 'escape', 'declaration_file': 'utils.mbt',
                                'sha256': 'a' * 64, 'range': '1:1-1:2'}]}
        self.report = self.fx.make_report([finding], project_verification={
            'status': 'compiler_verified', 'compilation_units': [copy.deepcopy(self.unit)],
            'snapshot_sha256': {p.as_posix(): fixtures.sha_of_file(p)
                                for p in self.project.rglob('*') if p.is_file()}}, semantic_analysis=semantic)

    def mapping(self, identity, source, start, end):
        return {'function': identity, 'source': source.as_posix(), 'unit': 'unit:test',
                'source_range': {'start_line': start, 'end_line': end, 'start_column': 1, 'end_column': 2}}

    def prepare(self, report=None, *extra):
        self.fx.report.write_text(json.dumps(report or self.report), encoding='utf-8')
        self.fx.prepare(*extra, report=self.fx.report)
        return self.fx.load_bundle()

    def context(self, bundle):
        return bundle['findings'][0]['semantic_context']

    def test_full_function_and_ir_are_sent_with_exact_cross_file_citations(self):
        bundle = self.prepare()
        context = self.context(bundle)
        self.assertEqual(context['status'], 'ready')
        self.assertTrue(bundle['semantic_snapshot_verified'])
        attachment = next(a for a in context['attachments'] if a['file'] == 'bridge/helper.mbt')
        self.assertEqual(attachment['text'], self.helper.read_text(encoding='utf-8').rstrip('\n'))
        prompt = (self.fx.bundle_dir / 'prompt.txt').read_text(encoding='utf-8')
        for text in ('reported static dataflow', 'declared_models', 'compilation_units', '常量31', self.callee):
            self.assertIn(text, prompt)
        quote = {'attachment_id': attachment['attachment_id'], 'file': attachment['file'],
                 'start_line': 34, 'end_line': 35, 'quote': '  value\n}'}
        contract.check_evidence(bundle['findings'][0], quote)
        for changed in ({**quote, 'attachment_id': 'foreign'}, {**quote, 'quote': 'value'},
                        {**quote, 'start_line': 36, 'end_line': 36}, {**quote, 'file': 'other.mbt'}):
            with self.assertRaises(contract.ReviewError):
                contract.check_evidence(bundle['findings'][0], changed)
        another = {**bundle['findings'][0], 'semantic_context': {'attachments': []}}
        with self.assertRaises(contract.ReviewError):
            contract.check_evidence(another, quote)

    def test_ambiguous_or_mismatched_identity_is_disclosed(self):
        changes = {
            'duplicate_function': lambda r: r['semantic_analysis']['functions'].append(r['semantic_analysis']['functions'][0]),
            'dangling_call': lambda r: r['semantic_analysis']['functions'][0]['operations'][0].__setitem__(2, 'missing'),
            'unknown_op': lambda r: r['semantic_analysis']['functions'][0]['operations'].insert(0, ['MadeUpSafe', 4]),
            'wrong_source': lambda r: r['semantic_analysis']['function_units'][1].__setitem__('source', self.source.as_posix()),
            'wrong_column': lambda r: r['semantic_analysis']['function_units'][1]['source_range'].__setitem__('start_column', 999),
            'missing_range': lambda r: r['semantic_analysis']['function_units'][1].pop('source_range'),
            'bad_range': lambda r: r['semantic_analysis']['function_units'][1]['source_range'].__setitem__('end_line', 999),
            'unit_mismatch': lambda r: r['semantic_analysis']['compilation_units'][0].__setitem__('role', 'whitebox_test'),
            'missing_snapshot': lambda r: r['project_verification']['snapshot_sha256'].pop(self.helper.as_posix()),
            'duplicate_route': lambda r: r['semantic_analysis']['routes'].append(r['semantic_analysis']['routes'][0]),
            'status_mismatch': lambda r: r['semantic_analysis']['routes'][0]['result'].__setitem__('status', 'incomplete'),
            'missing_verification': lambda r: r.__setitem__('project_verification', None),
            'alias_snapshot': lambda r: r['project_verification']['snapshot_sha256'].__setitem__('bridge/../bridge/helper.mbt', 'a' * 64),
        }
        for name, mutate in changes.items():
            with self.subTest(name=name):
                report = copy.deepcopy(self.report)
                mutate(report)
                bundle = self.prepare(report)
                self.assertEqual(self.context(bundle)['status'], 'unavailable')
                self.assertFalse(self.context(bundle)['attachments'])
                self.assertTrue(bundle['disclosures'])

    def test_source_configuration_dependency_and_input_set_changes_are_rejected(self):
        bundle = self.prepare()
        for path in (self.helper, self.project / 'moon.mod', self.dependency):
            with self.subTest(path=path.name):
                original = path.read_bytes()
                path.write_bytes(original + b'\n// modified\n')
                with self.assertRaises(contract.ReviewError):
                    contract.reverify_sources(bundle)
                path.write_bytes(original)
        added = self.project / 'new.mbt'
        added.write_text('pub fn new() -> Int { 1 }')
        with self.assertRaises(contract.ReviewError):
            contract.reverify_sources(bundle)
        added.unlink()
        contract.reverify_sources(bundle)
        old = self.helper.read_bytes()
        self.helper.unlink()
        with self.assertRaises(contract.ReviewError):
            contract.reverify_sources(bundle)
        self.helper.write_bytes(old)

    def test_budget_omits_whole_function_instead_of_claiming_partial_text_complete(self):
        bundle = self.prepare(None, '--max-context-chars', '600')
        self.assertEqual(self.context(bundle)['status'], 'unavailable')
        self.assertEqual(self.context(bundle)['reason'], 'semantic_context_budget')
        reviews = self.fx.default_reviews(bundle)
        reviews[0]['verdict'] = 'supported_concern'
        with self.assertRaises(contract.ReviewError):
            contract.validate_response(bundle, {'schema': contract.SCHEMA_RESPONSE,
                'bundle_id': bundle['bundle_id'], 'reviews': reviews})

    def test_recursion_terminates_and_post_return_call_is_not_reached(self):
        functions = self.report['semantic_analysis']['functions']
        functions[1]['operations'].insert(0, ['Call', 3, self.callee, [2], self.helper.as_posix() + ':2:1'])
        functions[0]['operations'].append(['Call', 9, 'dead_missing', [], self.source.as_posix() + ':9:1'])
        context = self.context(self.prepare())
        self.assertEqual(context['status'], 'ready')
        self.assertEqual(len(context['functions']), 2)

    def test_same_sink_in_another_route_does_not_expand_this_findings_graph(self):
        semantic = self.report['semantic_analysis']
        other = copy.deepcopy(semantic['routes'][0])
        other['entry'] = self.source.as_posix() + ':8:1'
        other['route'] = '/other'
        other['result']['source_paths'][0][-1] = other['entry'] + ':route_response'
        semantic['routes'].append(other)
        semantic['functions'].append({'id': other['entry'], 'parameters': [],
            'operations': [['Call', 0, 'unrelated_missing_function', [], 'other'], ['Return', 0]]})
        context = self.context(self.prepare())
        self.assertEqual(context['status'], 'ready')
        self.assertEqual([r['route'] for r in context['routes']], ['/raw'])
        self.assertEqual({f['id'] for f in context['functions']}, {self.entry, self.callee})

    def test_partial_evidence_remains_partial(self):
        self.report['findings'][0]['evidence'] = 'partial_dataflow'
        self.report['semantic_analysis']['routes'][0]['result']['status'] = 'incomplete'
        self.report['errors'] = ['unsupported_html_context']
        bundle = self.prepare()
        self.assertEqual(self.context(bundle)['status'], 'ready')
        self.assertTrue(bundle['scan_state']['static_incomplete'])
        self.assertEqual(bundle['findings'][0]['evidence'], 'partial_dataflow')

    def test_unicode_line_separators_are_explicitly_unsupported_for_semantic_ranges(self):
        text = self.helper.read_text(encoding='utf-8').replace('常量0', '常量0\u2028\u2029')
        self.helper.write_text(text, encoding='utf-8')
        self.report['project_verification']['snapshot_sha256'][self.helper.as_posix()] = fixtures.sha_of_file(self.helper)
        context = self.context(self.prepare())
        self.assertEqual(context['status'], 'unavailable')
        self.assertEqual(context['reason'], 'unsupported_semantic_source_line_endings')
        self.assertEqual(context['attachments'], [])

    def test_invalid_snapshot_path_and_empty_prompt_budget_fail_cleanly(self):
        report = copy.deepcopy(self.report)
        report['project_verification']['snapshot_sha256']['bad\x00.mbt'] = 'a' * 64
        self.fx.report.write_text(json.dumps(report), encoding='utf-8')
        run = self.fx.prepare(report=self.fx.report, expect=2)
        self.assertNotIn('Traceback', run.stderr)
        report = self.fx.make_report([], errors=['x' * (contract.PROMPT_MAX_BYTES + 1)])
        self.fx.report.write_text(json.dumps(report), encoding='utf-8')
        self.fx.prepare(report=self.fx.report, expect=2)
        self.assertFalse((self.fx.bundle_dir / 'bundle.json').exists())

    def test_crlf_raw_digest_and_unicode_citations(self):
        self.helper.write_bytes(self.helper.read_bytes().replace(b'\n', b'\r\n'))
        self.report['project_verification']['snapshot_sha256'][self.helper.as_posix()] = fixtures.sha_of_file(self.helper)
        bundle = self.prepare()
        attachment = next(a for a in self.context(bundle)['attachments'] if a['file'] == 'bridge/helper.mbt')
        contract.check_evidence(bundle['findings'][0], {'attachment_id': attachment['attachment_id'],
            'file': attachment['file'], 'start_line': 33, 'end_line': 33, 'quote': '  let _v31 = "常量31"'})
        contract.reverify_sources(bundle)


if __name__ == '__main__':
    unittest.main(verbosity=2)
