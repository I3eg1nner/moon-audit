#!/usr/bin/env python3
"""Real compiler-to-extracted-LLM-helper acceptance; no external model calls."""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from native_semantic_test import Acceptance, ROOT, SEMANTIC_ID, require
from cross_package_test import BRIDGE, LEAF, EXPRESSIONS, routes


class LlmContext(Acceptance):
    def helper(self, *args, expected=0):
        run = subprocess.run([sys.executable, str(self.args.review_script), *map(str, args)],
                             text=True, capture_output=True, timeout=90)
        require(run.returncode == expected, f'LLM helper exit {run.returncode}: {run.stdout} {run.stderr}')
        return run

    def run(self):
        self.hint_file.unlink()
        (self.project / 'moon.pkg').write_text(
            'import { "oboard/mocket", "acceptance/semantic/bridge" @helpers }\nsupported_targets = "native"\n')
        bridge = self.project / 'bridge'
        bridge.mkdir()
        (bridge / 'moon.pkg').write_text('import { "oboard/mocket", "acceptance/semantic/leaf" }\n')
        (bridge / 'helpers.mbt').write_text(BRIDGE)
        leaf = self.project / 'leaf'
        leaf.mkdir()
        (leaf / 'moon.pkg').write_text('')
        helper_file = leaf / 'helpers.mbt'
        # A genuine AST span must retain a complete helper longer than the old
        # +/-12-line context window; comments add no unsupported IR behavior.
        helper_file.write_text(LEAF.replace('{ "<p>"', '{\n' +
            ''.join(f'  // source context line {n}\n' for n in range(32)) + '  "<p>"'), encoding='utf-8')
        self.source_file.write_text(routes(EXPRESSIONS))
        scan_path = self.temporary / 'scan.json'
        bundle_path = self.temporary / 'bundle'
        response_path = self.temporary / 'response.json'
        output_path = self.temporary / 'review.json'

        def positive():
            code, report, _ = self.cli('cross_package_llm_input')
            findings = self.complete(code, report)
            require(len(findings) == 3 and len(report['findings']) == 3, 'expected only three dataflow findings')
            scan_path.write_text(json.dumps(report), encoding='utf-8')
            self.helper('prepare', '--report', scan_path, '--project', self.project, '--output', bundle_path)
            bundle = json.loads((bundle_path / 'bundle.json').read_text(encoding='utf-8'))
            require(bundle['semantic_snapshot_verified'], 'full input snapshot was not rechecked')
            reviews = []
            by_route = {}
            for finding in bundle['findings']:
                context = finding['semantic_context']
                require(context['status'] == 'ready', 'missing compiler-linked context: ' + context['reason'])
                require(len(context['routes']) == 1, 'finding linked to more than its actual route')
                route = context['routes'][0]['route']
                by_route[route] = finding
                require(context['functions'] and context['bindings'] and context['declared_models'], 'IR/binding/model evidence missing')
                attachment = next(a for a in context['attachments'] if a['file'].startswith('bridge/'))
                reviews.append({'finding_id': finding['finding_id'], 'verdict': 'needs_review',
                    'rationale': 'Exact project helper evidence; route execution and output assumptions still need review.',
                    'missing_context': ['runtime registration and middleware behavior'],
                    'evidence': [{'attachment_id': attachment['attachment_id'], 'file': attachment['file'],
                        'start_line': attachment['start_line'], 'end_line': attachment['end_line'], 'quote': attachment['text']}]})
            require(set(by_route) == {'/raw', '/fake', '/second-value'}, 'unexpected finding-to-route mapping')
            raw = by_route['/raw']['semantic_context']
            wide = next(a for a in raw['attachments'] if a['file'] == 'leaf/helpers.mbt')
            require(wide['end_line'] - wide['start_line'] > 24 and wide['text'].endswith('}'), 'complete wide helper not included')
            require(not any(a['file'] == 'leaf/helpers.mbt' for a in by_route['/fake']['semantic_context']['attachments']),
                    'same-spelled fake encoder acquired unrelated helper context')
            response = {'schema': 'moon-audit.llm-review-response.v1', 'bundle_id': bundle['bundle_id'], 'reviews': reviews}
            response_path.write_text(json.dumps(response), encoding='utf-8')
            self.helper('validate', '--bundle', bundle_path, '--response', response_path, '--output', output_path)
            accepted = json.loads(output_path.read_text(encoding='utf-8'))
            require(accepted['origin'] == 'llm_unverified' and accepted['scope_complete'], 'review evidence was upgraded or incomplete')
            require(all(r['static_evidence'] == 'verified_dataflow' for r in accepted['reviews']), 'static evidence changed')
            self.bundle, self.response, self.by_route = bundle, response, by_route
            self.accepted = output_path.read_bytes()
            self.record['context_summary'] = {route: {'functions': len(f['semantic_context']['functions']),
                'attachments': len(f['semantic_context']['attachments']), 'status': f['semantic_context']['status']}
                for route, f in by_route.items()}
        self.case('actual_cross_package_report_includes_complete_function_evidence', positive)

        def foreign_quote():
            fake_id = self.by_route['/fake']['finding_id']
            wide = next(a for a in self.by_route['/raw']['semantic_context']['attachments'] if a['file'] == 'leaf/helpers.mbt')
            forged = json.loads(json.dumps(self.response))
            review = next(r for r in forged['reviews'] if r['finding_id'] == fake_id)
            review['evidence'] = [{'attachment_id': wide['attachment_id'], 'file': wide['file'],
                'start_line': wide['start_line'], 'end_line': wide['end_line'], 'quote': wide['text']}]
            response_path.write_text(json.dumps(forged), encoding='utf-8')
            self.helper('validate', '--bundle', bundle_path, '--response', response_path, '--output', output_path, expected=2)
            require(output_path.read_bytes() == self.accepted, 'foreign quote replaced the accepted output')
            response_path.write_text(json.dumps(self.response), encoding='utf-8')
        self.case('other_findings_attachment_cannot_be_cited', foreign_quote)

        def changed():
            original = helper_file.read_bytes()
            helper_file.write_bytes(original + b'\n// changed after prepare\n')
            try:
                self.helper('validate', '--bundle', bundle_path, '--response', response_path, '--output', output_path, expected=2)
                require(output_path.read_bytes() == self.accepted, 'changed source replaced accepted output')
            finally:
                helper_file.write_bytes(original)
        self.case('changed_cross_package_helper_invalidates_review', changed)

        def budget():
            out = self.temporary / 'budget-bundle'
            self.helper('prepare', '--report', scan_path, '--project', self.project, '--output', out, '--max-context-chars', '600')
            bundle = json.loads((out / 'bundle.json').read_text(encoding='utf-8'))
            require(all(f['semantic_context']['status'] == 'unavailable' and not f['semantic_context']['attachments']
                        for f in bundle['findings']), 'small budget fabricated complete helper evidence')
        self.case('context_budget_omits_whole_attachments_explicitly', budget)
        self.record['review_script_sha256'] = hashlib.sha256(self.args.review_script.read_bytes()).hexdigest()
        self.record['status'] = 'passed'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--analyzer', type=Path, default=os.environ.get('ANALYZER', ROOT / 'dist/extracted/moon-audit'))
    parser.add_argument('--toolchain', type=Path, default=os.environ.get('PROJECT_TOOLCHAIN', '/tmp/moon-audit-upgrade-20260922/toolchain'))
    parser.add_argument('--review-script', type=Path, default=os.environ.get('LLM_REVIEW_SCRIPT', ROOT / 'scripts/llm_review.py'))
    parser.add_argument('--corpus', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--work-dir', type=Path, help='keep isolated fixture and bundle for a separate optional API review')
    args = parser.parse_args()
    record = None
    try:
        if args.work_dir:
            args.work_dir.mkdir(parents=True)
            scope = contextlib.nullcontext(str(args.work_dir))
        else:
            scope = tempfile.TemporaryDirectory(prefix='moon-audit-llm-context-')
        with scope as directory:
            suite = LlmContext(args, Path(directory).resolve())
            record = suite.record
            record['schema'] = 'moon-audit.llm-context-acceptance.v1'
            suite.run()
    except Exception as error:
        record = record or {}
        record.update(status='failed', error=str(error))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': record['status'], 'cases': len(record.get('cases', [])), 'error': record.get('error')}))
    return 0 if record['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
