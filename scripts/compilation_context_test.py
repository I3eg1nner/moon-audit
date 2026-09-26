#!/usr/bin/env python3
"""Acceptance for compiler roles, conditional syntax and planned binding queries."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import tempfile

from native_semantic_test import Acceptance, ROOT, SEMANTIC_ID, require


def route(path, expression='value'):
    return (f'  app.get("{path}", event => {{\n'
            '    let value = event.req.query().get("q").unwrap_or("")\n'
            f'    @mocket.html({expression})\n  }})\n')


def install(path='/production', expression='value'):
    return 'pub fn install(app : @mocket.Mocket) -> Unit {\n' + route(path, expression) + '}\n'


def test_route(path):
    return 'test {\n  let app = @mocket.new()\n' + route(path) + '}\n'


class CompilationContext(Acceptance):
    def verified(self, report):
        require(isinstance(report, dict) and report['project_verification']['status'] == 'compiler_verified',
                'fixture was not accepted by the actual compiler; inspect recorded run')

    def mappings(self, report):
        verification = report['project_verification']
        require(verification['compilation_unit_schema'] == 'moon-audit.compilation-units.v1',
                'compiler unit schema missing')
        semantic = report['semantic_analysis']
        declared = {u['id']: u for u in verification['compilation_units']}
        selected = {u['id']: u for u in semantic['compilation_units']}
        require(selected and all(u['role'] == 'production' and u['target'] == 'native'
                                 for u in selected.values()), 'semantic units include a test role or wrong target')
        require(all(declared.get(key) == unit for key, unit in selected.items()),
                'semantic units differ from compiler verification')
        sources = {entry['source']: entry['unit'] for entry in semantic['source_units']}
        require(len(sources) == len(semantic['source_units']), 'source has more than one owner')
        for path, key in sources.items():
            unit = selected[key]
            require({'path': path, 'mode': 'source'} in unit['inputs'], 'source was not a real unit input')
            require(unit['module_root'] == str(self.project).replace('\\', '/'), 'module root differs')
            require(unit['module_name'] == 'acceptance/semantic', 'module name differs')
            require(path.startswith(unit['package_root'] + '/'), 'source is outside its package')
            require(not path.endswith(('_test.mbt', '_wbtest.mbt')), 'test input entered production source map')
        functions = {entry['function']: entry for entry in semantic['function_units']}
        require(len(functions) == len(semantic['function_units']), 'function has more than one owner')
        require(set(functions) == {function['id'] for function in semantic['functions']},
                'exported IR does not have a complete function-to-unit map')
        for entry in functions.values():
            require(sources.get(entry['source']) == entry['unit'], 'function/source ownership differs')
        return semantic

    def run(self):
        def inline_only():
            self.source_file.write_text(test_route('/inline-only'), encoding='utf-8')
            code, report, _ = self.cli('inline_test_only')
            self.verified(report)
            semantic = self.incomplete(code, report)
            require(semantic['binding_queries'] == 0 and not semantic['bindings'], 'TopTest issued production bindings')
            require(not semantic['routes'] and not semantic['functions'], 'TopTest became a production route')
            require(not [f for f in report['findings'] if f['rule_id'] == SEMANTIC_ID], 'test-only flow produced a semantic finding')
            self.mappings(report)
        self.case('inline_test_is_not_a_production_entry', inline_only)

        def mixed_roles():
            self.source_file.write_text(install() + test_route('/inline'), encoding='utf-8')
            whitebox = self.project / 'roles_wbtest.mbt'
            blackbox = self.project / 'roles_test.mbt'
            whitebox.write_text(test_route('/whitebox'), encoding='utf-8')
            blackbox.write_text(test_route('/blackbox'), encoding='utf-8')
            try:
                code, report, _ = self.cli('production_with_all_test_roles')
                self.verified(report)
                findings = self.complete(code, report)
                semantic = self.mappings(report)
                require([r['route'] for r in semantic['routes']] == ['/production'], 'test route entered production analysis')
                require(len(findings) == 1, 'expected exactly one production dataflow finding')
                roles = {u['role'] for u in report['project_verification']['compilation_units']}
                require(roles == {'production', 'whitebox_test', 'blackbox_test'}, 'actual compiler did not produce all three roles')
                test_inputs = {i['path'] for u in report['project_verification']['compilation_units']
                               if u['role'] != 'production' for i in u['inputs']}
                require(str(whitebox).replace('\\', '/') in test_inputs and str(blackbox).replace('\\', '/') in test_inputs,
                        'test fixture inputs missing from compiler evidence')
                require(all('/roles_' not in binding['query'].replace('\\', '/') for binding in semantic['bindings']),
                        'binding query targeted a test file')
            finally:
                whitebox.unlink()
                blackbox.unlink()
        self.case('compiler_roles_and_function_identity_remain_distinct', mixed_roles)

        def conditional(attribute, name):
            self.source_file.write_text(attribute + '\n' + install('/conditional'), encoding='utf-8')
            code, report, _ = self.cli(name)
            self.verified(report)
            semantic = self.incomplete(code, report)
            require(semantic['binding_queries'] == 0 and not semantic['bindings'], 'excluded cfg entry queried unavailable compiler bindings')
            require(len(semantic['routes']) == 1 and semantic['routes'][0].get('status') == 'incomplete',
                    'conditional entry disappeared or became complete')
            require('unsupported_conditional_compilation' in semantic['routes'][0].get('reason', ''),
                    'conditional entry lacks explicit unsupported reason')
            require(not semantic['functions'], 'conditional entry exported IR')
            self.mappings(report)
        self.case('cfg_false_is_explicitly_unsupported', lambda: conditional('#cfg(false)', 'cfg_false'))
        self.case('cfg_other_target_is_explicitly_unsupported', lambda: conditional('#cfg(target="js")', 'cfg_js'))

        def conditional_helper():
            self.source_file.write_text(
                '#cfg(target="native")\n'
                'fn conditional(value : String) -> String { value }\n' +
                install('/conditional-helper', 'conditional(value)'), encoding='utf-8')
            code, report, _ = self.cli('reached_conditional_helper')
            self.verified(report)
            semantic = self.incomplete(code, report)
            require(len(semantic['routes']) == 1 and
                    'unsupported_conditional_compilation' in semantic['routes'][0].get('reason', ''),
                    'reached cfg helper was treated as unconditional')
            require(semantic['binding_queries'] > 1, 'helper failure did not exercise official call binding')
            require(not semantic['functions'], 'conditional helper left partial IR behind')
            self.mappings(report)
        self.case('reached_conditional_helper_is_explicitly_unsupported', conditional_helper)

        def unsupported_body():
            self.source_file.write_text(
                'fn relay(value : String) -> String { value }\n'
                'pub fn install(app : @mocket.Mocket) -> Unit {\n'
                '  app.get("/unsupported", event => {\n'
                '    if true {\n'
                '      let value = event.req.query().get("q").unwrap_or("")\n' +
                ''.join(f'      let _v{n} = relay(value)\n' for n in range(260)) +
                '      @mocket.html(value)\n'
                '    } else { @mocket.html("fixed") }\n'
                '  })\n}\n', encoding='utf-8')
            code, report, _ = self.cli('unsupported_body_260_calls', measure=True)
            self.verified(report)
            semantic = self.incomplete(code, report)
            require(semantic['binding_queries'] == 1 and len(semantic['bindings']) == 1,
                    'structurally unsupported body consumed speculative binding queries')
            require(len(semantic['routes']) == 1 and 'unsupported_semantics' in semantic['routes'][0].get('reason', ''),
                    'structural failure was replaced by a query budget failure')
            require(not semantic['functions'], 'failed structural plan exported IR')
            self.record['unsupported_body_query_count'] = semantic['binding_queries']
            self.mappings(report)
        self.case('unsupported_body_does_not_query_260_calls', unsupported_body)

        def failed_resolution():
            directory = self.project / 'bridge'
            directory.mkdir()
            (directory / 'moon.pkg').write_text('import { "oboard/mocket" }\n', encoding='utf-8')
            (directory / 'helpers.mbt').write_text(
                'pub fn broken(value : String) -> String { @mocket.url_encode(value) }\n'
                'pub fn wrapper(value : String) -> String { broken(value) }\n'
                'pub fn relay(value : String) -> String { value }\n', encoding='utf-8')
            (self.project / 'moon.pkg').write_text(
                'import { "oboard/mocket", "acceptance/semantic/bridge" }\n'
                'supported_targets = "native"\n', encoding='utf-8')
            self.source_file.write_text('pub fn install(app : @mocket.Mocket) -> Unit {\n' +
                route('/broken-first', '@bridge.wrapper(value)') +
                route('/broken-second', '@bridge.broken(value)') +
                route('/known', '@bridge.relay(value)') + '}\n', encoding='utf-8')
            code, report, _ = self.cli('shared_helper_resolution_failure')
            self.verified(report)
            semantic = self.incomplete(code, report)
            rejected = [r for r in semantic['routes'] if r.get('status') == 'incomplete']
            require(len(rejected) == 2 and all('unmodeled_external_call' in r.get('reason', '') for r in rejected),
                    'failed resolved helper was reused as complete or lost its failure reason')
            require(len([f for f in report['findings'] if f['rule_id'] == SEMANTIC_ID]) == 1,
                    'independent known route was lost')
            require(any(r.get('route') == '/known' and r.get('result', {}).get('status') == 'complete'
                        for r in semantic['routes']), 'known route failed to complete')
            require(not any(f['id'].endswith(('bridge/helpers.mbt:1:8', 'bridge/helpers.mbt:2:8'))
                            for f in semantic['functions']), 'failed helper or wrapper remained in exported IR')
            require(any(f['id'].endswith('bridge/helpers.mbt:3:8') for f in semantic['functions']),
                    'known cross-package helper absent')
            self.mappings(report)
        self.case('resolution_failure_rolls_back_transitive_helpers', failed_resolution)
        self.record['status'] = 'passed'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--analyzer', type=Path, default=os.environ.get('ANALYZER', ROOT / 'dist/extracted/moon-audit'))
    parser.add_argument('--toolchain', type=Path, default=os.environ.get('PROJECT_TOOLCHAIN', '/tmp/moon-audit-upgrade-20260922/toolchain'))
    parser.add_argument('--corpus', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    record = None
    try:
        with tempfile.TemporaryDirectory(prefix='moon-audit-compilation-context-') as directory:
            suite = CompilationContext(args, Path(directory).resolve())
            record = suite.record
            record['schema'] = 'moon-audit.compilation-context-acceptance.v1'
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
