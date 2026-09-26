#!/usr/bin/env python3
"""Cross-package source lowering acceptance with frozen real mocket dependencies."""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
import tempfile

from native_semantic_test import Acceptance, ROOT, SEMANTIC_ID, require, canonical

BRIDGE = '''pub fn relay(value : String) -> String { @leaf.relay(value) }
pub fn safe(value : String) -> String { @mocket.escape_html(@leaf.relay(value)) }
pub fn escape_html(value : String) -> String { value }
pub fn second(first : String, second : String) -> String { @leaf.first(second, first) }
'''
LEAF = '''pub fn relay(value : String) -> String { "<p>" + value + "</p>" }
pub fn first(first : String, _second : String) -> String { first }
'''
EXPRESSIONS = {
    '/raw': '@helpers.relay(value)',
    '/safe': '@helpers.safe(value)',
    '/fake': '@helpers.escape_html(value)',
    '/second-value': '@helpers.second("fixed", value)',
    '/second-fixed': '@helpers.second(value, "fixed")',
}


def routes(expressions):
    return 'pub fn install(app : @mocket.Mocket) -> Unit {\n' + ''.join(
        f'  app.get("{path}", event => {{\n'
        '    let value = event.req.query().get("q").unwrap_or("")\n'
        f'    @mocket.html({expr})\n  }})\n' for path, expr in expressions.items()) + '}\n'


class CrossPackage(Acceptance):
    def package(self, name, imports, source):
        directory = self.project / name
        directory.mkdir(exist_ok=True)
        (directory / 'moon.pkg').write_text(imports, encoding='utf-8')
        (directory / 'helpers.mbt').write_text(source, encoding='utf-8')
        return directory

    def route_paths(self, report):
        return {r['route']: bool(r['result']['source_paths']) for r in report['semantic_analysis']['routes']}

    def run(self):
        (self.project / 'moon.pkg').write_text('import { "oboard/mocket", "acceptance/semantic/bridge" @helpers }\nsupported_targets = "native"\n')
        self.package('bridge', 'import { "oboard/mocket", "acceptance/semantic/leaf" }\n', BRIDGE)
        self.package('leaf', '', LEAF)
        self.source_file.write_text(routes(EXPRESSIONS), encoding='utf-8')
        expected = {p: p in ('/raw', '/fake', '/second-value') for p in EXPRESSIONS}

        def positive():
            code, report, _ = self.cli('cross_package_cold', measure=True)
            findings = self.complete(code, report)
            require(self.route_paths(report) == expected, 'parameter/return or sanitizer identity differs')
            require(len(findings) == 3, 'expected three query-to-HTML paths')
            definitions = {b['definition'].replace('\\', '/') for b in report['semantic_analysis']['bindings']}
            require(str(self.project / 'bridge/helpers.mbt').replace('\\', '/') in definitions, 'missing bridge binding')
            require(str(self.project / 'leaf/helpers.mbt').replace('\\', '/') in definitions, 'missing leaf binding')
            for relative, declaration in [('bridge/helpers.mbt', '1:8-1:13'), ('leaf/helpers.mbt', '1:8-1:13')]:
                require(any(b['definition'].replace('\\', '/').endswith('/' + relative) and b['range'] == declaration
                            for b in report['semantic_analysis']['bindings']), 'declaration identity/range mismatch: ' + relative)
            require(any('bridge/helpers.mbt:' in step for f in findings for step in f['dataflow']), 'trace lacks cross-package call')
            self.positive = report
            code, hot, _ = self.cli('cross_package_hot', measure=True)
            self.complete(code, hot)
            require(canonical(report, [self.project]) == canonical(hot, [self.project]), 'cold/hot changed output')
        self.case('aliases_two_hops_same_names_and_parameter_order', positive)

        def renamed():
            config = self.project / 'moon.pkg'
            config.write_text(config.read_text().replace('@helpers', '@renamed'))
            self.source_file.write_text(routes(EXPRESSIONS).replace('@helpers.', '@renamed.'))
            try:
                code, report, _ = self.cli('renamed_import')
                self.complete(code, report)
                require(self.route_paths(report) == expected, 'alias rename changed dataflow')
            finally:
                config.write_text(config.read_text().replace('@renamed', '@helpers'))
                self.source_file.write_text(routes(EXPRESSIONS))
        self.case('import_alias_rename_preserves_targets', renamed)

        def unrelated():
            self.package('unrelated', '', 'fn identity(value : String) -> String { value }\n' +
                         '\n'.join(f'pub fn unused_{n}() -> String {{ identity("fixed") }}' for n in range(300)))
            code, report, _ = self.cli('unrelated_package_300_calls', measure=True)
            self.complete(code, report)
            require(self.route_paths(report) == expected, 'unrelated package changed paths')
            require(report['semantic_analysis']['binding_queries'] == self.positive['semantic_analysis']['binding_queries'],
                    'unrelated calls consumed reachable binding budget')
            require(not any('/unrelated/' in b['query'].replace('\\', '/') for b in report['semantic_analysis']['bindings']),
                    'unreachable calls were bound')
        self.case('unrelated_package_does_not_consume_binding_budget', unrelated)

        def broken():
            target = self.project / 'bridge/helpers.mbt'
            target.write_text(BRIDGE + '''pub fn broken(value : String) -> String {
  return "constant"
  if value == "x" { "x" } else { value }
}
pub fn broken_wrapper(value : String) -> String { broken(value) }
''')
            self.source_file.write_text(routes({'/broken-first': '@helpers.broken_wrapper(value)',
                                                '/broken-second': '@helpers.broken(value)', '/known': '@helpers.relay(value)'}))
            try:
                code, report, _ = self.cli('shared_failed_helper')
                semantic = self.incomplete(code, report)
                rejected = [r for r in semantic['routes'] if r.get('status') == 'incomplete']
                require(len(rejected) == 2 and all('unsupported_semantics' in r['reason'] for r in rejected),
                        'failed helper was reused as complete or lost original failure')
                require(len([f for f in report['findings'] if f['rule_id'] == SEMANTIC_ID]) == 1, 'known route was lost')
                require(not any(f['id'].endswith(('bridge/helpers.mbt:5:8', 'bridge/helpers.mbt:9:8')) for f in semantic['functions']),
                        'failed helper remained in exported IR')
            finally:
                target.write_text(BRIDGE)
        self.case('failed_helper_is_not_reused_by_later_routes', broken)

        def external():
            self.source_file.write_text(routes({'/external': '@mocket.url_encode(value)'}))
            code, report, _ = self.cli('unmodeled_external_package')
            semantic = self.incomplete(code, report)
            require(any('unmodeled_external_call' in r.get('reason', '') for r in semantic['routes']),
                    'external source silently modeled')
        self.case('unmodeled_external_dependency_remains_incomplete', external)
        def other_operator():
            self.source_file.write_text(routes({'/unknown-operator': 'value'}).replace(
                '    @mocket.html(value)', '    let _same = value == "fixed"\n    @mocket.html(value)'))
            code, report, _ = self.cli('string_equality_is_not_concatenation')
            semantic = self.incomplete(code, report)
            require(any('unmodeled_external_call' in r.get('reason', '') for r in semantic['routes']),
                    'unmodeled operator was accepted as concatenation')
        self.case('unmodeled_operator_is_not_string_concatenation', other_operator)
        def numeric_escape():
            self.source_file.write_text(routes({'/escaped-markup': r'"\u003cscript>" + @mocket.escape_html(value)'}))
            code, report, _ = self.cli('numeric_escape_cannot_hide_markup')
            semantic = self.incomplete(code, report)
            require(any('unsupported_literal_escape' in r.get('reason', '') for r in semantic['routes']),
                    'numeric escape concealed HTML delimiters')
        self.case('unreviewed_escape_cannot_hide_markup', numeric_escape)
        self.case('unchanged_luna_production_package', self.real_package)

        def reached_budget():
            self.source_file.write_text('pub fn install(app : @mocket.Mocket) -> Unit {\n  app.get("/budget", event => {\n'
                '    let value = event.req.query().get("q").unwrap_or("")\n' +
                ''.join(f'    let _v{n} = @helpers.relay(value)\n' for n in range(260)) +
                '    @mocket.html(value)\n  })\n}\n')
            code, report, _ = self.cli('reached_binding_budget', extra=('--timeout-seconds', '120'))
            semantic = self.incomplete(code, report)
            require(report['project_verification']['status'] == 'compiler_verified',
                    'resource limit case did not verify the input project')
            # Windows can reach the worker's 60-second ceiling before 256 IDE
            # subprocesses finish. Keep production limits and record which won.
            if os.name == 'nt' and semantic == {
                    'status': 'incomplete', 'reason': 'semantic_worker_failed_or_budget: TimeoutError'}:
                require(not any(f['rule_id'] == SEMANTIC_ID for f in report['findings']),
                        'worker timeout fabricated a completed semantic path')
                self.record['reached_body_limit'] = {'kind': 'worker_timeout', 'query_limit_observed': False}
                return
            require(semantic.get('binding_queries') == 256, 'actual query budget was not bounded')
            require(any('binding_budget_exhausted' in r.get('reason', '') for r in semantic['routes']),
                    'reached-body budget exhaustion was not disclosed')
            self.record['reached_body_limit'] = {'kind': 'binding_queries', 'query_limit_observed': True,
                                                'binding_queries': 256}
        self.case('reached_body_limits_remain_conservative', reached_budget)
        self.record['status'] = 'passed'


    def real_package(self):
        pin = json.loads((ROOT / 'experiments/cross_package/source-pin.json').read_text())
        original = self.args.luna_source.resolve() / pin['package']
        hashes = lambda directory: {f.name: hashlib.sha256(f.read_bytes()).hexdigest()
                                    for f in directory.iterdir() if f.is_file()}
        require(hashes(original) == pin['files'], 'real package source differs')
        project = self.temporary / 'real-luna-consumer'
        self.prepare(project)
        (project / 'moon.mod').write_text('name = "mizchi/sol"\nsource = "src"\nimport { "oboard/mocket@0.9.1" }\npreferred_target = "native"\n')
        (project / 'moon.pkg').unlink()
        source = project / 'src'
        source.mkdir()
        (source / 'moon.pkg').write_text('import { "oboard/mocket", "mizchi/sol/internal/page_shell" @shell }\n')
        copied = source / 'internal/page_shell'
        shutil.copytree(original, copied)
        input_file = source / 'probe.mbt'
        input_file.write_text(routes({'/raw': '@shell.app_container(value)',
                                     '/safe': '@shell.app_container(@mocket.escape_html(value))',
                                     '/constant': '@shell.render_streaming_footer()'}))
        code, report, _ = self.cli('real_luna_package', project=project, measure=True)
        semantic = self.incomplete(code, report, syntax=False)
        require(self.route_paths(report) == {'/raw': True, '/safe': True, '/constant': False}, 'real package partial propagation differs')
        require(all(r['result']['reason'] == 'unsupported_html_context' for r in semantic['routes']),
                'attributed wrapper must retain unknown context')
        findings = [f for f in report['findings'] if f['rule_id'] == SEMANTIC_ID]
        require(len(findings) == 2 and all(f['evidence'] == 'partial_dataflow' for f in findings),
                'real package paths must remain partial, including encoded input in unknown context')
        require(any(op == ['Literal', op[1], '<div id="app">']
                    for function in semantic['functions'] for op in function['operations'] if op[0] == 'Literal'),
                'escaped source literal was not decoded')
        require(any(b['definition'].replace('\\', '/').endswith('/builtin/intrinsics.mbt') and b['range']=='1887:33-1887:36'
                    for b in report['semantic_analysis']['bindings']), 'String addition identity missing')
        # Execute the unchanged pure package in an independent package test.
        (source / 'runtime_wbtest.mbt').write_text('test {\n  assert_eq(@shell.app_container("<b>"), "<div id=\\"app\\"><b></div>")\n  assert_eq(@shell.app_container(@mocket.escape_html("<b>")), "<div id=\\"app\\">&lt;b&gt;</div>")\n}\n')
        env = os.environ | {'MOON_HOME': str(self.home), 'PATH': str(self.home/'bin')+os.pathsep+os.environ.get('PATH','')}
        moon = self.home/'bin'/('moon.exe' if os.name=='nt' else 'moon')
        runtime = subprocess.run([str(moon),'test','--frozen','--target','native'],cwd=project,env=env,text=True,capture_output=True,timeout=120)
        self.record['real_package_runtime'] = {'exit_code': runtime.returncode, 'stdout': runtime.stdout, 'stderr': runtime.stderr}
        require(runtime.returncode == 0, 'real package runtime failed: '+runtime.stderr)
        input_file.write_text(routes({'/unknown': '@shell.escape_html_text(value)'}))
        code, report, _ = self.cli('real_luna_unknown_sanitizer', project=project)
        require(code == 2 and report['project_verification']['status']=='compiler_verified', 'real unsupported helper was accepted')
        require(not [f for f in report['findings'] if f['rule_id']==SEMANTIC_ID], 'unknown sanitizer fabricated a verified path')
        require(any('unsupported_semantics' in r.get('reason','') for r in report['semantic_analysis']['routes']), 'unknown helper reason missing')
        require(hashes(original) == pin['files'] and hashes(copied) == pin['files'], 'original/copied package mutated')
        self.record['real_package'] = pin


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--analyzer', type=Path, default=os.environ.get('ANALYZER', ROOT / 'dist/extracted/moon-audit'))
    p.add_argument('--toolchain', type=Path, default=os.environ.get('PROJECT_TOOLCHAIN', '/tmp/moon-audit-upgrade-20260922/toolchain'))
    p.add_argument('--corpus', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--luna-source', type=Path, required=True)
    args = p.parse_args()
    record = None
    try:
        with tempfile.TemporaryDirectory(prefix='moon-audit-cross-package-') as directory:
            # Match compiler canonical paths (macOS /var -> /private/var).
            suite = CrossPackage(args, Path(directory).resolve())
            record = suite.record
            record['schema'] = 'moon-audit.cross-package-acceptance.v1'
            suite.run()
    except Exception as error:
        record = record or {}
        record.update(status='failed', error=str(error))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({'status': record['status'], 'cases': len(record.get('cases', [])), 'error': record.get('error')}))
    return 0 if record['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
