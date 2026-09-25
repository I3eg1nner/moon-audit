#!/usr/bin/env python3
"""Validate the restricted native source→IR chain against frozen real mocket APIs."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
from validate_mocket import HERE, IGNORED, fingerprint

EXPECTED = {
    '/raw': ('complete', 1, ''), '/safe': ('complete', 0, ''),
    '/discarded': ('complete', 0, ''), '/overwritten': ('complete', 0, ''),
    '/plain': ('complete', 0, ''), '/script': ('incomplete', 1, 'unsupported_html_context'),
    '/homonym': ('complete', 1, ''), '/unknown': ('incomplete', 0, 'unsupported_semantics'),
    '/recursive': ('incomplete', 0, 'incomplete_budget'),
    '/doubling': ('incomplete', 0, 'incomplete_budget'),
}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--mocket', required=True, type=Path)
    p.add_argument('--toolchain', required=True, type=Path)
    p.add_argument('--probe', type=Path, default=HERE.parents[1] / '_build/native/debug/build/src/semantic_probe/semantic_probe.exe')
    p.add_argument('--output', required=True, type=Path)
    args = p.parse_args()
    source, probe, home = args.mocket.resolve(), args.probe.resolve(), args.toolchain.resolve()
    runtime = json.loads((HERE / 'mocket-runtime-2026-09-25.json').read_text())
    assert fingerprint(source, exclude_dependencies=True)['sha256'] == runtime['source_fingerprint']['sha256']
    for name, expected in runtime['dependency_fingerprints'].items():
        assert fingerprint(source / '.mooncakes' / name)['sha256'] == expected['sha256'], name
    fixture = (HERE / 'consumer_probe.mbt.txt').read_text()
    route_lines = {str(i): line.split('"')[1] for i, line in enumerate(fixture.splitlines(), 1) if 'app.get("/' in line}
    record = {'schema': 'moon-audit.native-security-chain-validation.v1',
              'production_ready': False, 'reviewed_commit': runtime['reviewed_corpus_commit'],
              'fixture_sha256': hashlib.sha256(fixture.encode()).hexdigest(),
              'source_fingerprint': runtime['source_fingerprint']['sha256'],
              'dependency_fingerprints': {k: v['sha256'] for k, v in runtime['dependency_fingerprints'].items()},
              'cases': [], 'runs': [], 'limits': [
                  'Only pinned mocket .get literal-path inline callback declarations are covered.',
                  'Registration execution, middleware and browser exploitability are not proven.',
                  'Whole mocket checkout fails newest compiler in examples/benchmarks; this is a consumer project.',
                  'No production semantic mode, branch/heap analysis or historical-language compatibility claim.',
              ]}
    with tempfile.TemporaryDirectory(prefix='moon-audit-native-chain-') as temp:
        work = Path(temp) / 'consumer'
        work.mkdir()
        shutil.copytree(source / '.mooncakes', work / '.mooncakes', ignore=shutil.ignore_patterns(*IGNORED))
        lib = work / '.mooncakes/oboard/mocket'
        shutil.copytree(source, lib, ignore=shutil.ignore_patterns(*IGNORED, '.mooncakes'))
        (work / 'moon.mod').write_text('name = "audit/consumer"\nimport { "oboard/mocket@0.9.1" }\npreferred_target = "native"\n')
        shutil.copyfile(HERE / 'binding_fixture/moon.pkg.txt', work / 'moon.pkg')
        (work / 'probe.mbt').write_text(fixture)

        def run(name):
            started = time.monotonic()
            command = [str(probe), str(work), str(home)]
            result = subprocess.run(command, capture_output=True, text=True, timeout=240)
            report = json.loads(result.stdout)
            record['runs'].append({'name': name, 'command': command, 'seconds': round(time.monotonic()-started, 3),
                                   'exit_code': result.returncode, 'stderr': result.stderr, 'report': report})
            return result.returncode, report

        code, report = run('source_matrix')
        assert code == 2 and report['status'] == 'incomplete', report
        assert not report['errors'], report['errors']
        assert len(report['routes']) == len(EXPECTED)
        for route in report['routes']:
            name = route.get('route') or route_lines[route['entry'].rsplit(':', 2)[1]]
            result = route.get('result', route)
            status, count, reason = EXPECTED[name]
            actual_count = len(result.get('source_paths', []))
            passed = result['status'] == status and actual_count == count and reason in result.get('reason', '')
            record['cases'].append({'name': name, 'passed': passed, 'status': result['status'],
                                    'path_count': actual_count, 'reason': result.get('reason', '')})
            assert passed, (name, result)
        for name, target in [('library_changed', lib / 'README.md'),
                             ('dependency_changed', work / '.mooncakes/oboard/mimetype/README.md')]:
            original = target.read_bytes()
            target.write_bytes(original + b'\nreview mutation\n')
            try:
                code, changed = run(name)
                passed = code == 2 and changed['status'] == 'incomplete' and bool(changed['errors']) and not changed['routes']
                record['cases'].append({'name': name, 'passed': passed})
                assert passed, changed
            finally:
                target.write_bytes(original)
        (work / 'probe.mbt').write_text('pub fn install(app : @mocket.Mocket) -> Unit {\n  @mocket.Mocket::get(app, "/explicit", _event => @mocket.html("constant"))\n}\n')
        code, explicit = run('unsupported_registration_shape')
        passed = code == 2 and explicit['status'] == 'incomplete' and explicit['coverage_status'] == 'restricted_experiment'
        record['cases'].append({'name': 'unsupported_registration_shape', 'passed': passed})
        assert passed, explicit
    record['status'] = 'passed'
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, indent=2, ensure_ascii=False) + '\n')
    print(json.dumps({'status': record['status'], 'cases': len(record['cases']), 'elapsed_seconds': sum(x['seconds'] for x in record['runs'])}))

if __name__ == '__main__':
    main()
