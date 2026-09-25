#!/usr/bin/env python3
"""Verify native file selection against real target compiler/backends."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
SOURCE = 'pub fn escape(s : String) -> String { s.replace(old="<", new="&lt;") }\n'

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scanner', type=Path, required=True)
    parser.add_argument('--toolchain', action='append', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    records = []
    with tempfile.TemporaryDirectory(prefix='moon-audit-native-matrix-') as temporary:
        project = Path(temporary)
        (project / 'moon.mod.json').write_text('{"name":"fixture/native_matrix"}', encoding='utf-8')
        (project / 'moon.pkg.json').write_text(json.dumps({'targets': {'js_only.mbt': ['js'], 'native_only.mbt': ['native']}}), encoding='utf-8')
        (project / 'common.mbt').write_text('pub fn common() -> Int { 1 }\n', encoding='utf-8')
        (project / 'js_only.mbt').write_text(SOURCE, encoding='utf-8')
        (project / 'native_only.mbt').write_text('pub fn native_only() -> Int { 2 }\n', encoding='utf-8')
        for home in args.toolchain:
            for target in ['native', 'js', 'wasm', 'wasm-gc']:
                command = [str(args.scanner.resolve()), '--verify-project', '--project-toolchain', str(home.resolve()), '--target', target, '--format', 'json', str(project)]
                start = time.monotonic()
                run = subprocess.run(command, capture_output=True, encoding='utf-8', timeout=320)
                report = json.loads(run.stdout)
                verification = report['project_verification']
                expected = {'common.mbt'} | ({'native_only.mbt'} if target == 'native' else {'js_only.mbt'} if target == 'js' else set())
                actual = {Path(item).name for item in verification['compiler_files']}
                parsed = {Path(item['path']).name for item in report['analysis_manifest']['files'] if item['status'] == 'parsed'}
                findings = {Path(item['file']).name for item in report['findings']}
                passed = run.returncode == 0 and verification['status'] == 'compiler_verified' and expected == actual == parsed and findings == ({'js_only.mbt'} if target == 'js' else set())
                records.append({'toolchain': verification['toolchain'], 'target': target, 'seconds': round(time.monotonic()-start, 4), 'passed': passed, 'exit_code': run.returncode, 'compiler_files': sorted(actual), 'parsed_files': sorted(parsed), 'findings': sorted(findings), 'errors': report['errors']})
                print(home.name, target, 'PASS' if passed else 'FAIL', flush=True)
    data = {'schema': 'moon-audit.native-version-matrix.v1', 'scanner_sha256': hashlib.sha256(args.scanner.read_bytes()).hexdigest(), 'scope': 'portable syntax, legacy package format and target-selected files; not all rules or historical syntax', 'cases': records}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(data, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    return 0 if all(item['passed'] for item in records) else 1

if __name__ == '__main__':
    raise SystemExit(main())
