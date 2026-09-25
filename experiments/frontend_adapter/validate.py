"""Reproduce the bounded compiler-backed witnesses and their AST contract ledger."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import time

from adapter import Reject, analyze

HERE = Path(__file__).resolve().parent
CASES = {
    'read_after_write_alias': [True, True],
    'clean_last_alias': [False, False],
    'dirty_last_alias': [True, False],
    'read_after_write_distinct': [True, False, False, False],
    'shadow': [False, True],
    'string_direct_positive': [True],
    'string_direct_safe': [False, False],
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--analyzer-moon-wrapper', type=Path, help='wrapper for the analyzer build toolchain')
    parser.add_argument('--project-moon-wrapper', type=Path, help='wrapper for the target project toolchain')
    parser.add_argument('--baseline', type=Path, help='previous verified AST contract ledger')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    rows = []
    passed = True
    analyzer_moon = [str(args.analyzer_moon_wrapper), 'moon'] if args.analyzer_moon_wrapper else ['moon']
    project_moon = [str(args.project_moon_wrapper), 'moon'] if args.project_moon_wrapper else analyzer_moon
    for label, expected in CASES.items():
        source = (HERE / 'fixtures' / f'{label}.mbt.txt').read_text()
        started = time.monotonic()
        try:
            report = analyze(source, analyzer_moon, project_moon=project_moon, fixture=label)
            sink_lines = [n for n, text in enumerate(source.splitlines(), 1)
                          if text.strip().startswith('sink(')]
            actual = [bool(report['result']['findings'].get(f'sink@{line}:3')) for line in sink_lines]
            ok = actual == expected and report['status'] == 'fixed_point'
            row = {'fixture': label, 'status': report['status'], 'expected': expected,
                   'observed': actual, 'passed': ok, 'source_sha256': report['source_sha256'],
                   'program_digest': report['result']['program_digest'],
                   'ast_schema': report['ast_schema'], 'lookups': report['lookups'],
                   'solver_stats': report['result']['stats']}
            analyzer_version = report['analyzer_toolchain']
            project_version = report['project_toolchain']
            passed &= ok
        except Reject as error:
            row = {'fixture': label, 'status': error.status, 'detail': error.detail, 'passed': False}
            passed = False
        row['seconds_including_frontend'] = round(time.monotonic() - started, 4)
        rows.append(row)
    differences = []
    if args.baseline:
        previous = json.loads(args.baseline.read_text())
        old_rows = {row['fixture']: row for row in previous['rows']}
        for row in rows:
            old = old_rows.get(row['fixture'])
            for field in ('status', 'observed', 'ast_schema'):
                if old is None or old.get(field) != row.get(field):
                    differences.append({'fixture': row['fixture'], 'field': field})
        passed &= not differences
    output = {'schema': 'moon-audit.frontend-adapter-validation.v1',
              'analyzer_toolchain': analyzer_version if 'analyzer_version' in locals() else None,
              'project_toolchain': project_version if 'project_version' in locals() else None,
              'parser_package': 'moonbitlang/parser@0.4.0',
              'backend': 'native', 'supported_fixtures': len(CASES),
              'passed': passed, 'baseline_differences': differences, 'production_migrated': False,
              'generic_dispatch_supported': False, 'exception_supported': False,
              'recursive_source_supported': False,
              'exporter_sha256': hashlib.sha256((HERE.parents[1] / 'src/frontend_export/main.mbt').read_bytes()).hexdigest(),
              'adapter_sha256': hashlib.sha256((HERE / 'adapter.py').read_bytes()).hexdigest(),
              'rows': rows}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, ensure_ascii=False, indent=2) + '\n')
    print(f'{sum(row["passed"] for row in rows)}/{len(rows)} source witnesses passed; contract passed: {passed}; report: {args.output}')
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
