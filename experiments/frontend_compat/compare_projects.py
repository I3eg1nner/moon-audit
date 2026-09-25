#!/usr/bin/env python3
"""Compare pinned real sources without executing or rewriting target programs."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from popular_projects import ledger, scan, save


def run_export(binary, source, compat=False):
    result = subprocess.run([str(binary), *(['--compat'] if compat else []), str(source)],
                            text=True, encoding='utf-8', capture_output=True, timeout=30)
    return result.returncode, json.loads(result.stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('before', 'after', 'exporter', 'source-root', 'output-dir'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--project', action='append', help='Project name from the fixed manifest; repeatable')
    args = parser.parse_args()
    output = args.output_dir.resolve(); output.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((ROOT / 'experiments/popular_projects/manifest-2026-09-25.json').read_text())
    projects = args.project or ['moonbitlang/quickcheck', 'mizchi/bitflow']
    entries = [x for x in manifest['entries'] if x['project'] in projects]
    if not entries:
        parser.error('no matching fixed project')
    rules = json.loads(subprocess.check_output([str(args.after.resolve()), '--format', 'json', 'list-rules'], text=True))
    flags = [word for rule in rules for word in ('--rule', rule['id'])]
    record = {'scope': 'Fixed source snapshots; syntax support is not semantic support',
              'before_sha256': hashlib.sha256(args.before.read_bytes()).hexdigest(),
              'after_sha256': hashlib.sha256(args.after.read_bytes()).hexdigest(),
              'projects': []}
    for entry in entries:
        source = args.source_root.resolve() / entry['id']
        before_ledger = ledger(source)
        pin = json.loads((args.source_root / (entry['id'] + '.pin.json')).read_text())
        if pin['source_files'] != before_ledger or pin['url'] != entry['archive_url']:
            raise ValueError('fixed snapshot differs: ' + entry['id'])
        row = {'project': entry['project'], 'id': entry['id'], 'version': entry.get('version'),
               'archive_url': entry['archive_url'], 'archive_sha256': pin['archive_sha256']}
        reports = {}
        for name in ('before', 'after'):
            target = output / (entry['id'] + '-' + name + '.json.gz')
            row[name] = scan(getattr(args, name).resolve(), source, flags, target, 120)
            reports[name] = json.loads(gzip.decompress(target.read_bytes()))
        old, new = reports['before'], reports['after']
        old_parsed = {f['path'] for f in old['analysis_manifest']['files'] if f['status'] == 'parsed'}
        new_parsed = {f['path'] for f in new['analysis_manifest']['files'] if f['status'] == 'parsed'}
        if not old_parsed <= new_parsed:
            raise ValueError('lost parsed files')
        if [f for f in new['findings'] if f['file'] in old_parsed] != old['findings']:
            raise ValueError('findings changed on previously parsed files')
        ast_checks = []
        for name in sorted(new_parsed):
            code, official = run_export(args.exporter.resolve(), Path(name))
            compat_code, compat = run_export(args.exporter.resolve(), Path(name), True)
            if compat_code != 0:
                raise ValueError('compatible Handrolled parser failed: ' + name)
            same = code == 0 and official == compat
            if code == 0 and not same:
                raise ValueError('AST or original positions changed: ' + name)
            ast_checks.append({'file': str(Path(name).relative_to(source)),
                               'official_exit': code, 'compat_exit': compat_code,
                               'same_ast_and_positions': same if code == 0 else None})
        row['newly_parsed'] = [str(Path(x).relative_to(source)) for x in sorted(new_parsed - old_parsed)]
        row['unchanged_findings_on_previously_parsed_files'] = True
        row['ast_checks'] = ast_checks
        row['source_unchanged'] = before_ledger == ledger(source)
        if not row['source_unchanged']:
            raise ValueError('source changed during experiment')
        record['projects'].append(row)
        print(entry['project'], row['before']['files_parsed'], '->', row['after']['files_parsed'], flush=True)
    record['status'] = 'passed'
    save(output / 'summary.json', record)


if __name__ == '__main__':
    main()
