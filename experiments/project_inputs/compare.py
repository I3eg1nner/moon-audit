#!/usr/bin/env python3
"""Offline comparison of previously imported, pinned popular-project snapshots."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from popular_projects import ledger, scan, save


def extra_inputs(root):
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in root.rglob('*')
            if p.is_file() and not p.is_symlink()
            and (p.name.endswith('.mbt.md') or p.name.endswith('.mbtx'))
            and not any(x.startswith('.') or x == '_build' for x in p.relative_to(root).parts)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('before', 'after', 'source-root', 'output-dir'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads((ROOT / 'experiments/popular_projects/manifest-2026-09-25.json').read_text())
    output = args.output_dir.resolve()
    record = {'scope': 'Input coverage and module attribution; not vulnerability accuracy',
              'before_sha256': hashlib.sha256(args.before.read_bytes()).hexdigest(),
              'after_sha256': hashlib.sha256(args.after.read_bytes()).hexdigest(), 'projects': []}
    for entry in manifest['entries']:
        source = args.source_root.resolve() / entry['id']
        if not source.is_dir():
            record['projects'].append({'id': entry['id'], 'status': 'not_imported'})
            continue
        pin = json.loads((args.source_root / (entry['id'] + '.pin.json')).read_text())
        original = ledger(source)
        extra = extra_inputs(source)
        if original != pin['source_files'] or pin['url'] != entry['archive_url']:
            raise ValueError('snapshot no longer matches original .mbt/config ledger: ' + entry['id'])
        row = {'id': entry['id'], 'project': entry['project'], 'archive_sha256': pin['archive_sha256'],
               'extra_format_sha256': extra}
        reports = {}
        for label in ('before', 'after'):
            report_path = output / (entry['id'] + '-' + label + '.json.gz')
            row[label] = scan(getattr(args, label).resolve(), source, [], report_path, 120)
            reports[label] = json.loads(gzip.decompress(report_path.read_bytes()))
        old, new = reports['before'], reports['after']
        parsed = lambda report: {f['path'] for f in report['analysis_manifest']['files'] if f['status'] == 'parsed'}
        if parsed(old) != parsed(new):
            raise ValueError('unexpected .mbt parsing coverage change: ' + entry['id'])
        if old['findings'] != new['findings']:
            raise ValueError('unexpected default finding change: ' + entry['id'])
        row['unsupported_inputs'] = [str(Path(f['path']).relative_to(source))
                                    for f in new['analysis_manifest']['files'] if f['status'] == 'unsupported']
        row['unchanged_parsed_files_and_default_findings'] = True
        row['source_unchanged'] = original == ledger(source) and extra == extra_inputs(source)
        if not row['source_unchanged']:
            raise ValueError('source mutated: ' + entry['id'])
        row['new_diagnostics'] = [e for e in new['errors'] if e not in old['errors']]
        record['projects'].append(row)
        print(entry['project'], row['before']['exit_code'], '->', row['after']['exit_code'],
              'unsupported', len(row['unsupported_inputs']), flush=True)
    record['status'] = 'passed'
    save(output / 'summary.json', record)


if __name__ == '__main__':
    main()
