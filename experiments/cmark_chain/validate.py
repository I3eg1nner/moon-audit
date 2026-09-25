#!/usr/bin/env python3
"""Verify pinned cmark behavior and official declaration identities without editing library sources."""
from __future__ import annotations
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import time
import urllib.request
import zipfile

HERE = Path(__file__).resolve().parent
COMMIT = 'ebf47ab9efcbd2ecff6f6ec8656c06a308395729'
EXPECTED = {
    'raw': '<script>alert(1)</script>\n',
    'safe': '<!--CommonMark HTML block omitted-->\n',
    'default': '<!--CommonMark HTML block omitted-->\n',
    'raw_url': '<p><a href="javascript:alert(1)">link</a></p>\n',
    'safe_url': '<p><a href="">link</a></p>\n',
    'ordinary': '<p><strong>hello</strong></p>\n',
    'unrelated': '<script>alert(1)</script>',
}


def fingerprint(root: Path) -> dict:
    values = {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in sorted(root.rglob('*')) if p.is_file()
              and not set(p.relative_to(root).parts) & {'_build', '.git', '.mooncakes', '.moon-audit-cache'}}
    return {'sha256': hashlib.sha256(json.dumps(values, sort_keys=True).encode()).hexdigest(), 'files': values}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cmark', required=True, type=Path, help='Git checkout containing the pinned commit')
    parser.add_argument('--archives', required=True, type=Path)
    parser.add_argument('--toolchain', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--download', action='store_true', help='Download missing exact checksum-verified dependency archives')
    args = parser.parse_args()
    home = args.toolchain.resolve()
    executable = home / 'bin/moon'
    env = dict(os.environ, MOON_HOME=str(home), PATH=str(home / 'bin') + os.pathsep + os.environ.get('PATH', ''))
    dependencies = json.loads((HERE / 'dependencies.json').read_text())
    args.archives.mkdir(parents=True, exist_ok=True)
    for item in dependencies:
        path = args.archives / (item['module'].replace('/', '_') + '-' + item['version'] + '.zip')
        if not path.exists() and args.download:
            path.write_bytes(urllib.request.urlopen(item['url'], timeout=45).read())
        if not path.exists():
            parser.error('missing archive; use --download once: ' + str(path))
        if hashlib.sha256(path.read_bytes()).hexdigest() != item['sha256']:
            parser.error('dependency archive checksum mismatch: ' + str(path))
        item['archive'] = str(path.resolve())
    archive = subprocess.check_output(['git', '-C', str(args.cmark.resolve()), 'archive', COMMIT])
    record = {'schema': 'moon-audit.cmark-model-validation.v1', 'library': 'moonbit-community/cmark',
              'library_version': '0.4.8', 'commit': COMMIT, 'target': 'native', 'dependencies': dependencies,
              'production_ready': False, 'commands': [], 'bindings': [],
              'limits': ['Runtime API and binding evidence only; no production IR integration is asserted.',
                         'No browser or HTTP server is executed.',
                         'safe=true is an HTML-fragment property, not universal string neutralization.',
                         'The render API may raise; only successful normal outputs are validated here.',
                         'backend_blocks and strict are kept at reviewed defaults false and true.']}
    passed = False
    with tempfile.TemporaryDirectory(prefix='moon-audit-cmark-model-') as temp:
        root = Path(temp)
        lib = root / 'cmark'
        lib.mkdir()
        with tarfile.open(fileobj=io.BytesIO(archive)) as snapshot:
            for member in snapshot.getmembers():
                name = Path(member.name)
                if name.is_absolute() or '..' in name.parts or not (member.isfile() or member.isdir()):
                    parser.error('unsupported archive entry: ' + member.name)
            snapshot.extractall(lib, filter='data')
        record['source_fingerprint'] = fingerprint(lib)
        for item in dependencies:
            target = lib / '.mooncakes' / item['module']
            target.mkdir(parents=True)
            with zipfile.ZipFile(item['archive']) as zipped:
                for member in zipped.infolist():
                    name = Path(member.filename)
                    if name.is_absolute() or '..' in name.parts:
                        parser.error('unsafe archive path: ' + member.filename)
                zipped.extractall(target)
            item['source_fingerprint'] = fingerprint(target)

        def run(cwd: Path, arguments: list[str]):
            command = [str(executable), *arguments]
            started = time.monotonic()
            result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True, timeout=120)
            entry = {'command': command, 'cwd': str(cwd), 'exit_code': result.returncode,
                     'seconds': round(time.monotonic()-started, 4), 'stdout': result.stdout, 'stderr': result.stderr}
            record['commands'].append(entry)
            return entry

        record['toolchain'] = run(lib, ['version', '--all'])['stdout']
        upstream = run(lib, ['test', '--frozen', '--target', 'native', 'src/cmark_html/safe_default_test.mbt', '--diagnostic-limit', '3'])
        record['upstream_safe_tests_passed'] = upstream['exit_code'] == 0 and 'Total tests: 4, passed: 4, failed: 0.' in upstream['stdout'] + upstream['stderr']
        record['library_sources_unchanged_after_upstream_test'] = record['source_fingerprint'] == fingerprint(lib)
        consumer = root / 'consumer'
        consumer.mkdir()
        shutil.copytree(lib / '.mooncakes', consumer / '.mooncakes')
        shutil.copytree(lib, consumer / '.mooncakes/moonbit-community/cmark', ignore=shutil.ignore_patterns('.mooncakes', '_build'))
        (consumer / 'moon.mod').write_text('name = "audit/cmark-probe"\nimport { "moonbit-community/cmark@0.4.8" }\npreferred_target = "native"\n')
        for name in ['moon.pkg', 'probe.mbt', 'probe_wbtest.mbt']:
            shutil.copyfile(HERE / (name + '.txt'), consumer / name)
        record['fixture_sha256'] = {name.name: hashlib.sha256(name.read_bytes()).hexdigest() for name in sorted(HERE.glob('*.txt'))}
        checked = run(consumer, ['check', '--frozen', '--target', 'native', '--diagnostic-limit', '3'])
        tested = run(consumer, ['test', '--frozen', '--target', 'native', 'probe_wbtest.mbt', '--diagnostic-limit', '3'])
        record['observed_output'] = {name: json.loads(value) for name, value in re.findall(r'^CMARK_CHAIN (\w+) (.*)$', tested['stdout'], re.M)}
        record['consumer_tests_passed'] = tested['exit_code'] == 0 and 'Total tests: 7, passed: 7, failed: 0.' in tested['stdout'] + tested['stderr'] and record['observed_output'] == EXPECTED
        if checked['exit_code'] == 0:
            source = (consumer / 'probe.mbt').read_text().splitlines()
            for index, (label, line) in enumerate([('unsafe_library_render', 3), ('safe_library_render', 8), ('default_library_render', 13), ('unrelated_render', 24)]):
                col = source[line-1].index('render')+1
                command = ['ide', 'peek-def', '--json', '--target', 'native', '--loc', f'probe.mbt:{line}:{col}']
                if index:
                    command.append('--no-check')
                result = run(consumer, command)
                try:
                    value = json.loads(result['stdout'])
                except ValueError:
                    value = None
                expected_file = consumer / ('.mooncakes/moonbit-community/cmark/src/cmark_html/html.mbt' if index < 3 else 'probe.mbt')
                expected_range = '1032:8-1032:14' if index < 3 else '17:4-17:10'
                valid = result['exit_code'] == 0 and isinstance(value, list) and len(value) == 1 and Path(value[0].get('path', '')) == expected_file and value[0].get('range') == expected_range
                record['bindings'].append({'name': label, 'query': f'probe.mbt:{line}:{col}', 'response': value,
                                           'unique_expected_declaration': valid, 'declaration_file_sha256': hashlib.sha256(expected_file.read_bytes()).hexdigest()})
        passed = record['upstream_safe_tests_passed'] and record['library_sources_unchanged_after_upstream_test'] and record['consumer_tests_passed'] and len(record['bindings']) == 4 and all(x['unique_expected_declaration'] for x in record['bindings'])
    record['status'] = 'runtime_and_binding_verified' if passed else 'failed'
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, indent=2, ensure_ascii=False)+'\n')
    print(json.dumps({'status':record['status'],'upstream_tests':record['upstream_safe_tests_passed'], 'consumer_tests':record['consumer_tests_passed'], 'bindings':[x['unique_expected_declaration'] for x in record['bindings']], 'output':str(args.output)}))
    if not passed:
        for entry in record['commands']:
            if entry['exit_code']: print(entry['stdout'], entry['stderr'])
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
