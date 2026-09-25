#!/usr/bin/env python3
"""Record syntax-only compiler/parser agreement; never execute sample programs."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--analyzer', type=Path, required=True)
    parser.add_argument('--moonc', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    rows = []
    for source in sorted((Path(__file__).parent / 'syntax-repros').glob('*.mbt.txt')):
        with tempfile.TemporaryDirectory(prefix='moon-audit-syntax-oracle-') as tmp:
            root = Path(tmp)
            (root / 'lib.mbt').write_bytes(source.read_bytes())
            (root / 'moon.mod').write_text('name = "fixture/syntax"\n', encoding='utf-8')
            (root / 'moon.pkg').write_text('', encoding='utf-8')
            compiler = subprocess.run([str(args.moonc.resolve()), 'syncheck', str(root / 'lib.mbt')],
                                      text=True, encoding='utf-8', capture_output=True, timeout=30)
            scanner = subprocess.run([str(args.analyzer.resolve()), '--format', 'json', str(root)],
                                     text=True, encoding='utf-8', capture_output=True, timeout=30)
            report = json.loads(scanner.stdout.replace(tmp, '<case>'))
            rows.append({'file': 'syntax-repros/' + source.name,
                         'sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
                         'compiler_syntax_exit': compiler.returncode,
                         'compiler_syntax_stdout': compiler.stdout.replace(tmp, '<case>'),
                         'compiler_syntax_stderr': compiler.stderr.replace(tmp, '<case>'),
                         'scanner_exit': scanner.returncode,
                         'scanner_errors': report['errors'],
                         'scanner_findings': report['findings']})
    version = subprocess.check_output([str(args.moonc.resolve()), '-v'], text=True).strip()
    args.output.write_text(json.dumps({'compiler_version': version,
        'analyzer_sha256': hashlib.sha256(args.analyzer.read_bytes()).hexdigest(),
        'scope': 'Minimal syntax acceptance only; not type checking or historical compiler support',
        'cases': rows}, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    for row in rows:
        print(row['file'], row['compiler_syntax_exit'], row['scanner_exit'])


if __name__ == '__main__':
    main()
