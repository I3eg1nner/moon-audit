#!/usr/bin/env python3
"""Compare configuration acceptance with the two installed target compilers."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from popular_projects import save

CASES = {
    'line-comment': ('{ // comment\n "name":"fixture/config" }', True),
    'block-comment': ('{ /* comment */ "name":"fixture/config" }', True),
    'trailing-comma': ('{ "name":"fixture/config", }', True),
    'escaped-name': ('{ "na\\u006de":"fixture/config" }', True),
    'duplicate-name': ('{ "name":"fixture/config", "name":"moonbitlang/core" }', False),
    'escaped-duplicate': ('{ "name":"fixture/config", "na\\u006de":"moonbitlang/core" }', False),
    'unquoted-key': ('{ name: "fixture/config" }', False),
    'single-quote': ("{ 'name': 'fixture/config' }", False),
    'empty-comma': ('{,}', False),
}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--analyzer', required=True, type=Path)
    ap.add_argument('--toolchain', required=True, action='append', type=Path)
    ap.add_argument('--output', required=True, type=Path)
    args = ap.parse_args()
    result = {'analyzer_sha256': hashlib.sha256(args.analyzer.read_bytes()).hexdigest(), 'observations': []}
    for home in args.toolchain:
        home = home.resolve()
        environment = os.environ | {'MOON_HOME': str(home), 'PATH': str(home / 'bin') + os.pathsep + os.environ.get('PATH', '')}
        moon = home / 'bin' / ('moon.exe' if os.name == 'nt' else 'moon')
        version = subprocess.check_output([str(moon), 'version'], env=environment, text=True, timeout=30).strip()
        for name, (config, accepted) in CASES.items():
            with tempfile.TemporaryDirectory(prefix='moon-audit-config-oracle-') as temporary:
                root = Path(temporary)
                (root / 'moon.mod.json').write_text(config, encoding='utf-8')
                (root / 'moon.pkg.json').write_text('{ /* package */ "import": [], }', encoding='utf-8')
                (root / 'main.mbt').write_text('pub fn escape(s : String) -> String { s.replace(old="<", new="&lt;") }\n', encoding='utf-8')
                compiler = subprocess.run([str(moon), 'check', '--target', 'native'], cwd=root, env=environment,
                                          capture_output=True, text=True, timeout=90)
                scanner = subprocess.run([str(args.analyzer.resolve()), '--format', 'json', str(root)],
                                         capture_output=True, text=True, timeout=30)
                report = json.loads(scanner.stdout)
                assert (compiler.returncode == 0) == accepted, (version, name, compiler.stderr)
                assert scanner.returncode == (0 if accepted else 2), (version, name, report)
                assert len(report['findings']) == 1, (version, name, report)
                result['observations'].append({'toolchain': version, 'case': name, 'source': config,
                    'compiler_exit': compiler.returncode, 'compiler_stdout': compiler.stdout,
                    'compiler_stderr': compiler.stderr, 'scanner_exit': scanner.returncode, 'report': report})
    result['status'] = 'passed'
    save(args.output, result)
    print(f"{len(result['observations'])} configuration observations passed")


if __name__ == '__main__':
    main()
