#!/usr/bin/env python3
"""Install reviewed compiler/core archives with fixed SHA-256 into a fresh directory."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tarfile
import tempfile
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--destination', type=Path, required=True)
    p.add_argument('--lock', type=Path, default=ROOT / 'scripts/toolchain-lock.json',
                   help='Reviewed archive lock; compatibility CI uses one per real target toolchain')
    args = p.parse_args()
    os_name = {'Linux': 'linux', 'Darwin': 'macos', 'Windows': 'windows'}[platform.system()]
    arch = {'x86_64': 'x86_64', 'AMD64': 'x86_64', 'aarch64': 'arm64', 'arm64': 'arm64'}[platform.machine()]
    lock = json.loads(args.lock.read_text(encoding='utf-8'))
    artifact = lock['artifacts'][os_name + '-' + arch]
    destination = args.destination.resolve()
    if destination.exists() and any(destination.iterdir()):
        p.error('destination must be empty; existing toolchains are never overwritten')
    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='moon-audit-toolchain-') as temp:
        for name, spec, output in [('binary', artifact, destination), ('core', lock['core'], destination / 'lib')]:
            archive = Path(temp) / name
            request = urllib.request.Request(spec['url'], headers={'User-Agent': 'moon-audit-build/0.5'})
            with urllib.request.urlopen(request, timeout=120) as response, archive.open('wb') as target:
                while data := response.read(1024 * 1024):
                    target.write(data)
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            if digest != spec['sha256']:
                raise RuntimeError(f'{name}: SHA-256 mismatch: {digest}')
            output.mkdir(parents=True, exist_ok=True)
            if spec['url'].endswith('.zip'):
                with zipfile.ZipFile(archive) as package:
                    for item in package.infolist():
                        if not (output / item.filename).resolve().is_relative_to(output):
                            raise RuntimeError('archive path outside destination')
                    package.extractall(output)
            else:
                with tarfile.open(archive) as package:
                    package.extractall(output, filter='data')
    if os.name != 'nt':
        for tool in (destination / 'bin').rglob('*'):
            if tool.is_file():
                tool.chmod(tool.stat().st_mode | 0o755)
    executable = destination / 'bin' / ('moon.exe' if os.name == 'nt' else 'moon')
    env = {**os.environ, 'MOON_HOME': str(destination), 'PATH': str(destination / 'bin') + os.pathsep + os.environ.get('PATH', '')}
    subprocess.run([str(executable), '-C', str(destination / 'lib/core'), 'bundle', '--warn-list', '-a', '--all'], env=env, check=True)
    subprocess.run([str(executable), 'version', '--all'], env=env, check=True)
    for variable, lines in [('GITHUB_PATH', [str(destination / 'bin')]),
                            ('GITHUB_ENV', ['MOON_HOME=' + str(destination), 'PROJECT_TOOLCHAIN=' + str(destination)])]:
        if variable in os.environ:
            with open(os.environ[variable], 'a', encoding='utf-8') as output:
                output.write('\n'.join(lines) + '\n')

if __name__ == '__main__':
    main()
