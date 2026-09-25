#!/usr/bin/env python3
"""Package a native release and extract the exact archive for acceptance."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--platform', required=True, choices=['linux-x86_64', 'macos-arm64', 'windows-x86_64'])
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    machine = platform.machine().lower()
    expected_os, expected_cpu = args.platform.split('-')
    actual_os = {'linux': 'linux', 'darwin': 'macos', 'windows': 'windows'}.get(platform.system().lower())
    actual_cpu = {'amd64': 'x86_64', 'x86_64': 'x86_64', 'arm64': 'arm64', 'aarch64': 'arm64'}.get(machine)
    if (actual_os, actual_cpu) != (expected_os, expected_cpu):
        parser.error(f'host mismatch: {platform.platform()} {machine}')
    binary = ROOT / '_build/native/release/build/src/main/main.exe'
    if not binary.is_file():
        parser.error(f'build native release first: {binary}')
    version = subprocess.check_output([str(binary), '--version'], text=True).strip()
    toolchain = subprocess.check_output(['moon', 'version', '--all'], text=True).strip()
    if 'moon 0.1.20260920' not in toolchain:
        parser.error('release must use the fixed analyzer toolchain')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    name = 'moon-audit.exe' if os.name == 'nt' else 'moon-audit'
    moon_executable = Path(shutil.which('moon')).resolve()
    core_license = moon_executable.parent.parent / 'lib/core/LICENSE'
    if not core_license.is_file():
        parser.error(f'core license missing from build toolchain: {core_license}')
    dependencies = {}
    for dependency in ('parser', 'lexer', 'x', 'async'):
        manifest = ROOT / '.mooncakes/moonbitlang' / dependency / 'moon.mod'
        dependencies[dependency] = hashlib.sha256(manifest.read_bytes()).hexdigest()
    info = {'version': version, 'toolchain': toolchain, 'host': platform.platform(),
            'architecture': machine, 'artifact_platform': args.platform,
            'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
            'dependency_manifest_sha256': dependencies,
            'runtime': 'native; target MoonBit required only for project verification',
            'acceptance': 'pending extracted-artifact tests'}
    metadata = output / 'build-info.json'
    metadata.write_text(json.dumps(info, indent=2) + '\n', encoding='utf-8')
    archive = output / f'moon-audit-0.5.0-dev-{args.platform}.zip'
    with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as package:
        package.write(binary, name)
        package.write(ROOT / 'LICENSE', 'LICENSE')
        package.write(core_license, 'licenses/core/LICENSE')
        package.write(ROOT / 'README.md', 'README.md')
        package.write(metadata, 'build-info.json')
        notices = []
        apache_text = ROOT / '.mooncakes/moonbitlang/parser/LICENSE'
        for dependency in ('parser', 'lexer', 'x', 'async'):
            module = ROOT / '.mooncakes/moonbitlang' / dependency
            manifest = module / 'moon.mod'
            metadata_text = manifest.read_text(encoding='utf-8')
            declared = re.search(r'^license\s*=\s*"([^"]+)"', metadata_text, re.MULTILINE)
            license_id = declared.group(1) if declared else 'See bundled module metadata'
            package.write(manifest, f'licenses/{dependency}/moon.mod')
            license_files = sorted(path for path in module.rglob('LICENSE*') if path.is_file())
            for license_file in license_files:
                package.write(license_file, f'licenses/{dependency}/{license_file.relative_to(module).as_posix()}')
            # Some registry archives declare Apache-2.0 but omit its standard text.
            # Reuse the unmodified standard text from the pinned parser archive;
            # retain each module's own metadata and any nested third-party notices.
            if not (module / 'LICENSE').is_file() and license_id == 'Apache-2.0':
                package.write(apache_text, f'licenses/{dependency}/LICENSE')
            notices.append(f'moonbitlang/{dependency}: {license_id}; see licenses/{dependency}/moon.mod')
        package.writestr('THIRD_PARTY_NOTICES.txt',
            'Dependency module metadata and license texts accompany this archive.\n'
            'Apache-2.0 standard text is also supplied when a registry archive omits it.\n'
            + '\n'.join(notices) + '\nMoonBit core: see licenses/core/LICENSE\n')
    archive.with_suffix('.zip.sha256').write_text(hashlib.sha256(archive.read_bytes()).hexdigest() + '  ' + archive.name + '\n', encoding='ascii')
    extracted = output / 'extracted'
    if extracted.exists():
        shutil.rmtree(extracted)
    with zipfile.ZipFile(archive) as package:
        package.extractall(extracted)
    (extracted / name).chmod(0o755)
    print(archive)

if __name__ == '__main__':
    main()
