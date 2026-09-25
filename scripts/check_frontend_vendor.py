#!/usr/bin/env python3
"""Verify the exact pinned frontend sources and their small upstream patch offline."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VENDOR = ROOT / 'src/vendor/parser_compat'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def verify(upstream=None):
    manifest = json.loads((VENDOR / 'vendor.lock.json').read_text(encoding='utf-8'))
    expected = {entry['path']: entry for entry in manifest['files']}
    metadata = {'README.md', 'NOTICE', 'compat.patch', 'vendor.lock.json'}
    actual = {p.relative_to(VENDOR).as_posix() for p in VENDOR.rglob('*')
              if p.is_file() and p.name != 'pkg.generated.mbti'
              and p.relative_to(VENDOR).as_posix() not in metadata}
    if actual != set(expected):
        raise ValueError(f'frontend file set changed: {sorted(actual ^ set(expected))}')
    diff = []
    for name, entry in sorted(expected.items()):
        data = (VENDOR / name).read_bytes()
        if digest(data) != entry['sha256']:
            raise ValueError(f'frontend digest mismatch: {name}')
        if upstream is not None:
            original = (upstream / name).read_bytes()
            if digest(original) != entry['upstream_sha256']:
                raise ValueError(f'upstream digest mismatch: {name}')
            diff.extend(difflib.unified_diff(original.decode().splitlines(True),
                                           data.decode().splitlines(True),
                                           fromfile='upstream/' + name, tofile='compat/' + name))
    patch = (VENDOR / 'compat.patch').read_bytes()
    if digest(patch) != manifest['patch_sha256']:
        raise ValueError('frontend patch digest mismatch')
    if upstream is not None and ''.join(diff).encode() != patch:
        raise ValueError('compat.patch does not describe the vendored sources')
    print(f'Frontend {manifest["compatibility_id"]}: {len(expected)} files verified'
          + (' against pinned upstream and patch' if upstream else ''))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--upstream', type=Path)
    args = parser.parse_args()
    try:
        verify(args.upstream)
    except (ValueError, KeyError, OSError) as error:
        parser.exit(2, f'frontend verification failed: {error}\n')


if __name__ == '__main__':
    main()
