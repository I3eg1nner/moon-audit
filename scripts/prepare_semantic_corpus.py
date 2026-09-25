#!/usr/bin/env python3
"""Fetch fixed public model corpora for CI and verify their reviewed file hashes."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'experiments/security_chain'))
from validate_mocket import fingerprint

def fetch(url):
    request = urllib.request.Request(url, headers={'User-Agent': 'moon-audit-acceptance/0.5'})
    with urllib.request.urlopen(request, timeout=120) as source:
        return source.read()

def extract_zip(data, target):
    target.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for item in archive.infolist():
            if not (target / item.filename).resolve().is_relative_to(target):
                raise RuntimeError('unsafe archive member')
        archive.extractall(target)

def source_archive(url, target):
    with tempfile.TemporaryDirectory(prefix='moon-audit-model-download-') as temp:
        with tarfile.open(fileobj=io.BytesIO(fetch(url))) as archive:
            archive.extractall(temp, filter='data')
        roots = list(Path(temp).iterdir())
        if len(roots) != 1 or not roots[0].is_dir():
            raise RuntimeError('unexpected source archive layout')
        shutil.copytree(roots[0], target)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--destination',type=Path,required=True)
    args=p.parse_args();dest=args.destination.resolve();dest.mkdir(parents=True,exist_ok=True)
    mocket=json.loads((ROOT/'experiments/security_chain/mocket-runtime-2026-09-25.json').read_text())
    cmark=json.loads((ROOT/'experiments/cmark_chain/cmark-model-2026-09-25.json').read_text())
    for name,repo,commit,record in [('mocket','oboard/mocket',mocket['reviewed_corpus_commit'],mocket),('cmark','moonbit-community/cmark.mbt',cmark['commit'],cmark)]:
        target=dest/name
        if target.exists():p.error('destination model directory already exists: '+str(target))
        source_archive(f'https://codeload.github.com/{repo}/tar.gz/{commit}',target)
        actual=fingerprint(target,exclude_dependencies=True)['files']
        expected=record['source_fingerprint']['files']
        if actual != expected:raise RuntimeError(name+': source file fingerprints differ')
        modules=target/'.mooncakes';modules.mkdir()
        (modules/'.moon-lock').touch()
        if name=='mocket':
            deps=[(module,version,record['dependency_fingerprints'][module]['files']) for module,version in [('moonbitlang/async','0.21.0'),('moonbitlang/x','0.5.1'),('oboard/mimetype','0.2.0')]]
        else:deps=[(dep['module'],dep['version'],dep['source_fingerprint']['files']) for dep in record['dependencies']]
        for module,version,expected in deps:
            extract_zip(fetch(f'https://download.mooncakes.io/user/{module}/{version}.zip'),modules/module)
            if fingerprint(modules/module)['files'] != expected:raise RuntimeError(module+': reviewed dependency fingerprints differ')
        print(name+': pinned source and dependencies verified')

if __name__=='__main__':main()
