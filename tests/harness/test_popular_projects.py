#!/usr/bin/env python3
"""Immutable corpus import boundaries and scanner status regression tests."""
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
import popular_projects as corpus


class CorpusTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.target = self.root / 'project'

    def tar(self, link=None):
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode='w') as archive:
            item = tarfile.TarInfo('repo/main.mbt');item.size=3
            archive.addfile(item, io.BytesIO(b'abc'))
            if link:
                item=tarfile.TarInfo('repo/link');item.type=tarfile.SYMTYPE;item.linkname=link
                archive.addfile(item)
        return data.getvalue()

    def test_valid_tar_and_in_repo_link_preserved(self):
        corpus.extract(self.tar('main.mbt'),self.target,'tar')
        self.assertTrue((self.target/'link').is_symlink())
        self.assertEqual(corpus.ledger(self.target)['link'],'symlink:main.mbt')

    def test_tar_external_link_rejected_without_partial_cache(self):
        with self.assertRaises(tarfile.TarError):
            corpus.extract(self.tar('../../outside'),self.target,'tar')
        self.assertFalse(self.target.exists())

    def test_zip_traversal_rejected(self):
        for name in ('../outside', '/absolute', 'dir\\escape'):
            data=io.BytesIO()
            with zipfile.ZipFile(data,'w') as archive:archive.writestr(name,'no')
            with self.assertRaises(ValueError):corpus.extract(data.getvalue(),self.target,'zip')
        self.assertFalse(self.target.exists())

    def test_archive_existing_target_not_modified(self):
        self.target.mkdir();(self.target/'keep').write_text('keep')
        with self.assertRaises(ValueError):corpus.extract(self.tar(),self.target,'tar')
        self.assertEqual((self.target/'keep').read_text(),'keep')

    def test_ledger_tracks_sources_not_build_outputs(self):
        self.target.mkdir();(self.target/'main.mbt').write_text('original')
        before=corpus.ledger(self.target)
        (self.target/'_build').mkdir();(self.target/'_build/cache.mbt').write_text('generated')
        self.assertEqual(before,corpus.ledger(self.target))
        (self.target/'main.mbt').write_text('changed')
        self.assertNotEqual(before,corpus.ledger(self.target))

    def test_directory_symlink_escape_rejected(self):
        self.target.mkdir();(self.target/'outside').symlink_to(self.root,target_is_directory=True)
        with self.assertRaises(ValueError):corpus.ledger(self.target)

    def test_directory_symlink_is_in_ledger(self):
        self.target.mkdir();(self.target/'sub').mkdir();(self.target/'alias').symlink_to('sub',target_is_directory=True)
        self.assertEqual(corpus.ledger(self.target)['alias'],'symlink:sub')

    def scan(self,code,report):
        response=subprocess.CompletedProcess([],code,json.dumps(report),'')
        with patch.object(corpus.subprocess,'run',return_value=response):
            return corpus.scan(Path('/binary'),self.target,[],self.root/'report.json',1)

    def test_parse_gaps_remain_incomplete_even_without_error_strings(self):
        result=self.scan(0,{'findings':[],'errors':[],'files_selected':2,'files_parsed':1})
        self.assertEqual(result['status'],'incomplete')

    def test_exit_two_preserves_findings(self):
        result=self.scan(2,{'findings':[{'rule_id':'example'}],'errors':['parse error'],'files_selected':2,'files_parsed':1})
        self.assertEqual(result['status'],'incomplete');self.assertEqual(result['findings'],1)

    def test_invalid_scanner_report_is_execution_failure(self):
        self.assertEqual(self.scan(0,{'ok':True})['status'],'execution_failed')


if __name__=='__main__':unittest.main()
