#!/usr/bin/env python3
"""Discover public popularity cohorts and scan immutable source snapshots.

Rankings measure popularity, not security. No target application is executed.
Project compilation is optional and explicitly separate from syntax coverage.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
import urllib.request
import zipfile

IGNORED = {'.git', '.mooncakes', '_build', '.recovery', '__pycache__'}

def sha(data):
    return hashlib.sha256(data).hexdigest()

def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + '.tmp')
    data=(json.dumps(value, indent=2, ensure_ascii=False) + '\n').encode('utf-8')
    temporary.write_bytes(gzip.compress(data,mtime=0) if path.suffix=='.gz' else data)
    temporary.replace(path)

def fetch(url, limit=100*1024*1024):
    request = urllib.request.Request(url, headers={'User-Agent':'moon-audit-popular-projects/0.5'})
    with urllib.request.urlopen(request, timeout=90) as response:
        data=response.read(limit+1)
    if len(data)>limit:raise ValueError('download exceeds size budget')
    return data

def github(endpoint, *parameters):
    command=['gh','api','-X','GET',endpoint]
    for item in parameters:command += ['-f', item]
    return json.loads(subprocess.check_output(command, text=True, timeout=60))

def discover(args):
    stamp=datetime.now(timezone.utc).isoformat()
    homepage=fetch('https://mooncakes.io').decode('utf-8')
    section=homepage.split('Most downloaded',1)[1].split('Show more modules',1)[0]
    downloads=list(dict.fromkeys(re.findall(r'href="/docs/([^"@]+)@([^"/]+)"',section)))[:args.downloads]
    if len(downloads)!=args.downloads:raise ValueError('official homepage does not expose requested number of entries')
    search=github('search/repositories','q=language:MoonBit archived:false fork:false','sort=stars','order=desc','per_page='+str(args.stars))
    def entry(pair):
        rank,repo=pair
        commit=github('repos/'+repo['full_name']+'/commits/'+repo['default_branch'])['sha']
        return {'id':'star-'+repo['full_name'].replace('/','--'),'cohort':'github_stars','rank':rank,'project':repo['full_name'],'stars':repo['stargazers_count'],'repository':repo['html_url'],'commit':commit,'archive_url':f"https://codeload.github.com/{repo['full_name']}/tar.gz/{commit}",'archive_type':'tar'}
    with ThreadPoolExecutor(max_workers=4) as pool:stars=list(pool.map(entry,enumerate(search['items'],1)))
    entries=[{'id':'download-'+name.replace('/','--'),'cohort':'mooncakes_downloads','rank':n,'project':name,'version':version,'download_count':None,'registry_page':f'https://mooncakes.io/docs/{name}@{version}','archive_url':f'https://download.mooncakes.io/user/{name}/{version}.zip','archive_type':'zip'} for n,(name,version) in enumerate(downloads,1)]+stars
    save(args.output,{'schema':'moon-audit.popular-projects.v1','retrieved_at':stamp,'sources':{'downloads':{'url':'https://mooncakes.io','section':'Most downloaded','html_sha256':sha(homepage.encode()),'metric':'official homepage order; counts and time window not exposed, not inferred'},'stars':{'url':'https://api.github.com/search/repositories?q=language%3AMoonBit+archived%3Afalse+fork%3Afalse&sort=stars&order=desc','total_count':search['total_count'],'metric':'GitHub stargazers_count at retrieval'}},'entries':entries})
    print('Pinned',len(entries),'public source snapshots')

def extract(data, target, kind):
    if target.exists():raise ValueError('refusing to overwrite an existing source snapshot')
    target.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(dir=target.parent,prefix='extract-') as temp:
        staging=Path(temp)
        if kind=='zip':
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                members=archive.infolist()
                if len(members)>50000 or sum(m.file_size for m in members)>512*1024*1024:raise ValueError('archive extraction budget')
                for m in members:
                    path=PurePosixPath(m.filename)
                    mode=m.external_attr>>16
                    if path.is_absolute() or '..' in path.parts or '\\' in m.filename or stat.S_ISLNK(mode):raise ValueError('unsafe archive path or symlink')
                archive.extractall(staging)
            source=staging
        else:
            with tarfile.open(fileobj=io.BytesIO(data)) as archive:
                members=archive.getmembers()
                if len(members)>50000 or sum(m.size for m in members)>512*1024*1024:raise ValueError('archive extraction budget')
                if any(not(m.isfile() or m.isdir() or m.issym() or m.islnk()) for m in members):raise ValueError('source archive contains special files')
                archive.extractall(staging,filter='data')
            roots=list(staging.iterdir())
            if len(roots)!=1 or not roots[0].is_dir():raise ValueError('unexpected repository archive layout')
            source=roots[0]
        shutil.copytree(source,target,symlinks=True)

def ledger(root):
    result={}
    for parent,dirs,files in os.walk(root,followlinks=False):
        dirs[:]=sorted(d for d in dirs if d not in IGNORED)
        for name in list(dirs):
            p=Path(parent)/name
            if p.is_symlink():
                if not p.resolve().is_relative_to(root.resolve()):raise ValueError('source symlink escapes snapshot')
                result[p.relative_to(root).as_posix()]='symlink:'+os.readlink(p)
                dirs.remove(name)
        for name in sorted(files):
            p=Path(parent)/name
            if p.is_symlink():
                if not p.resolve().is_relative_to(root.resolve()):raise ValueError('source symlink escapes snapshot')
                result[p.relative_to(root).as_posix()]='symlink:'+os.readlink(p)
                continue
            if name.endswith('.mbt') or name in ('moon.mod','moon.mod.json','moon.pkg','moon.pkg.json','.moon-audit.json'):
                result[p.relative_to(root).as_posix()]=sha(p.read_bytes())
    return result

def scan(binary, project, flags, output, timeout):
    command=[str(binary),'--format','json',*flags,str(project)]
    start=time.monotonic()
    response=subprocess.run(command,capture_output=True,text=True,encoding='utf-8',timeout=timeout)
    row={'command':command,'seconds':round(time.monotonic()-start,3),'exit_code':response.returncode,'stderr':response.stderr[-8000:]}
    try:
        report=json.loads(response.stdout)
        if not isinstance(report.get('findings'),list) or not isinstance(report.get('errors'),list):raise ValueError('invalid report structure')
        if response.returncode not in (0,1,2):raise ValueError('unexpected scanner exit')
        save(output,report)
        row.update(status='incomplete' if response.returncode==2 or report['errors'] or report['files_parsed'] != report['files_selected'] else 'completed_requested_syntax_scope',report=output.name,files_selected=report['files_selected'],files_parsed=report['files_parsed'],findings=len(report['findings']),errors=len(report['errors']),rules={})
        for finding in report['findings']:row['rules'][finding['rule_id']]=row['rules'].get(finding['rule_id'],0)+1
        if 'project_verification' in report and report['project_verification']:row['verification']=report['project_verification']['status']
    except (ValueError,KeyError,TypeError) as error:
        row.update(status='execution_failed',detail=str(error),stdout_tail=response.stdout[-2000:])
    return row

def run(args):
    manifest=json.loads(args.manifest.read_text());args.work_dir=args.work_dir.resolve();args.output_dir.mkdir(parents=True,exist_ok=True)
    args.work_dir.mkdir(parents=True,exist_ok=True)
    binary=args.analyzer.resolve();binary_hash=sha(binary.read_bytes())
    registry=json.loads(subprocess.check_output([str(binary),'--format','json','list-rules'],text=True,timeout=args.timeout))
    all_rules=[word for entry in registry for word in ('--rule',entry['id'])]
    result={'schema':'moon-audit.popular-project-scan.v1','started_at':datetime.now(timezone.utc).isoformat(),'manifest_sha256':sha(args.manifest.read_bytes()),'analyzer_sha256':binary_hash,'scope':'default syntax and opt-in all registered syntax hints; not full security analysis','projects':[],'limitations':['Registry popularity and GitHub stars are separate cohorts; duplicates across cohorts retain different source versions.','Examples, tests, dot directories and configured exclusions follow the scanner manifest, not whole-repository coverage.','No findings is not a safety conclusion. Parse and compilation failures remain incomplete.','Optional compiler checks use one explicitly selected toolchain; failure is not evidence the project itself is invalid.']}
    verified={}
    for entry in manifest['entries']:
        row=dict(entry);result['projects'].append(row);root=args.work_dir/entry['id'];blob=args.work_dir/(entry['id']+'.archive');pin=args.work_dir/(entry['id']+'.pin.json')
        try:
            if not root.exists():
                data=fetch(entry['archive_url']);blob.write_bytes(data);extract(data,root,entry['archive_type']);save(pin,{'url':entry['archive_url'],'archive_sha256':sha(data),'source_files':ledger(root)})
            pinned=json.loads(pin.read_text());before=ledger(root)
            if pinned['url']!=entry['archive_url'] or pinned['source_files']!=before:raise ValueError('cached source differs from fixed snapshot')
            if sha(blob.read_bytes())!=pinned['archive_sha256']:raise ValueError('cached archive digest differs')
            row.update(source_path=str(root),archive_sha256=pinned['archive_sha256'],source_file_count=len(before),source_ledger_sha256=sha(json.dumps(before,sort_keys=True).encode()))
            row['default']=scan(binary,root,[],args.output_dir/(entry['id']+'-default.json.gz'),args.timeout)
            row['all_rules']=scan(binary,root,all_rules,args.output_dir/(entry['id']+'-all.json.gz'),args.timeout)
            cohort=entry['cohort']
            if args.toolchain and verified.get(cohort,0)<args.verify_per_cohort:
                verified[cohort]=verified.get(cohort,0)+1
                modules=sorted({str(Path(f).parent) for f in before if Path(f).name in ('moon.mod','moon.mod.json')},key=lambda f:(len(Path(f).parts),f))
                if modules:
                    module=root/modules[0];home=args.toolchain.resolve();env=os.environ|{'MOON_HOME':str(home),'PATH':str(home/'bin')+os.pathsep+os.environ.get('PATH','')}
                    moon=home/'bin'/('moon.exe' if os.name=='nt' else 'moon')
                    prepared=subprocess.run([str(moon),'-C',str(module),'check','--target','native'],env=env,capture_output=True,text=True,encoding='utf-8',timeout=120)
                    row['dependency_preparation']={'exit_code':prepared.returncode,'module':modules[0],'other_modules_not_compiled':modules[1:],'diagnostics':(prepared.stdout+prepared.stderr)[-12000:]}
                    row['verified']=scan(binary,module,['--verify-project','--project-toolchain',str(home),'--timeout-seconds','30'],args.output_dir/(entry['id']+'-verified.json.gz'),180)
                else:row['verified']={'status':'not_attempted','reason':'no MoonBit module manifest in this repository snapshot'}
            else:row['verified']={'status':'not_requested','reason':'explicit compiler sampling limit; syntax scan remains unverified'}
            row['source_unchanged']=ledger(root)==before
            if not row['source_unchanged']:raise ValueError('target sources changed during checking')
        except (OSError,ValueError,subprocess.SubprocessError,tarfile.TarError,zipfile.BadZipFile) as error:
            row['harness_error']=type(error).__name__+': '+str(error)
        save(args.output_dir/'summary.json',result)
        print(entry['id'],row.get('default',{}).get('status',row.get('harness_error')),row.get('all_rules',{}).get('findings'),flush=True)
    result['finished_at']=datetime.now(timezone.utc).isoformat();result['analyzer_unchanged']=sha(binary.read_bytes())==binary_hash
    result['harness_complete']=result['analyzer_unchanged'] and all(not r.get('harness_error') and all(r.get(mode,{}).get('status') != 'execution_failed' for mode in ('default','all_rules','verified')) for r in result['projects'])
    save(args.output_dir/'summary.json',result)
    return 0 if result['harness_complete'] else 2

def main():
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='action',required=True)
    p=sub.add_parser('discover');p.add_argument('--output',type=Path,required=True);p.add_argument('--stars',type=int,default=12);p.add_argument('--downloads',type=int,default=12)
    p=sub.add_parser('run');p.add_argument('--manifest',type=Path,required=True);p.add_argument('--work-dir',type=Path,required=True);p.add_argument('--analyzer',type=Path,required=True);p.add_argument('--output-dir',type=Path,required=True);p.add_argument('--toolchain',type=Path);p.add_argument('--verify-per-cohort',type=int,default=3);p.add_argument('--timeout',type=int,default=120)
    args=parser.parse_args()
    if args.action=='discover':
        if not 1<=args.stars<=100 or not 1<=args.downloads<=12:parser.error('stars 1..100; homepage downloads 1..12')
        discover(args);return 0
    if args.timeout<=0 or args.verify_per_cohort<0:parser.error('positive timeout and nonnegative verification sample size required')
    return run(args)

if __name__=='__main__':raise SystemExit(main())
