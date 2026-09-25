#!/usr/bin/env python3
"""Verify exact try! AST and normal/terminating execution boundaries."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import shutil
import subprocess
import tempfile
import time
from validate import HERE, fingerprint


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--prepared-cmark', type=Path, required=True)
    p.add_argument('--toolchain', type=Path, required=True)
    p.add_argument('--ast-exporter', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    source, home, exporter = args.prepared_cmark.resolve(), args.toolchain.resolve(), args.ast_exporter.resolve()
    baseline = json.loads((HERE/'cmark-model-2026-09-25.json').read_text())
    assert fingerprint(source)['sha256'] == baseline['source_fingerprint']['sha256']
    for dependency in baseline['dependencies']:
        assert fingerprint(source/'.mooncakes'/dependency['module'])['sha256'] == dependency['source_fingerprint']['sha256']
    env = dict(os.environ, MOON_HOME=str(home), PATH=str(home/'bin')+os.pathsep+os.environ.get('PATH',''))
    result = {'schema':'moon-audit.cmark-callmode.v1','production_ready':False,'commands':[],
              'source_fingerprint':baseline['source_fingerprint']['sha256'],
              'exporter_sha256':hashlib.sha256(exporter.read_bytes()).hexdigest(),
              'fixture_sha256':{x.name:hashlib.sha256(x.read_bytes()).hexdigest() for x in HERE.glob('callmode_*.txt')}}
    with tempfile.TemporaryDirectory(prefix='moon-audit-cmark-callmode-') as temp:
        root=Path(temp)
        shutil.copytree(source/'.mooncakes',root/'.mooncakes')
        shutil.copytree(source,root/'.mooncakes/moonbit-community/cmark',ignore=shutil.ignore_patterns('.mooncakes','_build','.git','.moon-audit-cache'))
        (root/'moon.mod').write_text('name = "audit/cmark-callmode"\nimport { "moonbit-community/cmark@0.4.8" }\npreferred_target = "native"\n')
        shutil.copyfile(HERE/'moon.pkg.txt',root/'moon.pkg')
        def run(command):
            started=time.monotonic()
            response=subprocess.run(command,cwd=root,env=env,text=True,capture_output=True,timeout=90,
                preexec_fn=lambda:resource.setrlimit(resource.RLIMIT_CORE,(0,0)))
            item={'command':command,'exit_code':response.returncode,'stdout':response.stdout,'stderr':response.stderr,'seconds':round(time.monotonic()-started,4)}
            result['commands'].append(item)
            return item
        moon=[str(home/'bin/moon')]
        result['toolchain']=run(moon+['version','--all'])['stdout']
        shutil.copyfile(HERE/'callmode_legacy.mbt.txt',root/'probe.mbt')
        legacy=run(moon+['check','--frozen','--target','native','--diagnostic-limit','5'])
        result['legacy_render_bang_rejected']=legacy['exit_code']!=0 and '3002' in legacy['stderr']+legacy['stdout']
        shutil.copyfile(HERE/'callmode_valid.mbt.txt',root/'probe.mbt')
        shutil.copyfile(HERE/'callmode_test.mbt.txt',root/'probe_wbtest.mbt')
        good=run(moon+['check','--frozen','--target','native','--diagnostic-limit','3'])
        tests=run(moon+['test','--frozen','--target','native','probe_wbtest.mbt','--diagnostic-limit','3'])
        result['try_bang_compiles_and_runs']=good['exit_code']==0 and tests['exit_code']==0 and 'Total tests: 2, passed: 2, failed: 0.' in tests['stdout']+tests['stderr']
        ast=run([str(exporter),str(root/'probe.mbt')])
        tree=json.loads(ast['stdout']) if ast['exit_code']==0 else []
        operators=[]
        def walk(value):
            if isinstance(value,dict):
                if value.get('kind')=='Expr::TryOperator':
                    operators.append(value)
                for child in value.values():walk(child)
            elif isinstance(value,list):
                for child in value:walk(child)
        walk(tree)
        result['try_operator_nodes']=operators
        result['expected_ast_verified']=len(operators)==2 and all(x['children']['kind']['kind']=='TryOperatorKind::Exclamation' and x['children']['body']['kind']=='Expr::Apply' and x['children']['body']['children']['attr']['kind']=='ApplyAttr::NoAttr' for x in operators)
        abort=root/'abort_case'; abort.mkdir()
        (abort/'moon.pkg').write_text('pkgtype(kind: "executable")\nsupported_targets = "native"\n')
        shutil.copyfile(HERE/'callmode_abort.mbt.txt',abort/'main.mbt')
        check_abort=run(moon+['check','--frozen','--target','native','abort_case','--diagnostic-limit','3'])
        aborted=run(moon+['run','--frozen','--target','native','abort_case'])
        result['try_bang_error_terminates']=check_abort['exit_code']==0 and aborted['exit_code']!=0 and 'BEFORE_TRY' in aborted['stdout'] and 'AFTER_TRY' not in aborted['stdout']
    passed=all(result[key] for key in ['legacy_render_bang_rejected','try_bang_compiles_and_runs','expected_ast_verified','try_bang_error_terminates'])
    result['status']='verified' if passed else 'failed'
    result['limits']=['Error termination uses a controlled raising helper; no failing cmark input is claimed.', 'This probes nonraising callbacks, not mocket registration or production lowering.']
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n')
    print(json.dumps({key:result[key] for key in ['status','legacy_render_bang_rejected','try_bang_compiles_and_runs','expected_ast_verified','try_bang_error_terminates']}))
    return 0 if passed else 1


if __name__=='__main__':raise SystemExit(main())
