#!/usr/bin/env python3
"""Production CLI acceptance for the explicitly scoped native mocket analysis.

ANALYZER: native moon-audit executable; PROJECT_TOOLCHAIN: target MoonBit home;
MODEL_CORPUS: reviewed mocket checkout/copy with populated frozen .mooncakes.
Only isolated temporary consumers are modified. Linux additionally exercises
worker address-space containment and process-tree timeout cleanup.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'experiments/security_chain'))
from validate_mocket import fingerprint, IGNORED

HINT = 'pub fn weak_escape(value : String) -> String { value.replace(old="<", new="&lt;") }\n'
POSITIVE = '''fn relay(value : String) -> String { value }
pub fn install(app : @mocket.Mocket) -> Unit {
  app.get("/raw", event => {
    let value = event.req.query().get("q").unwrap_or("")
    @mocket.html(relay(value))
  })
  app.get("/safe", event => {
    let value = event.req.query().get("q").unwrap_or("")
    @mocket.html(@mocket.escape_html(relay(value)))
  })
  app.get("/discarded", event => {
    let value = event.req.query().get("q").unwrap_or("")
    let _discarded = @mocket.html(relay(value))
    @mocket.html("constant")
  })
  app.get("/overwritten", event => {
    let value = event.req.query().get("q").unwrap_or("")
    let mut response = @mocket.html(relay(value))
    response = @mocket.html("replacement")
    response
  })
}
'''
SAFE = '''pub fn install(app : @mocket.Mocket) -> Unit {
  app.get("/safe", event => {
    let value = event.req.query().get("q").unwrap_or("")
    @mocket.html(@mocket.escape_html(value))
  })
}
'''
UNKNOWN = '''pub fn unknown(app : @mocket.Mocket) -> Unit {
  app.get("/unknown", event => {
    let value = event.req.query().get("q").unwrap_or("")
    @mocket.html(if value == "x" { "" } else { value })
  })
}
'''
BUDGET = '''fn spin(value : String) -> String { spin(value) }
fn twice(value : String) -> String { "\\{value}\\{value}" }
pub fn install(app : @mocket.Mocket) -> Unit {
  app.get("/recursive", event => {
    let value = event.req.query().get("q").unwrap_or("")
    @mocket.html(spin(value))
  })
  app.get("/doubling", event => {
    let value = event.req.query().get("q").unwrap_or("")
''' + '\n'.join(f'    let v{i} = twice({"value" if i == 0 else "v"+str(i-1)})' for i in range(30)) + '''
    @mocket.html(v29)
  })
}
'''
SEMANTIC_ID = 'CWE-79/mocket-query-html'
HINT_ID = 'CWE-116/replace-escaping'


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def canonical(value, roots):
    if isinstance(value, dict):
        return {k: canonical(v, roots) for k,v in value.items()}
    if isinstance(value, list):
        return [canonical(v, roots) for v in value]
    if isinstance(value, str):
        for root in roots:
            value = value.replace(str(root), '<PROJECT>')
    return value


def active_process(pid):
    status = Path(f'/proc/{pid}/status')
    if status.exists():
        return '\nState:\tZ' not in status.read_text()
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


class Acceptance:
    def __init__(self, args, temporary):
        self.args, self.temporary = args, temporary
        self.source, self.home = args.corpus.resolve(), args.toolchain.resolve()
        self.original_analyzer = args.analyzer.resolve()
        self.analyzer = temporary / ('moon-audit.exe' if os.name == 'nt' else 'moon-audit')
        shutil.copy2(self.original_analyzer, self.analyzer)
        self.record = {'schema':'moon-audit.production-semantic-acceptance.v1',
            'scope':'mocket-get-callbacks','platform':sys.platform,
            'analyzer':str(self.original_analyzer),'analyzer_sha256':hashlib.sha256(self.analyzer.read_bytes()).hexdigest(),
            'project_toolchain':str(self.home),'cases':[],'runs':[],
            'limits':['Acceptance is for the declared callback scope, not project-wide security or browser exploitability.',
                      'GNU time peak RSS is the reported peak for the invocation and waited-for descendants, not a sum of concurrent processes.',
                      'Linux resource-failure injections do not replace actual Windows/macOS platform testing.']}
        baseline = json.loads((ROOT/'experiments/security_chain/mocket-runtime-2026-09-25.json').read_text())
        require(fingerprint(self.source, exclude_dependencies=True)['sha256'] == baseline['source_fingerprint']['sha256'], 'mocket source fingerprint differs')
        for module, expected in baseline['dependency_fingerprints'].items():
            require(fingerprint(self.source/'.mooncakes'/module)['sha256'] == expected['sha256'], f'dependency changed: {module}')
        self.record['model_source_fingerprint'] = baseline['source_fingerprint']['sha256']
        self.record['dependency_fingerprints'] = {k:v['sha256'] for k,v in baseline['dependency_fingerprints'].items()}
        self.project = temporary/'consumer'
        self.prepare(self.project)
        self.source_file = self.project/'probe.mbt'
        self.hint_file = self.project/'hint.mbt'
        self.source_file.write_text(POSITIVE)
        self.hint_file.write_text(HINT)

    def prepare(self, project):
        project.mkdir()
        shutil.copytree(self.source/'.mooncakes',project/'.mooncakes',ignore=shutil.ignore_patterns(*IGNORED))
        shutil.copytree(self.source,project/'.mooncakes/oboard/mocket',ignore=shutil.ignore_patterns(*IGNORED,'.mooncakes'))
        (project/'moon.mod').write_text('name = "acceptance/semantic"\nimport { "oboard/mocket@0.9.1" }\npreferred_target = "native"\n')
        (project/'moon.pkg').write_text('import { "oboard/mocket" }\nsupported_targets = "native"\n')

    def cli(self, name, *, fmt='json', extra=(), project=None, wrapper=None, subcommand=None, scoped=True, measure=False):
        project = project or self.project
        command = [str(self.analyzer)]
        if subcommand: command.append(subcommand)
        if scoped:
            command += ['--analysis','semantic','--verify-project','--semantic-scope','mocket-get-callbacks']
        command += ['--project-moon',str(wrapper)] if wrapper else ['--project-toolchain',str(self.home)]
        command += ['--format',fmt,*map(str,extra),str(project)]
        executed = command
        rss_file = self.temporary/(name+'.time')
        if measure and Path('/usr/bin/time').is_file() and sys.platform.startswith('linux'):
            executed = ['/usr/bin/time','-v','-o',str(rss_file),*command]
        started=time.monotonic()
        response=subprocess.run(executed,cwd=ROOT,text=True,capture_output=True,timeout=180)
        entry={'name':name,'command':command,'seconds':round(time.monotonic()-started,3),
               'exit_code':response.returncode,'stdout_sha256':hashlib.sha256(response.stdout.encode()).hexdigest(),'stderr':response.stderr}
        if rss_file.exists():
            timing=rss_file.read_text()
            peak=re.search(r'Maximum resident set size \(kbytes\): (\d+)',timing)
            entry['peak_rss_kib']=int(peak.group(1)) if peak else None
            entry['gnu_time']=timing
        report=None
        if fmt in {'json','sarif'}:
            try: report=json.loads(response.stdout)
            except ValueError: pass
        stored = json.loads(json.dumps(report)) if report is not None else response.stdout
        if isinstance(stored, dict):
            verification = stored.get('project_verification')
            if isinstance(verification, dict) and isinstance(verification.get('snapshot_sha256'), dict):
                snapshot = verification.pop('snapshot_sha256')
                verification['snapshot_file_count'] = len(snapshot)
                verification['snapshot_ledger_sha256'] = hashlib.sha256(json.dumps(snapshot,sort_keys=True).encode()).hexdigest()
        entry['report']=stored
        self.record['runs'].append(entry)
        return response.returncode,report,response.stdout

    def case(self,name,action):
        try:
            action()
            self.record['cases'].append({'name':name,'passed':True})
            print('PASS '+name,flush=True)
        except Exception as error:
            self.record['cases'].append({'name':name,'passed':False,'error':str(error)})
            raise

    def complete(self,code,report,expected_code=0):
        require(code==expected_code, f'exit {code}, expected {expected_code}; inspect recorded run')
        require(isinstance(report,dict) and not report['errors'],'complete report has errors; inspect recorded run')
        semantic=report['semantic_analysis']
        require(semantic['status']=='complete_within_declared_scope',f'wrong semantic status {semantic}')
        require(semantic['coverage_status']=='explicit_callback_scope','scope missing')
        return [f for f in report['findings'] if f['rule_id']==SEMANTIC_ID]

    def incomplete(self,code,report,*,syntax=True):
        require(code==2 and isinstance(report,dict) and report.get('errors'),f'failure not disclosed: exit={code}; inspect recorded run')
        if syntax:
            require(any(f['rule_id']==HINT_ID and f['evidence']=='syntax_hint' for f in report['findings']),'syntax finding lost on semantic failure')
        return report.get('semantic_analysis')

    def wrapper(self,name,action):
        target=self.temporary/(name+'-moon')
        marker=self.temporary/(name+'-marker.json')
        body=f'''#!{sys.executable}
import os,sys,json,subprocess,time,resource
from pathlib import Path
home={str(self.home)!r}
os.environ['MOON_HOME']=home
os.environ['PATH']=home+'/bin'+os.pathsep+os.environ.get('PATH','')
if len(sys.argv)>1 and sys.argv[1]=='ide':
    marker=Path({str(marker)!r})
{action}
os.execv(home+'/bin/moon',[home+'/bin/moon',*sys.argv[1:]])
'''
        target.write_text(body);target.chmod(0o755)
        return target,marker

    def run(self):
        def cold_hot():
            c,cold,_=self.cli('cold_positive',measure=True)
            findings=self.complete(c,cold)
            require(len(findings)==1 and findings[0]['evidence']=='verified_dataflow','expected one verified path')
            require(len(findings[0]['dataflow'])>=3,'missing propagation trace')
            require('does not establish browser exploitability' in findings[0]['message'],'missing conditional claim')
            require(any(f['rule_id']==HINT_ID for f in cold['findings']),'default syntax rule missing')
            c,hot,_=self.cli('hot_positive',measure=True)
            self.complete(c,hot)
            require(canonical(cold,[self.project])==canonical(hot,[self.project]),'cold/hot reports differ')
            self.positive=cold
        self.case('cold_hot_json_consistency_and_default_rules',cold_hot)
        if os.name == 'nt':
            def windows_aliases():
                import ctypes
                from ctypes import wintypes
                kernel=ctypes.WinDLL('kernel32',use_last_error=True)
                def spelling(name,path):
                    api=getattr(kernel,name)
                    api.argtypes=[wintypes.LPCWSTR,wintypes.LPWSTR,wintypes.DWORD]
                    api.restype=wintypes.DWORD
                    buffer=ctypes.create_unicode_buffer(32768)
                    length=api(str(path),buffer,len(buffer))
                    require(0<length<len(buffer),name+' failed: '+str(ctypes.get_last_error()))
                    return buffer.value
                long_name=spelling('GetLongPathNameW',self.project)
                short_name=spelling('GetShortPathNameW',self.project)
                variants={'long':long_name,'short':short_name,'different_case':long_name.swapcase()}
                self.record['windows_path_aliases']=variants
                expected=sorted((f['rule_id'],f['fingerprint'],f['evidence']) for f in self.positive['findings'])
                for name,path in variants.items():
                    require(Path(path).is_dir(),'path alias must refer to the existing project')
                    c,r,_=self.cli('windows_'+name,project=Path(path))
                    self.complete(c,r)
                    actual=sorted((f['rule_id'],f['fingerprint'],f['evidence']) for f in r['findings'])
                    require(actual==expected,'Windows alias changed findings or local helper identity')
                    require(len(r['semantic_analysis']['routes'])==4,'Windows alias changed callback coverage')
            self.case('windows_long_short_and_case_paths_share_binding_identity',windows_aliases)
        def fail_one():
            self.hint_file.unlink()
            try:
                c,r,_=self.cli('fail_on_error',extra=['--fail-on-error'])
                findings=self.complete(c,r,1)
                require(len(findings)==1 and all(f['rule_id']==SEMANTIC_ID for f in r['findings']), 'exit 1 must be caused by semantic evidence alone')
            finally:
                self.hint_file.write_text(HINT)
        self.case('exit_1_requires_findings_policy',fail_one)
        def sarif():
            c,r,_=self.cli('sarif_positive',fmt='sarif')
            require(c==0 and r['version']=='2.1.0','invalid SARIF')
            run=r['runs'][0]
            require(run['invocations'][0]['executionSuccessful'] is True,'SARIF successful invocation missing')
            findings=[f for f in run['results'] if f['ruleId']==SEMANTIC_ID]
            require(len(findings)==1 and findings[0]['properties']['evidence']=='verified_dataflow','SARIF evidence missing')
            require(findings[0]['properties']['dataflow']==[f for f in self.positive['findings'] if f['rule_id']==SEMANTIC_ID][0]['dataflow'],'SARIF trace differs')
            require(run['properties']['semantic_analysis']['coverage_status']=='explicit_callback_scope','SARIF scope missing')
        self.case('sarif_preserves_evidence_and_scope',sarif)
        def text():
            c,_,stdout=self.cli('text_positive',fmt='text')
            require(c==0 and SEMANTIC_ID in stdout and 'Semantic scope:' in stdout and 'semantic-status: complete_within_declared_scope' in stdout,'text lacks semantic findings/scope')
        self.case('text_preserves_semantic_scope',text)
        baseline=self.temporary/'baseline.json'
        def baseline_roundtrip():
            c,_,stdout=self.cli('baseline_generate',subcommand='generate-baseline',extra=['--output',baseline])
            require(c==0 and baseline.exists(),'baseline generation failed '+stdout)
            entries=json.loads(baseline.read_text())
            require({e['rule_id'] for e in entries}=={SEMANTIC_ID,HINT_ID},'baseline omits or conflates evidence rule identities')
            require(all(e['path_scope']=='project' and not Path(e['file']).is_absolute() for e in entries),'baseline is checkout-specific')
            self.source_file.write_text('\n\n'+POSITIVE)
            c,r,_=self.cli('baseline_line_move',extra=['--baseline',baseline,'--fail-on-error'])
            self.complete(c,r)
            require(not r['findings'],'line movement broke baseline')
            copy=self.temporary/'new-checkout'
            shutil.copytree(self.project,copy,ignore=shutil.ignore_patterns('_build'))
            c,r,_=self.cli('baseline_new_checkout',project=copy,extra=['--baseline',baseline])
            self.complete(c,r)
            require(not r['findings'],'new checkout broke baseline')
            self.source_file.write_text(POSITIVE)
        self.case('baseline_survives_lines_and_checkout',baseline_roundtrip)
        def failure_baseline():
            self.source_file.write_text(POSITIVE+UNKNOWN)
            c,r,_=self.cli('unknown_with_baseline',extra=['--baseline',baseline,'--fail-on-error'])
            self.incomplete(c,r,syntax=False)
            require(not r['findings'],'known findings should be suppressed while failure remains')
            before=baseline.read_bytes()
            c,_,_=self.cli('baseline_cannot_replace_after_failure',subcommand='generate-baseline',extra=['--output',baseline])
            require(c==2 and baseline.read_bytes()==before,'incomplete generation replaced baseline')
            c,r,_=self.cli('unknown_sarif',fmt='sarif')
            require(c==2 and r['runs'][0]['invocations'][0]['executionSuccessful'] is False,'SARIF failure marked successful')
            require(any(f['ruleId']==HINT_ID for f in r['runs'][0]['results']),'SARIF failure lost syntax finding')
            self.source_file.write_text(POSITIVE)
        self.case('baseline_never_clears_incomplete_or_replaces_file',failure_baseline)
        def legacy_syntax_is_not_semantic_support():
            for name, expression in [
                ('loop', 'loop value { x => x }'),
                ('try_question', 'try? might_fail(value)'),
            ]:
                source = 'fn might_fail(value : String) -> String raise { value }\n'
                source += 'pub fn install(app : @mocket.Mocket) -> Unit {\n'
                source += '  app.get("/legacy", event => {\n'
                source += '    let value = event.req.query().get("q").unwrap_or("")\n'
                source += '    let _unsupported = ' + expression + '\n'
                source += '    @mocket.html("constant")\n  })\n}\n'
                self.source_file.write_text(source)
                code, report, _ = self.cli('legacy_' + name)
                semantic = self.incomplete(code, report)
                require(report['project_verification']['status'] == 'compiler_verified',
                        'legacy test did not pass compiler and parser verification')
                require('unsupported_legacy_' + name in json.dumps(semantic),
                        'legacy syntax was not explicitly rejected by semantic lowering')
                require(not any(f['rule_id'] == SEMANTIC_ID for f in report['findings']),
                        'unmodeled legacy syntax produced verified dataflow')
            self.source_file.write_text(POSITIVE)
        self.case('legacy_syntax_is_not_semantic_support', legacy_syntax_is_not_semantic_support)
        def budgets():
            self.source_file.write_text(BUDGET)
            c,r,_=self.cli('ir_budgets',measure=True)
            semantic=self.incomplete(c,r)
            reasons=[x.get('result',x).get('reason','') for x in semantic['routes']]
            require(len(reasons)==2 and all(x=='incomplete_budget' for x in reasons),'recursive/doubling did not exhaust conservatively')
            self.source_file.write_text(POSITIVE)
        self.case('recursion_and_expansion_budgets',budgets)
        def model_changes():
            for label,relative in [('model','.mooncakes/oboard/mocket/README.md'),('dependency','.mooncakes/oboard/mimetype/README.md')]:
                target=self.project/relative;original=target.read_bytes()
                target.write_bytes(original+b'\nacceptance fingerprint mutation\n')
                try:
                    c,r,_=self.cli(label+'_mismatch')
                    semantic=self.incomplete(c,r)
                    require(semantic['errors'] and not semantic['routes'],'mismatched model silently accepted')
                finally:target.write_bytes(original)
        self.case('library_and_dependency_mismatch_preserve_syntax',model_changes)
        def no_candidates():
            self.source_file.write_text('pub fn install(app : @mocket.Mocket) -> Unit { @mocket.Mocket::get(app,"/explicit", _ => @mocket.html("constant")) }\n')
            c,r,_=self.cli('unsupported_registration')
            semantic=self.incomplete(c,r)
            require(not semantic['routes'],'explicit unsupported call treated as supported')
            self.source_file.write_text(POSITIVE)
        self.case('zero_supported_candidates_is_incomplete',no_candidates)
        def mixed_registration():
            self.source_file.write_text(POSITIVE + 'pub fn explicit(app : @mocket.Mocket) -> Unit { @mocket.Mocket::get(app,"/explicit", event => @mocket.html(event.req.query().get("q").unwrap_or(""))) }\n')
            c,r,_=self.cli('mixed_unsupported_registration')
            semantic=self.incomplete(c,r)
            require(semantic['routes'],'supported callbacks disappeared in mixed registration project')
            require(semantic['errors'],'unsupported explicit registration was not disclosed')
            require(any(f['rule_id']==SEMANTIC_ID for f in r['findings']),'known dataflow discarded by unsupported registration')
            self.source_file.write_text(POSITIVE)
        self.case('mixed_registration_discloses_gap_and_keeps_known_paths',mixed_registration)
        def safe_zero():
            self.source_file.write_text(SAFE);self.hint_file.unlink()
            c,r,_=self.cli('safe_zero',extra=['--fail-on-error'])
            require(not self.complete(c,r) and not r['findings'],'safe-only sample produces finding/failure')
            self.source_file.write_text(POSITIVE);self.hint_file.write_text(HINT)
        self.case('complete_safe_zero_findings_exit_0',safe_zero)
        def explicit_contract():
            for name, extra in [
                ('missing_scope', ['--analysis','semantic','--verify-project']),
                ('missing_verification', ['--analysis','semantic','--semantic-scope','mocket-get-callbacks']),
                ('unknown_scope', ['--analysis','semantic','--verify-project','--semantic-scope','all']),
            ]:
                c,_,_=self.cli(name,scoped=False,extra=extra)
                require(c==2,name+' was not rejected')
            c,_,_=self.cli('unsupported_backend',extra=['--target','js'])
            require(c==2,'semantic model accepted unsupported backend')
        self.case('semantic_requires_explicit_scope_verification_and_backend',explicit_contract)
        if sys.platform.startswith('linux'):
            def binding_error():
                wrapper,marker=self.wrapper('binding_error',"    marker.write_text(json.dumps({'reached':True}))\n    sys.exit(37)")
                c,r,_=self.cli('binding_failure',wrapper=wrapper)
                self.incomplete(c,r)
                require(marker.exists(),'failure injector not reached')
            self.case('binding_subprocess_failure_preserves_syntax',binding_error)
            def memory():
                wrapper,marker=self.wrapper('memory',"    limit=resource.getrlimit(resource.RLIMIT_AS)[0]\n    marker.write_text(json.dumps({'address_space_limit':limit}))\n    try:\n        data=bytearray(2300*1024*1024)\n    except MemoryError:\n        marker.write_text(json.dumps({'address_space_limit':limit,'allocation_blocked':True}))\n        sys.exit(42)\n    sys.exit(43)")
                c,r,_=self.cli('worker_memory',wrapper=wrapper,measure=True)
                self.incomplete(c,r)
                limits=json.loads(marker.read_text())
                require(0<limits['address_space_limit']<=2048*1024*1024,'worker memory cap not inherited')
                require(limits.get('allocation_blocked') is True,'oversized allocation was not actually rejected')
                self.record['memory_injection']=limits
            self.case('worker_address_space_cap_and_syntax_survival',memory)
            def timeout():
                wrapper,marker=self.wrapper('timeout',"    child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(120)'])\n    marker.write_text(json.dumps({'pid':child.pid}))\n    time.sleep(120)")
                c,r,_=self.cli('worker_timeout',wrapper=wrapper,extra=['--timeout-seconds','3'],measure=True)
                self.incomplete(c,r)
                require(marker.exists(),'timeout occurred before semantic IDE injection')
                pid=json.loads(marker.read_text())['pid']
                deadline=time.monotonic()+3
                while active_process(pid) and time.monotonic()<deadline:time.sleep(.05)
                live=active_process(pid)
                self.record['timeout_injection']={'child_pid':pid,'child_live_after_grace':live}
                if live:
                    topology=subprocess.run(['ps','-eo','pid,ppid,pgid,sid,stat,args'],text=True,capture_output=True).stdout
                    self.record['timeout_injection']['remaining_processes']=[line for line in topology.splitlines() if str(self.temporary) in line or str(pid) in line]
                    group=os.getpgid(pid)
                    if group!=os.getpgrp():
                        os.killpg(group,signal.SIGKILL)
                require(not live,'semantic timeout leaked a live descendant')
            self.case('worker_timeout_cleans_descendants_and_keeps_syntax',timeout)
        else:
            self.record['platform_resource_injections']='not executed; Linux-only harness'
        self.record['status']='passed'


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--analyzer',type=Path,default=os.environ.get('ANALYZER',ROOT/'_build/native/debug/build/src/main/main.exe'))
    p.add_argument('--toolchain',type=Path,default=os.environ.get('PROJECT_TOOLCHAIN','/tmp/moon-audit-upgrade-20260922/toolchain'))
    p.add_argument('--corpus',type=Path,default=os.environ.get('MODEL_CORPUS','/tmp/moon-audit-upgrade-20260922/compiled-corpus-mocket'))
    p.add_argument('--output',type=Path,default=ROOT/'docs/metrics/semantic-production-acceptance-2026-09-25.json')
    args=p.parse_args()
    report=None
    try:
        with tempfile.TemporaryDirectory(prefix='moon-audit-semantic-acceptance-') as tmp:
            acceptance=Acceptance(args,Path(tmp));report=acceptance.record
            acceptance.run()
    except Exception as error:
        if report is None:report={'status':'failed','error':str(error)}
        else:report['status']='failed';report['error']=str(error)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n')
    print(json.dumps({'status':report['status'],'cases':len(report.get('cases',[])),'output':str(args.output),'error':report.get('error')}))
    return 0 if report['status']=='passed' else 1

if __name__=='__main__':raise SystemExit(main())
