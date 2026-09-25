#!/usr/bin/env python3
"""Verify the second real library through the production CLI and shared IR."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
TEMPLATE = '''fn render(value : String) -> String raise {{ value }}
pub fn install(app : @mocket.Mocket) -> Unit {{
  app.get("/{name}", event => {{
    let input = event.req.query().get("q").unwrap_or("")
    {body}
  }})
}}
'''
CASES = {
 'safe_default': ('let output = try! @html.render(input)\n    @mocket.html(output)', 0, 0),
 'safe_explicit': ('let output = try! @html.render(input, safe=true)\n    @mocket.html(output)', 0, 0),
 'unsafe': ('let output = try! @html.render(input, safe=false)\n    @mocket.html(output)', 2, 1),
 'encoded_then_unsafe': ('let output = try! @html.render(@mocket.escape_html(input), safe=false)\n    @mocket.html(output)', 2, 1),
 'safe_in_script': ('let output = try! @html.render(input)\n    @mocket.html("<script>\\{output}</script>")', 2, 1),
 'dynamic_flag': ('let output = try! @html.render(input, safe=(input == "safe"))\n    @mocket.html(output)', 2, 0),
 'safe_attribute': ('let output = try! @html.render(input)\n    @mocket.html("<div title=\\{output}>body</div>")', 2, 1),
 'same_name_render': ('let output = try! render(input)\n    @mocket.html(output)', 2, 0),
 'literal_supported_options': ('let output = try! @html.render(input, safe=true, strict=true, backend_blocks=false)\n    @mocket.html("<div>\\{output}</div>")', 0, 0),
 'unsupported_options': ('let output = try! @html.render(input, strict=false)\n    @mocket.html(output)', 2, 0),
}

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ['mocket','cmark','toolchain','output']:p.add_argument('--'+name,required=True,type=Path)
 p.add_argument('--analyzer',type=Path,default=ROOT/'_build/native/debug/build/src/main/main.exe')
 args=p.parse_args(); records=[]
 with tempfile.TemporaryDirectory(prefix='moon-audit-cmark-production-') as temp:
  analyzer=Path(temp)/args.analyzer.name
  shutil.copy2(args.analyzer.resolve(),analyzer)
  analyzer_sha256=hashlib.sha256(analyzer.read_bytes()).hexdigest()
  work=Path(temp)/'consumer';work.mkdir()
  ignore=shutil.ignore_patterns('.git','_build','.mooncakes','__pycache__')
  shutil.copytree(args.mocket/'.mooncakes',work/'.mooncakes',ignore=shutil.ignore_patterns('_build','.git'))
  shutil.copytree(args.mocket,work/'.mooncakes/oboard/mocket',ignore=ignore)
  shutil.copytree(args.cmark,work/'.mooncakes/moonbit-community/cmark',ignore=ignore)
  for name in ['casefold','charclass','ucd']:
   shutil.copytree(args.cmark/'.mooncakes/moonbit-community'/name,work/'.mooncakes/moonbit-community'/name)
  (work/'moon.mod').write_text('name = "acceptance/cmark"\nimport { "oboard/mocket@0.9.1", "moonbit-community/cmark@0.4.8" }\npreferred_target = "native"\n')
  (work/'moon.pkg').write_text('import { "oboard/mocket", "moonbit-community/cmark/cmark_html" @html }\nsupported_targets = "native"\n')
  def run(name, body, code, count):
   (work/'probe.mbt').write_text(TEMPLATE.format(name=name,body=body))
   command=[str(analyzer),'--analysis','semantic','--semantic-scope','mocket-get-callbacks','--verify-project','--project-toolchain',str(args.toolchain.resolve()),'--format','json',str(work)]
   measured=command
   timing=Path(temp)/'timing.txt'
   if sys.platform.startswith('linux') and Path('/usr/bin/time').exists():measured=['/usr/bin/time','-v','-o',str(timing),*command]
   start=time.monotonic();r=subprocess.run(measured,capture_output=True,text=True,timeout=100);seconds=round(time.monotonic()-start,3)
   report=json.loads(r.stdout);semantic=report.get('semantic_analysis') or {}
   findings=[f for f in report['findings'] if f['rule_id']=='CWE-79/mocket-query-html']
   routes=semantic.get('routes',[])
   checks={
    'exit_code':r.returncode==code,
    'finding_count':len(findings)==count,
    'compiler_verified':report.get('project_verification',{}).get('status')=='compiler_verified',
    'declared_scope':semantic.get('coverage_status')=='explicit_callback_scope',
    'one_route':len(routes)==1,
    'overall_status':semantic.get('status')==('complete_within_declared_scope' if code==0 else 'incomplete'),
    'errors_match_status':bool(report.get('errors'))==(code!=0),
   }
   route=routes[0] if len(routes)==1 else {}
   result=route.get('result',{})
   if code==0:
    checks['complete_without_paths']=result.get('status')=='complete' and result.get('reason')=='' and result.get('source_paths')==[]
   elif count:
    checks['context_incomplete']=result.get('status')=='incomplete' and result.get('reason')=='unsupported_html_context'
    checks['partial_evidence']=all(f.get('evidence')=='partial_dataflow' and len(f.get('dataflow',[]))>=4 for f in findings)
    checks['path_matches_finding']=result.get('source_paths')==[f.get('dataflow') for f in findings]
   else:
    expected='unsupported_markdown_options' if name in ('dynamic_flag','unsupported_options') else 'unsupported_terminating_call'
    checks['frontend_rejection']=route.get('status')=='incomplete' and expected in route.get('reason','')
   passed=all(checks.values())
   peak=None
   if timing.exists():
    match=re.search(r'Maximum resident set size \(kbytes\):\s*(\d+)',timing.read_text())
    if match:peak=int(match[1])
   records.append({'name':name,'passed':passed,'checks':checks,'source':(work/'probe.mbt').read_text(),'command':command,'exit_code':r.returncode,'seconds':seconds,'peak_rss_kib':peak,'report':report,'stderr':r.stderr})
   assert passed,(name,{key:value for key,value in checks.items() if not value},routes)
   return report
  for name,(body,code,count) in CASES.items():run(name,body,code,count)
  for package in ['cmark','casefold','charclass','ucd']:
   target=work/'.mooncakes/moonbit-community'/package/'README.md'
   original=target.read_bytes()
   try:
    target.write_bytes(original+b'\nmodel mutation\n')
    run(package+'_model_mismatch',CASES['safe_default'][0],2,0)
   finally:target.write_bytes(original)
 result={'schema':'moon-audit.cmark-production-acceptance.v1','status':'passed','analyzer':str(args.analyzer.resolve()),'analyzer_sha256':analyzer_sha256,'cases':records,'limits':['Unsafe Markdown has unknown generated HTML context: source path is retained as partial_dataflow and exit 2.','safe=true is a reviewed HTML fragment property, not HTML text encoding or universal sanitizer.','mocket async0.21.0 remains selected; cmark renderer does not import async.','No browser exploitability or registration reachability is proven.']}
 args.output.write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n')
 print(json.dumps({'status':'passed','cases':len(records),'seconds':sum(r['seconds'] for r in records)}))
if __name__=='__main__':main()
