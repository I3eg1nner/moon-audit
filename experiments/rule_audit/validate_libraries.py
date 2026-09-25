#!/usr/bin/env python3
"""Compile real pinned library calls; keep these separate from synthetic shapes."""
import argparse, hashlib, json, pathlib, re, shutil, subprocess, tempfile
HERE=pathlib.Path(__file__).resolve().parent

def run(argv,cwd):
    p=subprocess.run(argv,cwd=cwd,text=True,capture_output=True,timeout=240)
    return dict(exit_code=p.returncode,stdout=p.stdout,stderr=p.stderr)

def summarize_compiler(result):
    stderr=result['stderr']
    blocks=[]
    for match in re.finditer(r'Error: \[',stderr):
        end=stderr.find('───╯',match.start())
        blocks.append(stderr[match.start():end+4] if end!=-1 else stderr[match.start():match.start()+1000])
    return dict(exit_code=result['exit_code'],stdout=result['stdout'],stderr_sha256=hashlib.sha256(stderr.encode()).hexdigest(),warning_count=stderr.count('Warning: ['),error_diagnostics=blocks)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--moon-wrapper',type=pathlib.Path,required=True)
    p.add_argument('--analyzer',type=pathlib.Path,required=True)
    p.add_argument('--mocket',type=pathlib.Path,required=True)
    p.add_argument('--crescent',type=pathlib.Path,required=True)
    p.add_argument('--cmark',type=pathlib.Path)
    p.add_argument('--output',type=pathlib.Path,required=True)
    a=p.parse_args(); allresults=[]; libraries={}
    specs=[('mocket',a.mocket,'rule_probe','import { "oboard/mocket", "oboard/mocket/cors" }',[
      ('cookie_missing','CWE-614/cookie-attrs','pub fn probe(res : @mocket.HttpResponse) -> Unit { res.set_cookie("token", "value") }',1),
      ('cookie_true','CWE-614/cookie-attrs','pub fn probe(res : @mocket.HttpResponse) -> Unit { res.set_cookie("token", "value", http_only=true, secure=true, same_site=Strict) }',0),
      ('cookie_false','CWE-614/cookie-attrs','pub fn probe(res : @mocket.HttpResponse) -> Unit { res.set_cookie("token", "value", http_only=false, secure=false, same_site=SameSiteNone) }',0),
      ('html_dynamic','CWE-79/template-injection','pub fn probe(input : String) -> &@mocket.Responder { @mocket.html("<p>\\{input}</p>") }',1),
      ('html_constant','CWE-79/template-injection','pub fn probe() -> &@mocket.Responder { @mocket.html("<p>constant</p>") }',0),
      ('html_trusted_dynamic','CWE-79/template-injection','pub fn probe() -> &@mocket.Responder { let input = "constant"; @mocket.html("<p>\\{input}</p>") }',1),
      ('cors_wildcard','CWE-942/cors-credentials','pub fn probe() -> @mocket.Middleware { @cors.handle_cors(credentials=true) }',1),
      ('cors_explicit','CWE-942/cors-credentials','pub fn probe() -> @mocket.Middleware { @cors.handle_cors(origin="https://example.com", credentials=true) }',0),
    ]),('crescent',a.crescent,'rule_probe','import { "bobzhang/crescent", "bobzhang/crescent/core" }',[
      ('body_unbounded','CWE-770/no-body-limit','pub async fn probe(app : @crescent.App) -> Unit { app.post("/", _ => @core.html("constant")); app.serve(port=0) }',1),
      ('body_bounded','CWE-770/no-body-limit','pub async fn probe(app : @crescent.App) -> Unit { app.post("/", _ => @core.html("constant")); app.serve(port=0, options=@crescent.NativeServeOptions(max_request_body_bytes=1024)) }',1),
      ('header_dynamic','CWE-113/crlf-injection','pub fn probe(res : @core.HttpResponse, input : String) -> @core.HttpResponse { res.header("X-Value", input) }',0),
      ('header_constant','CWE-113/crlf-injection','pub fn probe(res : @core.HttpResponse) -> @core.HttpResponse { res.header("X-Value", "constant") }',0),
    ])]
    if a.cmark:
        specs.append(('cmark',a.cmark,'src/rule_probe','import { "moonbit-community/cmark/cmark_html" @html }',[
          ('render_unsafe','CWE-79/cmark-unsafe','pub fn probe(input : String) -> String raise { @html.render(input, safe=false) }',1),
          ('render_safe','CWE-79/cmark-unsafe','pub fn probe(input : String) -> String raise { @html.render(input, safe=true) }',0),
          ('render_default','CWE-79/cmark-unsafe','pub fn probe(input : String) -> String raise { @html.render(input) }',0),
        ]))
    with tempfile.TemporaryDirectory(prefix='moon-library-rule-audit-') as tmp:
        for name,source,pkg,manifest,cases in specs:
            root=pathlib.Path(tmp)/name
            shutil.copytree(source,root,ignore=shutil.ignore_patterns('.git','_build','.recovery'))
            probe=root/pkg; probe.mkdir(exist_ok=True)
            (probe/'moon.pkg').write_text(manifest+'\n')
            files={str(f.relative_to(source)):hashlib.sha256(f.read_bytes()).hexdigest() for f in source.rglob('*.mbt') if not any(x in f.parts for x in ['_build','.git','.mooncakes'])}
            libraries[name]=dict(source_path=str(source),manifest=(source/'moon.mod').read_text(),source_mbt_sha256=files)
            snapshots=HERE/'real_fixtures'/name; snapshots.mkdir(parents=True,exist_ok=True)
            (snapshots/'moon.pkg.txt').write_text(manifest+'\n')
            for kind,rule,code,expect in cases:
                (snapshots/(kind+'.mbt.txt')).write_text(code+'\n')
                (probe/'probe.mbt').write_text(code+'\n')
                compiler=run([str(a.moon_wrapper.resolve()),'moon','check','--frozen','--target','native',pkg],root)
                scan=run([str(a.analyzer.resolve()),str(probe),'--rule',rule,'--format','json','--quiet'],root)
                try:
                    data=json.loads(scan['stdout']); findings=[x for x in data['findings'] if x.get('rule_id')==rule]; count=len(findings); errors=data.get('errors',[])
                except (ValueError,KeyError): count=None; errors=['invalid_report']
                passed=compiler['exit_code']==0 and not errors and count==expect
                allresults.append(dict(library=name,kind=kind,rule=rule,fixture_sha256=hashlib.sha256((code+'\n').encode()).hexdigest(),compiler=summarize_compiler(compiler),verification_status="compiler_verified" if compiler["exit_code"]==0 else "compiler_rejected_unverified",scanner_exit=scan['exit_code'],findings=count,expected_findings=expect,errors=errors,passed=passed))
                print(name,kind,'PASS' if passed else 'FAIL',compiler['exit_code'],count,flush=True)
    record=dict(schema='moon-audit.real-library-rule-audit.v1',analyzer_sha256=hashlib.sha256(a.analyzer.read_bytes()).hexdigest(),toolchain=run([str(a.moon_wrapper.resolve()),'moon','version','--all'],HERE),purpose='Real library compile and scanner behavior; no exploitability claim.',libraries=libraries,cases=allresults,passed=sum(x['passed'] for x in allresults),total=len(allresults))
    a.output.write_text(json.dumps(record,indent=2)+'\n')
    return 0 if record['passed']==record['total'] else 1
if __name__=='__main__': raise SystemExit(main())
