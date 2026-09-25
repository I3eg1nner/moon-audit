#!/usr/bin/env python3
"""Compiler-checked shape/counterexample audit. Synthetic APIs are never real-library proof."""
import argparse, hashlib, json, pathlib, shutil, subprocess, tempfile
HERE = pathlib.Path(__file__).resolve().parent

def case(rule, kind, source, expect, evidence='synthetic_shape', target='native'):
    return dict(rule=rule, kind=kind, source=source, expected_findings=expect, evidence=evidence, target=target)

DUMMY='pub struct Dummy {}\n'
C=[]
def add(rule, danger, safe, shadow, evidence='synthetic_shape', target='native'):
    C.extend([case(rule,'dangerous_shape',danger,1,evidence,target),case(rule,'control_shape',safe,0,evidence,target),case(rule,'same_name_or_semantic_counterexample',shadow,1,'counterexample',target)])
add('CWE-116/replace-escaping',
'pub fn probe(input : String) -> String { input.replace(old="<", new="&lt;") }',
'pub fn probe(input : String) -> String { input.replace_all(old="<", new="&lt;") }',
DUMMY+'pub fn Dummy::replace(_self : Dummy, old~ : String, new~ : String) -> String { ignore((old, new)); "constant" }\npub fn probe(input : Dummy) -> String { input.replace(old="<", new="&lt;") }', 'real_builtin')
render='pub fn render(_value : String, safe? : Bool = true) -> String { if safe { "constant" } else { "constant" } }\n'
add('CWE-79/cmark-unsafe', render+'pub fn probe(input : String) -> String { render(input, safe=false) }',render+'pub fn probe(input : String) -> String { render(input, safe=true) }',render+'pub fn probe() -> String { render("constant", safe=false) }')
inner=DUMMY+'pub fn Dummy::inner_html(_self : Dummy, _value : String) -> Unit {}\n'
add('CWE-79/inner-html',inner+'pub fn probe(view : Dummy, input : String) -> Unit { view.inner_html(input) }',inner+'pub fn probe(view : Dummy) -> Unit { view.inner_html("constant") }',inner+'pub fn probe(view : Dummy) -> Unit { let value = "constant"; view.inner_html(value) }')
html='pub fn html(value : String) -> String { value }\n'
add('CWE-79/template-injection',html+'pub fn probe(input : String) -> String { html("<p>\\{input}</p>") }',html+'pub fn probe() -> String { html("<p>constant</p>") }',html+'pub fn probe() -> String { let input = "constant"; html("<p>\\{input}</p>") }')
add('CWE-94/eval-extern','pub extern "js" fn probe(input : String) -> String = "(input) => eval(input)"','pub extern "js" fn probe(input : String) -> String = "(input) => input"','pub extern "js" fn probe(input : String) -> String = "(input) => { /* eval(input) */ return input; }"','real_js_ffi','js')
header=DUMMY+'pub fn Dummy::set_header(_self : Dummy, _name : String, _value : String) -> Unit {}\n'
add('CWE-113/crlf-injection',header+'pub fn probe(res : Dummy, input : String) -> Unit { res.set_header("X", input) }',header+'pub fn probe(res : Dummy) -> Unit { res.set_header("X", "constant") }',header+'pub fn probe(res : Dummy) -> Unit { let input = "constant"; res.set_header("X", input) }')
cors='pub fn handle_cors(origin? : String = "*", credentials? : Bool = false) -> String { if credentials { origin } else { "constant" } }\n'
add('CWE-942/cors-credentials',cors+'pub fn probe() -> String { handle_cors(credentials=true) }',cors+'pub fn probe() -> String { handle_cors(origin="https://example.com", credentials=true) }',cors+'pub fn probe() -> String { handle_cors(origin="*", credentials=true) }')
cookie=DUMMY+'pub fn Dummy::set_cookie(_self : Dummy, _name : String, _value : String, http_only? : Bool = false, secure? : Bool = false, same_site? : String = "None") -> Unit { ignore((http_only, secure, same_site)) }\n'
add('CWE-614/cookie-attrs',cookie+'pub fn probe(res : Dummy) -> Unit { res.set_cookie("token", "value") }',cookie+'pub fn probe(res : Dummy) -> Unit { res.set_cookie("token", "value", http_only=true, secure=true, same_site="Strict") }',cookie+'pub fn probe(res : Dummy) -> Unit { res.set_cookie("token", "value") }')
C.append(case('CWE-614/cookie-attrs','false_attributes_counterexample',cookie+'pub fn probe(res : Dummy) -> Unit { res.set_cookie("token", "value", http_only=false, secure=false, same_site="None") }',0,'counterexample'))
server=DUMMY+'pub fn Dummy::post(_self : Dummy, _path : String) -> Unit {}\npub fn Dummy::serve(_self : Dummy, body_limit? : Int = 0) -> Unit { ignore(body_limit) }\n'
add('CWE-770/no-body-limit',server+'pub fn probe(app : Dummy) -> Unit { app.post("/"); app.serve() }',server+'pub fn probe(app : Dummy) -> Unit { app.post("/"); app.serve(body_limit=1024) }',server+'pub fn probe(app : Dummy) -> Unit { app.post("/"); app.serve() }')
ws='pub fn upgrade_websocket(origin? : String = "") -> String { origin }\n'
add('CWE-346/ws-origin',ws+'pub fn probe() -> String { upgrade_websocket() }',ws+'pub fn probe() -> String { upgrade_websocket(origin="https://example.com") }',ws+'pub fn probe() -> String { upgrade_websocket() }')
add('CWE-22/path-concat','pub fn probe(base_path : String, user_input : String) -> String { base_path + user_input }','pub fn probe() -> String { "base/" + "constant" }','pub fn probe() -> String { let base_path = "base/"; let user_input = "constant"; base_path + user_input }','real_builtin_operator')
unsafe='pub fn unsafe_cast(value : Int) -> Int { value }\n'
add('CWE-676/unsafe-call',unsafe+'pub fn probe(input : Int) -> Int { unsafe_cast(input) }',unsafe+'pub fn probe(input : Int) -> Int { guard true else { return 0 }; unsafe_cast(input) }',unsafe+'pub fn probe() -> Int { unsafe_cast(1) }')
add('CWE-248/panic-reachable','pub fn probe() -> Unit { abort("operation failed") }','pub fn probe() -> Unit {}','pub fn probe() -> Unit { let abort = (_msg : String) => (); abort("operation failed") }','real_builtin')
C.append(case('CWE-248/panic-reachable','reachable_guard_counterexample','pub fn probe(input : Bool) -> Unit { guard input else { abort("operation failed") }; () }',0,'real_builtin_counterexample'))
cast=DUMMY+'pub fn Dummy::cast(_self : Dummy) -> Int { 0 }\n'
add('CWE-704/unsafe-cast',cast+'pub fn probe(value : Dummy) -> Int { value.cast() }',cast+'pub fn probe(value : Int) -> String { value.to_string() }',cast+'pub fn probe() -> Int { Dummy::{}.cast() }')

def run(argv,cwd):
    p=subprocess.run(argv,cwd=cwd,text=True,capture_output=True,timeout=120)
    return dict(exit_code=p.returncode,stdout=p.stdout,stderr=p.stderr)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--moon-wrapper',type=pathlib.Path,required=True)
    p.add_argument('--analyzer',type=pathlib.Path,required=True)
    p.add_argument('--output',type=pathlib.Path,required=True)
    a=p.parse_args(); results=[]
    (HERE/'fixtures').mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='moon-rule-audit-') as td:
        root=pathlib.Path(td)
        (root/'moon.mod').write_text('name = "audit/rules"\nversion = "0.0.1"\n')
        gate=root/'mocket_cmark_rabbita_crescent'; gate.mkdir()
        (gate/'moon.pkg').write_text('')
        (gate/'marker.mbt').write_text('pub fn marker() -> Unit {}\n')
        probe=root/'probe'; probe.mkdir()
        (probe/'moon.pkg').write_text('import { "audit/rules/mocket_cmark_rabbita_crescent" }\n')
        for idx,c in enumerate(C):
            code=c['source']+'\n'
            fixture=HERE/'fixtures'/f'{idx:02d}_{c["rule"].replace("/","_")}_{c["kind"]}.mbt.txt'
            fixture.write_text(code)
            (probe/'probe.mbt').write_text(code)
            compiler=run([str(a.moon_wrapper.resolve()),'moon','check','--target',c['target']],root)
            scan=run([str(a.analyzer.resolve()),str(root),'--rule',c['rule'],'--format','json','--quiet'],root)
            try:
                report=json.loads(scan['stdout']); findings=[x for x in report['findings'] if x.get('rule_id')==c['rule']]
                # rule_id can be a structured object in earlier report formats.
                if not findings: findings=[x for x in report['findings'] if x.get('rule_id')=={'cwe':int(c['rule'].split('/')[0][4:]),'variant':c['rule'].split('/')[1]}]
                count=len(findings); errors=report.get('errors',[])
            except (ValueError,KeyError): count=None; errors=['invalid_report']
            result={k:v for k,v in c.items() if k!='source'}
            result.update(fixture=str(fixture.relative_to(HERE)),sha256=hashlib.sha256(code.encode()).hexdigest(),compiler=compiler,scanner_exit=scan['exit_code'],findings=count,scanner_errors=errors)
            result['passed']=compiler['exit_code']==0 and not errors and count==c['expected_findings']
            results.append(result)
            print(c['rule'],c['kind'],'PASS' if result['passed'] else 'FAIL',compiler['exit_code'],count,flush=True)
    record=dict(schema='moon-audit.rule-shape-audit.v1',toolchain=run([str(a.moon_wrapper.resolve()),'moon','version','--all'],HERE),analyzer_sha256=hashlib.sha256(a.analyzer.read_bytes()).hexdigest(),purpose='Compiler-checked syntax shapes and counterexamples; synthetic APIs do not validate real libraries or exploitability.',gating='Intentionally misleading local import name demonstrates import substring is not API identity.',cases=results,passed=sum(x['passed'] for x in results),total=len(results))
    a.output.write_text(json.dumps(record,indent=2)+'\n')
    return 0 if record['passed']==record['total'] else 1
if __name__=='__main__': raise SystemExit(main())
