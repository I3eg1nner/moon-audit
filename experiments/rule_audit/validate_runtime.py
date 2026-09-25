#!/usr/bin/env python3
"""Execute harmless runtime oracles for builtin replace and JS FFI token matching."""
import argparse, hashlib, json, pathlib, subprocess, tempfile
HERE=pathlib.Path(__file__).resolve().parent
NATIVE='''test "builtin replaces first occurrence" {
  inspect("<<".replace(old="<", new="&lt;"), content="&lt;<")
}
test "builtin replaces all occurrences" {
  inspect("<<".replace_all(old="<", new="&lt;"), content="&lt;&lt;")
}
'''
JS='''extern "js" fn evaluate(input : String) -> Int = "(input) => eval(input)"
extern "js" fn identity(input : String) -> String = "(input) => { /* eval(input) */ return input; }"
test "actual eval executes harmless arithmetic" { inspect(evaluate("1 + 1"), content="2") }
test "comment containing eval does not execute input" { inspect(identity("1 + 1"), content="1 + 1") }
'''
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--moon-wrapper',type=pathlib.Path,required=True);p.add_argument('--output',type=pathlib.Path,required=True);a=p.parse_args();cases=[]
    with tempfile.TemporaryDirectory(prefix='moon-rule-runtime-') as td:
        root=pathlib.Path(td);(root/'moon.mod').write_text('name = "audit/runtime"\nversion = "0.0.1"\n');(root/'moon.pkg').write_text('')
        for target,src in [('native',NATIVE),('js',JS)]:
            fixture=HERE/'real_fixtures'/('runtime_'+target+'.mbt.txt');fixture.write_text(src);(root/'oracle_test.mbt').write_text(src)
            cmd=[str(a.moon_wrapper.resolve()),'moon','test','--target',target]
            out=subprocess.run(cmd,cwd=root,text=True,capture_output=True,timeout=180)
            cases.append(dict(target=target,fixture=str(fixture.relative_to(HERE)),fixture_sha256=hashlib.sha256(src.encode()).hexdigest(),command=cmd,exit_code=out.returncode,stdout=out.stdout,stderr=out.stderr,passed=out.returncode==0))
    rec=dict(schema='moon-audit.rule-runtime-oracle.v1',purpose='Language semantics only; no user-data exploitability claim.',cases=cases,passed=sum(x['passed'] for x in cases),total=len(cases));a.output.write_text(json.dumps(rec,indent=2)+'\n');print(json.dumps(rec,indent=2));return 0 if all(x['passed'] for x in cases) else 1
if __name__=='__main__': raise SystemExit(main())
