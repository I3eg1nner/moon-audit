"""Reproduce review boundaries; exit 1 on semantic mismatch, 2 on compilation failure."""
import json, pathlib, subprocess, sys
if len(sys.argv) != 3:
 raise SystemExit("usage: probe.py OUTPUT_DIR ANALYZER")
root=pathlib.Path(sys.argv[1]).resolve()
root.mkdir(parents=True,exist_ok=True)
bin=pathlib.Path(sys.argv[2]).resolve()
prefix='fn source() -> String { "dirty" }\nfn sink(value : String) -> Unit { ignore(value) }\n'
cases={
 'method_field':prefix+'''pub struct Box { mut value : String }
fn Box::put(self : Box, value : String) -> Unit { self.value = value }
pub fn go(value : String) -> Unit {
  let box = Box::{ value: "safe" }
  box.put(value)
  sink(box.value) // alert
}
''',
 'static_field':prefix+'''pub struct Box { mut value : String }
fn Box::put(self : Box, value : String) -> Unit { self.value = value }
pub fn go(value : String) -> Unit {
  let box = Box::{ value: "safe" }
  Box::put(box, value)
  sink(box.value) // alert
}
''',
 'source_return':prefix+'''fn wrapper() -> String { source() }
pub fn go() -> Unit { sink(wrapper()) } // alert
''',
 'function_param_shadow':prefix+'''fn pick(a : String, b : String) -> String { ignore(a); b }
pub fn go(pick : (String, String) -> String, value : String) -> Unit {
  sink(pick(value, "safe")) // alert
}
''',
 'constant_branch':prefix+'''pub fn go(value : String) -> Unit {
  if false { sink(value) }
}
''',
 'constant_loop':prefix+'''pub fn go(value : String) -> Unit {
  while false { sink(value) }
}
''',
 'labelled_safe':prefix+'''fn pick(first~ : String, second : String) -> String { ignore(first); second }
pub fn go(value : String) -> Unit { sink(pick(first=value, "safe")) }
''',
 'labelled_first':prefix+'''fn pick(first~ : String, second : String) -> String { ignore(first); second }
pub fn go(value : String) -> Unit { sink(pick(first="safe", value)) } // alert
''',
}
results={}
for name,source in cases.items():
 d=root/name;d.mkdir(exist_ok=True)
 (d/'moon.mod').write_text('name = "review/probe"\n')
 (d/'moon.pkg').write_text('')
 (d/'main.mbt').write_text(source)
 (d/'taint-rules.json').write_text(json.dumps({'sources':[{'method':'source','kind':'RequestData'}],'sinks':[{'method':'sink','kind':'HeaderValue','value_slot':0}]}))
 p=subprocess.run(['moon','check'],cwd=d,capture_output=True,text=True,timeout=60)
 (d/'check.log').write_text(p.stdout+p.stderr)
 results[name]={'compile':p.returncode,'expected':[i for i,line in enumerate(source.splitlines(),1) if '// alert' in line]}
 if p.returncode==0:
  for mode,flags in [('ast',[]),('cfg',['--cfg-engine']),('strict',['--cfg-verify'])]:
   p=subprocess.run([str(bin),'--mode','deep','--format','json',*flags,str(d)],capture_output=True,text=True,timeout=60)
   (d/(mode+'.json')).write_text(p.stdout);(d/(mode+'.stderr')).write_text(p.stderr)
   r=json.loads(p.stdout)
   results[name][mode]={'rc':p.returncode,'lines':[f['line'] for f in r['findings']],'scope':r.get('analysis_scope')}
 print(name, json.dumps({k:v if not isinstance(v,dict) else {kk:vv for kk,vv in v.items() if kk!='scope'} for k,v in results[name].items()}),flush=True)
(root/'results.json').write_text(json.dumps(results,indent=2,ensure_ascii=False))

if any(r['compile'] != 0 for r in results.values()):
 raise SystemExit(2)
failed=[name for name,r in results.items() if any(r[mode]['rc'] != 0 or r[mode]['lines'] != r['expected'] for mode in ('ast','cfg'))]
print('Semantic mismatches:', ', '.join(failed) if failed else 'none')
raise SystemExit(1 if failed else 0)
