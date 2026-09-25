"""Reproduce remaining review boundaries; exit 1 on semantic mismatch, 2 on compilation failure."""
import json, pathlib, subprocess, sys
if len(sys.argv) != 3:
 raise SystemExit("usage: remaining_probe.py OUTPUT_DIR ANALYZER")
root=pathlib.Path(sys.argv[1]).resolve()
root.mkdir(parents=True,exist_ok=True)
bin=pathlib.Path(sys.argv[2]).resolve()
cases = {
    'default_parameter_dependency': '''fn source() -> String { "dirty" }
fn sink(value : String) -> Unit { ignore(value) }
fn pick(first : String, second~ : String = first) -> String { second }
pub fn go(value : String) -> Unit {
  sink(pick(value)) // alert
  sink(pick(value, second="safe"))
  sink(pick("safe"))
}
''',
    'default_sink_effect': '''fn source() -> String { "dirty" }
fn sink(value : String) -> Unit { ignore(value) }
fn choose(value~ : String = { sink(source()); "safe" }) -> String { value }
pub fn go() -> Unit {
  ignore(choose()) // alert
  ignore(choose(value="safe"))
}
''',
    'field_internal_source': '''fn source() -> String { "dirty" }
fn sink(value : String) -> Unit { ignore(value) }
pub struct Box { mut value : String }
fn Box::fill(self : Box) -> Unit { self.value = source() }
pub fn go() -> Unit {
  let box = Box::{value: "safe"}
  box.fill()
  sink(box.value) // alert
}
''',
    'field_alias_parameter': '''fn source() -> String { "dirty" }
fn sink(value : String) -> Unit { ignore(value) }
pub struct Box { mut value : String }
fn fill(box : Box, value : String) -> Unit { let alias_box = box; alias_box.value = value }
pub fn go(value : String) -> Unit {
  let box = Box::{value: "safe"}
  fill(box, value)
  sink(box.value) // alert
}
''',
    'field_multiple_origins': '''fn source() -> String { "dirty" }
fn sink(value : String) -> Unit { ignore(value) }
pub struct Box { mut value : String }
fn fill(box : Box, first : String, second : String, flag : Bool) -> Unit { box.value = if flag { first } else { second } }
pub fn go(value : String, flag : Bool) -> Unit {
  let box = Box::{value: "safe"}
  fill(box, "safe", value, flag)
  sink(box.value) // alert
  let safe_box = Box::{value: "safe"}
  fill(safe_box, "safe", "safe", flag)
  sink(safe_box.value)
}
''',
    'generic_trait_source': '''fn source() -> String { "dirty" }
fn sink(value : String) -> Unit { ignore(value) }
trait Render { render(Self) -> String }
struct Box {}
impl Render for Box with fn render(self) -> String { ignore(self); source() }
fn[T : Render] wrap(value : T) -> String { value.render() }
pub fn go() -> Unit { sink(wrap(Box::{})) } // alert
''',
    'show_local_literal_alias': '''fn source() -> String { "dirty" }
fn sink(value : String) -> Unit { ignore(value) }
fn[T : Show] wrap(value : T) -> String { value.to_string() }
pub fn go() -> Unit { let value = "safe"; sink(wrap(value)) }
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
