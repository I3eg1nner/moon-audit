"""Compile and check default argument evaluation; exit 1 on semantic mismatch, 2 on compilation failure."""
import json, pathlib, subprocess, sys
if len(sys.argv) != 3:
 raise SystemExit("usage: default_probe.py OUTPUT_DIR ANALYZER")
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
    'dependent_chain': '''fn source() -> String { "dirty" }
fn sink(value : String) -> Unit { ignore(value) }
fn pick(first : String, second~ : String = first, third~ : String = second) -> String { third }
pub fn go(value : String) -> Unit {
  sink(pick(value)) // alert
  sink(pick("safe"))
  sink(pick(value, second="safe"))
  sink(pick("safe", second=value)) // alert
  sink(pick(value, third="safe"))
}
''',
    'forward_presence': '''fn source() -> String { "dirty" }
fn sink(value : String) -> Unit { ignore(value) }
fn pick(value~ : String = { sink(source()); "safe" }) -> String { value }
pub fn go() -> Unit {
  ignore(pick(value?=Some("safe")))
  ignore(pick(value?=None)) // alert
  let present = Some("safe")
  ignore(pick(value?=present))
  let missing : String? = None
  ignore(pick(value?=missing)) // alert
}
''',
    'forward_return': '''fn source() -> String { "dirty" }
fn sink(value : String) -> Unit { ignore(value) }
fn pick(value~ : String = source()) -> String { value }
pub fn go() -> Unit {
  sink(pick(value?=Some("safe")))
  sink(pick(value?=None)) // alert
  let present = Some("safe")
  sink(pick(value?=present))
  let missing : String? = None
  sink(pick(value?=missing)) // alert
}
''',
    'default_helper_sink': '''fn source() -> String { "dirty" }
fn sink(value : String) -> Unit { ignore(value) }
fn emit(value : String) -> Unit { sink(value) } // alert
fn pick(value~ : String = { emit(source()); "safe" }) -> String { value }
pub fn go() -> Unit {
  ignore(pick()) // alert
  ignore(pick(value="safe"))
}
''',
    'default_method': '''fn source() -> String { "dirty" }
fn sink(value : String) -> Unit { ignore(value) }
pub struct Box {}
fn Box::pick(self : Box, first : String, value~ : String = first) -> String { ignore(self); value }
pub fn go(value : String) -> Unit {
  let box = Box::{}
  sink(box.pick(value)) // alert
  sink(box.pick("safe"))
  sink(box.pick(value, value="safe"))
}
''',
    'default_heap_write': '''fn source() -> String { "dirty" }
fn sink(value : String) -> Unit { ignore(value) }
pub struct Box { mut value : String }
fn pick(box : Box, value~ : String = { box.value = source(); "safe" }) -> String { value }
pub fn go() -> Unit {
  let dirty = Box::{value: "safe"}
  ignore(pick(dirty))
  sink(dirty.value) // alert
  let safe = Box::{value: "safe"}
  ignore(pick(safe, value="safe"))
  sink(safe.value)
}
''',
    'default_lexical_shadow': '''fn source() -> String { "dirty" }
fn sink(value : String) -> Unit { ignore(value) }
fn safe() -> String { "safe" }
fn pick(value~ : String = safe()) -> String { value }
pub fn go(safe : () -> String) -> Unit {
  ignore(safe)
  sink(pick())
}
''',
    'default_raise': '''fn source() -> String { "dirty" }
fn sink(value : String) -> Unit { ignore(value) }
suberror Bad { Bad(String) }
fn fail() -> String raise Bad { raise Bad(source()) }
fn pick(value~ : String = fail()) -> String raise Bad { value }
pub fn go() -> Unit {
  try { ignore(pick()) } catch { Bad(value) => sink(value) } // alert
  try { ignore(pick(value="safe")) } catch { Bad(value) => sink(value) }
}
''',
    'default_order': '''fn source() -> String { "dirty" }
fn sink(value : String) -> Unit { ignore(value) }
pub struct Box { mut value : String }
fn pick(box : Box, first~ : String = { box.value = source(); "safe" }, second~ : String = box.value) -> String { ignore(first); second }
pub fn go() -> Unit {
  let box = Box::{value: "safe"}
  sink(pick(box)) // alert
  let safe = Box::{value: "safe"}
  sink(pick(safe, first="safe"))
}
''',
    'default_overridden_raise': '''fn source() -> String { "dirty" }
fn sink(value : String) -> Unit { ignore(value) }
suberror Bad { Bad(String) }
fn fail() -> String raise Bad { raise Bad(source()) }
fn pick(value~ : String = fail()) -> String raise Bad { value }
pub fn go(value : String) -> Unit raise Bad {
  ignore(pick(value="safe"))
  sink(value) // alert
}
''',
    'forward_none_raise': '''fn source() -> String { "dirty" }
fn sink(value : String) -> Unit { ignore(value) }
suberror Bad { Bad(String) }
fn fail() -> String raise Bad { raise Bad(source()) }
fn pick(value~ : String = fail()) -> String raise Bad { value }
pub fn go() -> Unit {
  let missing : String? = None
  try {
    ignore(pick(value?=missing))
    sink(source())
  } catch { Bad(value) => sink(value) } // alert
}
''',
    'forward_changed': '''fn source() -> String { "dirty" }
fn sink(value : String) -> Unit { ignore(value) }
fn pick(value~ : String = { sink(source()); "safe" }) -> String { value }
pub fn go() -> Unit {
  let mut value = Some("safe")
  value = None
  ignore(pick(value?)) // alert
}
''',
    'forward_branch': '''fn source() -> String { "dirty" }
fn sink(value : String) -> Unit { ignore(value) }
fn pick(value~ : String = { sink(source()); "safe" }) -> String { value }
pub fn go(flag : Bool) -> Unit {
  let mut value = Some("safe")
  if flag { value = None }
  ignore(pick(value?)) // alert
}
''',
    'forward_both_present': '''fn source() -> String { "dirty" }
fn sink(value : String) -> Unit { ignore(value) }
fn pick(value~ : String = { sink(source()); "safe" }) -> String { value }
pub fn go(flag : Bool) -> Unit {
  let mut value : String? = None
  if flag { value = Some("safe") } else { value = Some("also safe") }
  ignore(pick(value?))
}
''',
    'default_model_source': '''fn sink(value : String) -> Unit { ignore(value) }
fn source(value~ : String = { sink(source(value="safe")); "safe" }) -> String { value }
pub fn go() -> Unit {
  ignore(source()) // alert
  ignore(source(value="safe"))
}
''',
    'default_model_sink': '''fn source() -> String { "dirty" }
fn sink(value~ : String = source()) -> Unit { ignore(value) }
pub fn go() -> Unit {
  sink() // alert
  sink(value="safe")
}
''',
    'default_exception_heap': '''fn source() -> String { "dirty" }
fn sink(value : String) -> Unit { ignore(value) }
suberror Bad { Bad(String) }
pub struct Box { mut value : String }
fn fail(box : Box) -> String raise Bad { box.value = source(); raise Bad("safe") }
fn pick(box : Box, value~ : String = { box.value = source(); raise Bad("safe") }) -> String raise Bad { value }
pub fn go() -> Unit {
  let box = Box::{value: "safe"}
  try { ignore(pick(box)) } catch { Bad(_) => sink(box.value) } // alert
}
''',
    'default_all_overridden': '''fn source() -> String { "dirty" }
fn sink(value : String) -> Unit { ignore(value) }
fn pick(first : String, second~ : String = first) -> String { second }
pub fn go(value : String) -> Unit {
  sink(pick(value, second="safe"))
  sink(pick("safe", second=value)) // alert
}
''',
    'default_generic_show': '''fn source() -> String { "dirty" }
fn sink(value : String) -> Unit { ignore(value) }
pub struct Box {}
pub impl Show for Box with fn output(self, logger) -> Unit { ignore(self); logger.write_string(source()) }
fn[T : Show] pick(value : T, text~ : String = value.to_string()) -> String { text }
fn[T : Show] wrap(value : T) -> String { pick(value) }
pub fn go() -> Unit { sink(wrap(Box::{})) } // alert
pub fn safe() -> Unit { sink(wrap("safe")) }
''',
    'default_factory_show': '''fn source() -> String { "dirty" }
fn sink(value : String) -> Unit { ignore(value) }
pub struct Box {}
pub impl Show for Box with fn output(self, logger) -> Unit { ignore(self); logger.write_string(source()) }
fn make() -> Box { Box::{} }
fn[T : Show] pick(value : T, text~ : String = value.to_string()) -> String { text }
pub fn go() -> Unit { sink(pick(make())) } // alert
pub fn safe() -> Unit { sink(pick("safe")) }
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
