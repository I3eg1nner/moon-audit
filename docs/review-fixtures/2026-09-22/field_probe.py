"""Compile and verify field postconditions and object identity; exit 1 on semantic mismatch, 2 on compilation failure."""
import json, pathlib, subprocess, sys
if len(sys.argv) != 3:
 raise SystemExit("usage: field_probe.py OUTPUT_DIR ANALYZER")
root=pathlib.Path(sys.argv[1]).resolve()
root.mkdir(parents=True,exist_ok=True)
bin=pathlib.Path(sys.argv[2]).resolve()
cases = {
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
    'shadowed_receiver_alias': '''fn source() -> String { "dirty" }
fn sink(value : String) -> Unit { ignore(value) }
pub struct Box { mut value : String }
fn fill(box : Box) -> Unit { let box = box; box.value = source() }
pub fn go() -> Unit {
  let box = Box::{value: "safe"}
  let box = box
  fill(box)
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
    'clean_and_unrelated_fields': '''fn source() -> String { "dirty" }
fn sink(value : String) -> Unit { ignore(value) }
pub struct Box { mut value : String; safe : String }
fn fill(box : Box) -> Unit { box.value = source() }
fn clear(box : Box) -> Unit { box.value = "safe" }
pub fn go() -> Unit {
  let box = Box::{value: "safe", safe: "safe"}
  fill(box)
  sink(box.value) // alert
  sink(box.safe)
  clear(box)
  sink(box.value)
}
''',
    'transitive_alias': '''fn source() -> String { "dirty" }
fn sink(value : String) -> Unit { ignore(value) }
pub struct Box { mut value : String; safe : String }
fn fill(box : Box, value : String) -> Unit { let alias_box = box; alias_box.value = value }
fn wrap(box : Box, value : String) -> Unit { let other = box; fill(other, value) }
pub fn go() -> Unit {
  let box = Box::{value: "safe", safe: "safe"}
  wrap(box, source())
  sink(box.value) // alert
  wrap(box, "safe")
  sink(box.value)
}
''',
    'conditional_write': '''fn source() -> String { "dirty" }
fn sink(value : String) -> Unit { ignore(value) }
pub struct Box { mut value : String; safe : String }
fn clear(box : Box, flag : Bool) -> Unit { if flag { box.value = "safe" } }
fn fill(box : Box, flag : Bool) -> Unit { if flag { box.value = source() } }
pub fn go(flag : Bool) -> Unit {
  let dirty = Box::{value: source(), safe: "safe"}
  clear(dirty, flag)
  sink(dirty.value) // alert
  let safe = Box::{value: "safe", safe: "safe"}
  clear(safe, flag)
  sink(safe.value)
  fill(safe, flag)
  sink(safe.value) // alert
}
''',
    'both_branches_clear': '''fn source() -> String { "dirty" }
fn sink(value : String) -> Unit { ignore(value) }
pub struct Box { mut value : String; safe : String }
fn clear(box : Box, flag : Bool) -> Unit { if flag { box.value = "safe" } else { box.value = "also safe" } }
pub fn go(flag : Bool) -> Unit {
  let box = Box::{value: source(), safe: "safe"}
  clear(box, flag)
  sink(box.value)
}
''',
    'early_return': '''fn source() -> String { "dirty" }
fn sink(value : String) -> Unit { ignore(value) }
pub struct Box { mut value : String; safe : String }
fn clear(box : Box, flag : Bool) -> Unit { if flag { return }; box.value = "safe" }
fn fill(box : Box, flag : Bool) -> Unit { if flag { box.value = source(); return } }
pub fn go(flag : Bool) -> Unit {
  let box = Box::{value: source(), safe: "safe"}
  clear(box, flag)
  sink(box.value) // alert
  let other = Box::{value: "safe", safe: "safe"}
  fill(other, flag)
  sink(other.value) // alert
}
''',
    'normal_and_exception': '''fn source() -> String { "dirty" }
fn sink(value : String) -> Unit { ignore(value) }
pub struct Box { mut value : String; safe : String }
suberror Boom { Boom }
fn fill(box : Box, flag : Bool) -> Unit raise Boom {
  if flag { raise Boom }
  box.value = source()
}
pub fn go(flag : Bool) -> Unit {
  let box = Box::{value: "safe", safe: "safe"}
  try {
    fill(box, flag)
    sink(box.value) // alert
  } catch { Boom => sink(box.value) }
}
''',
    'write_before_throw': '''fn source() -> String { "dirty" }
fn sink(value : String) -> Unit { ignore(value) }
pub struct Box { mut value : String; safe : String }
suberror Boom { Boom }
fn fill(box : Box) -> Unit raise Boom { box.value = source(); raise Boom }
pub fn go() -> Unit {
  let box = Box::{value: "safe", safe: "safe"}
  try { fill(box) } catch { Boom => sink(box.value) } // alert
}
''',
    'exception_clear': '''fn source() -> String { "dirty" }
fn sink(value : String) -> Unit { ignore(value) }
pub struct Box { mut value : String; safe : String }
suberror Boom { Boom }
fn clear(box : Box) -> Unit raise Boom { box.value = "safe"; raise Boom }
pub fn go() -> Unit {
  let box = Box::{value: source(), safe: "safe"}
  try { clear(box) } catch { Boom => sink(box.value) }
}
''',
    'exception_alternatives': '''fn source() -> String { "dirty" }
fn sink(value : String) -> Unit { ignore(value) }
pub struct Box { mut value : String; safe : String }
suberror Boom { Boom }
fn fill(box : Box, flag : Bool) -> Unit raise Boom {
  if flag { box.value = source(); raise Boom }
  raise Boom
}
pub fn go(flag : Bool) -> Unit {
  let box = Box::{value: "safe", safe: "safe"}
  try { fill(box, flag) } catch { Boom => sink(box.value) } // alert
}
''',
    'local_object_not_parameter': '''fn source() -> String { "dirty" }
fn sink(value : String) -> Unit { ignore(value) }
pub struct Box { mut value : String; safe : String }
fn work(box : Box) -> Unit {
  let local = Box::{value: box.value, safe: "safe"}
  local.value = source()
  ignore(local)
}
pub fn go() -> Unit {
  let box = Box::{value: "safe", safe: "safe"}
  work(box)
  sink(box.value)
}
''',
    'same_line_allocations': '''fn source() -> String { "dirty" }
fn sink(value : String) -> Unit { ignore(value) }
pub struct Box { value : String; safe : String }
pub fn go() -> Unit {
  let dirty = Box::{value: source(), safe: "safe"}; let safe = Box::{value: "safe", safe: "safe"}
  sink(dirty.value) // alert
  sink(safe.value)
}
''',
    'field_getter': '''fn source() -> String { "dirty" }
fn sink(value : String) -> Unit { ignore(value) }
pub struct Box { value : String; safe : String }
fn get(box : Box) -> String { box.value }
fn Box::get(self : Box) -> String { self.value }
pub fn go() -> Unit {
  let dirty = Box::{value: source(), safe: "safe"}
  let safe = Box::{value: "safe", safe: source()}
  sink(get(dirty)) // alert
  sink(dirty.get()) // alert
  sink(get(safe))
  sink(safe.get())
}
''',
    'field_copy': '''fn source() -> String { "dirty" }
fn sink(value : String) -> Unit { ignore(value) }
pub struct Box { mut value : String; safe : String }
fn copy(dst : Box, src : Box) -> Unit { dst.value = src.value }
pub fn go() -> Unit {
  let dirty = Box::{value: source(), safe: "safe"}
  let safe = Box::{value: "safe", safe: source()}
  let dst = Box::{value: "safe", safe: "safe"}
  copy(dst, dirty)
  sink(dst.value) // alert
  copy(dst, safe)
  sink(dst.value)
}
''',
    'field_swap': '''fn source() -> String { "dirty" }
fn sink(value : String) -> Unit { ignore(value) }
pub struct Box { mut value : String; mut safe : String }
fn swap(box : Box) -> Unit { let value = box.value; box.value = box.safe; box.safe = value }
pub fn go() -> Unit {
  let box = Box::{value: source(), safe: "safe"}
  swap(box)
  sink(box.value)
  sink(box.safe) // alert
}
''',
    'method_exception': '''fn source() -> String { "dirty" }
fn sink(value : String) -> Unit { ignore(value) }
pub struct Box { mut value : String; safe : String }
suberror Boom { Boom }
fn Box::fill(self : Box) -> Unit raise Boom { self.value = source(); raise Boom }
pub fn go() -> Unit {
  let box = Box::{value: "safe", safe: "safe"}
  try { box.fill() } catch { Boom => sink(box.value) } // alert
}
''',
    'defer_exit': '''fn source() -> String { "dirty" }
fn sink(value : String) -> Unit { ignore(value) }
pub struct Box { mut value : String; safe : String }
fn fill(box : Box) -> Unit { defer { box.value = source() }; return }
pub fn go() -> Unit {
  let box = Box::{value: "safe", safe: "safe"}
  fill(box)
  sink(box.value) // alert
}
''',
    'two_formals_alias_dirty_last': '''fn source() -> String { "dirty" }
fn sink(value : String) -> Unit { ignore(value) }
pub struct Box { mut value : String; safe : String }
fn fill(first : Box, second : Box) -> Unit { first.value = "safe"; second.value = source() }
pub fn go() -> Unit {
  let box = Box::{value: "safe", safe: "safe"}
  fill(box, box)
  sink(box.value) // alert
}
''',
    'two_formals_alias_read_after_write': '''fn source() -> String { "dirty" }
fn sink(value : String) -> Unit { ignore(value) }
pub struct Box { mut value : String; mut safe : String }
fn fill(first : Box, second : Box) -> Unit { first.value = source(); second.safe = second.value }
pub fn go() -> Unit {
  let box = Box::{value: "safe", safe: "safe"}
  fill(box, box)
  sink(box.value) // alert
  sink(box.safe) // alert
}
''',
    'two_formals_alias_clean_last': '''fn source() -> String { "dirty" }
fn sink(value : String) -> Unit { ignore(value) }
pub struct Box { mut value : String; safe : String }
fn fill(first : Box, second : Box) -> Unit { first.value = source(); second.value = "safe" }
pub fn go() -> Unit {
  let box = Box::{value: "safe", safe: "safe"}
  fill(box, box)
  sink(box.value)
}
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
