"""Compile and replay MoonBit 0.10.14 errdefer boundaries.
Exit 2 for invalid fixtures, 1 for semantic mismatches, 0 when all pass.
"""
import pathlib,subprocess,json,sys
if len(sys.argv) != 3:
 raise SystemExit("usage: upgrade_probe.py OUTPUT_DIR ANALYZER")
root=pathlib.Path(sys.argv[1]).resolve();root.mkdir(parents=True,exist_ok=True)
binary=str(pathlib.Path(sys.argv[2]).resolve())
prefix='fn sink(value : String) -> Unit { ignore(value) }\nsuberror Bad { Bad(String) }\n'
cases={
'normal':prefix+'''pub fn go(value : String) -> Unit {
  errdefer sink(value)
  ignore(value)
}
''',
'local_raise':prefix+'''pub fn go(value : String) -> Unit raise Bad {
  errdefer sink(value) // alert
  raise Bad(value)
}
''',
'callee_raise':prefix+'''fn fail(value : String) -> Unit raise Bad { raise Bad(value) }
pub fn go(value : String) -> Unit raise Bad {
  errdefer sink(value) // alert
  fail(value)
}
''',
'caught':prefix+'''pub fn go(value : String) -> Unit {
  errdefer sink(value)
  try { raise Bad(value) } catch { Bad(_) => () }
}
''',
'raise_state':prefix+'''pub fn go(value : String, flag : Bool) -> Unit raise Bad {
  let mut x = "safe"
  errdefer sink(x) // alert
  if flag { x = value; raise Bad(value) }
  x = "safe"
}
''',
 'callee_chain':prefix+'''fn fail(value : String) -> Unit raise Bad { raise Bad(value) }
fn wrapper(value : String) -> Unit raise Bad { fail(value) }
pub fn go(value : String) -> Unit raise Bad {
  errdefer sink(value) // alert
  wrapper(value)
}
''',
'caught_callee':prefix+'''fn fail(value : String) -> Unit raise Bad { raise Bad(value) }
pub fn go(value : String) -> Unit {
  errdefer sink(value)
  try { fail(value) } catch { Bad(_) => () }
}
''',
'nested_dirty':prefix+'''pub fn go(value : String) -> Unit raise Bad {
  let mut x = "safe"
  errdefer sink(x) // alert
  errdefer { x = value }
  raise Bad(value)
}
''',
'nested_clean':prefix+'''pub fn go(value : String) -> Unit raise Bad {
  let mut x = value
  errdefer sink(x)
  errdefer { x = "safe" }
  raise Bad(value)
}
''',
'cleanup_shadow':prefix+'''pub fn go(value : String) -> Unit raise Bad {
  let x = value
  errdefer sink(x) // alert
  let x = "safe"
  raise Bad(x)
}
''',
'catch_clean':prefix+'''pub fn go(value : String) -> Unit {
  let mut x = value
  try { raise Bad(value) } catch { Bad(_) => x = "safe" }
  sink(x)
}
''',
'catch_typed_wildcard':prefix+'''fn fail(value : String) -> Unit raise { raise Bad(value) }
pub fn go(value : String) -> Unit raise {
  errdefer sink(value)
  try { fail(value) } catch { Bad::_ => (); e => raise e }
}
''',
'payload_binding':prefix+'''fn fail(first~ : String, value : String) -> Unit raise Bad { ignore(first); raise Bad(value) }
pub fn go(value : String) -> Unit {
  try { fail(first="safe", value) } catch { Bad(text) => sink(text) } // alert
  try { fail(first=value, "safe") } catch { Bad(text) => sink(text) }
}
''',
 'callback_noraise':prefix+'''pub fn go(callback : () -> Unit, value : String) -> Unit {
  errdefer sink(value)
  let copied = callback
  copied()
}
''',
'callback_typed_error':prefix+'''pub fn go(callback : () -> Unit raise Bad, value : String) -> Unit {
  errdefer sink(value)
  try { callback() } catch { Bad(_) => () }
}
''',
'return_skips_error_cleanup':prefix+'''pub fn go(value : String, flag : Bool) -> Unit raise Bad {
  errdefer sink(value)
  if flag { return }
  ignore(value)
}
''',
'defer_error_state':prefix+'''pub fn go(value : String) -> Unit {
  let mut x = value
  try {
    defer { x = "safe" }
    raise Bad(value)
  } catch { Bad(_) => () }
  sink(x)
}
''',
'defer_raises_on_return':prefix+'''fn cleanup(value : String) -> Unit raise Bad { raise Bad(value) }
pub fn go(value : String) -> Unit raise Bad {
  errdefer sink(value) // alert
  defer cleanup(value)
  return
}
''',
'method_error':prefix+'''pub struct Box {}
fn Box::fail(self : Box, value : String) -> Unit raise Bad { ignore(self); raise Bad(value) }
pub fn go(value : String) -> Unit raise Bad {
  errdefer sink(value) // alert
  let box = Box::{}
  box.fail(value)
}
''',
 'recursive_error_summary':prefix+'''fn left(value : String, flag : Bool) -> Unit raise Bad {
  if flag { raise Bad(value) } else { right(value, true) }
}
fn right(value : String, flag : Bool) -> Unit raise Bad { left(value, flag) }
pub fn go(value : String, flag : Bool) -> Unit raise Bad {
  errdefer sink(value) // alert
  right(value, flag)
}
''',

'for_zero':prefix+'''pub fn go(value : String) -> Unit raise Bad {
  for i = 0; i < 0; i = i + 1 { raise Bad(value) }
  sink(value) // alert
}
''',
'foreach_zero':prefix+'''pub fn go(value : String) -> Unit raise Bad {
  for _ in ([] : Array[Int]) { raise Bad(value) }
  sink(value) // alert
}
''',
'for_must_raise':prefix+'''pub fn go(value : String) -> Unit raise Bad {
  for i = 0; true; i = i + 1 { raise Bad(value) }
  sink(value)
}
''',
'callback_error_family':prefix+'''suberror Choices { First; Second }
pub fn go(callback : () -> Unit raise Choices, value : String) -> Unit {
  try { callback() } catch {
    First => sink(value) // alert
    Second => sink(value) // alert
  }
}
''',
}
out={}
for name,source in cases.items():
 d=root/name;d.mkdir(exist_ok=True)
 (d/'moon.mod').write_text('name = "review/errdefer"\n');(d/'moon.pkg').write_text('');(d/'main.mbt').write_text(source)
 (d/'taint-rules.json').write_text(json.dumps({'sinks':[{'method':'sink','kind':'HeaderValue','value_slot':0}]}))
 c=subprocess.run(['moon','check'],cwd=d,text=True,capture_output=True,timeout=60);(d/'check.log').write_text(c.stdout+c.stderr)
 r={'compile':c.returncode,'expected':[i for i,l in enumerate(source.splitlines(),1) if '// alert' in l]}
 if c.returncode==0:
  for mode,flags in [('ast',[]),('cfg',['--cfg-engine'])]:
   p=subprocess.run([binary,'--format','json','--mode','deep',*flags,str(d)],text=True,capture_output=True,timeout=60)
   (d/(mode+'.json')).write_text(p.stdout);j=json.loads(p.stdout);r[mode]={'rc':p.returncode,'lines':[f['line'] for f in j['findings']]}
 else:r['error']=c.stdout+c.stderr
 out[name]=r;print(name,json.dumps(r),flush=True)
(root/'results.json').write_text(json.dumps(out,indent=2))

if any(r['compile'] != 0 for r in out.values()):
 raise SystemExit(2)
failed=[name for name,r in out.items() if any(r[mode]['rc'] != 0 or r[mode]['lines'] != r['expected'] for mode in ('ast','cfg'))]
print('Semantic mismatches:', ', '.join(failed) if failed else 'none')
raise SystemExit(1 if failed else 0)
