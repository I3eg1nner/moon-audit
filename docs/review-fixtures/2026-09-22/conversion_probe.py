"""Compile and compare conversion boundaries; 2=invalid, 1=mismatch, 0=pass."""
import json
from pathlib import Path
import subprocess
import sys

if len(sys.argv) != 3:
    raise SystemExit("usage: conversion_probe.py OUTPUT_DIR ANALYZER")
root = Path(sys.argv[1]).resolve()
root.mkdir(parents=True, exist_ok=True)
binary = str(Path(sys.argv[2]).resolve())
cases = {
    "utf8_identity": ('import { "moonbitlang/core/encoding/utf8" }\n', '''fn sink(value : Bytes) -> Unit { ignore(value) }
fn wrap(value : String) -> Bytes { @utf8.encode(value) }
pub fn go(value : String) -> Unit {
  sink(wrap("safe"))
  sink(wrap(value)) // alert
}
'''),
    "generic_show_source": ("", '''fn sink(value : String) -> Unit { ignore(value) }
fn source() -> String { "dirty" }
pub struct Box {}
pub impl Show for Box with fn output(self, logger) -> Unit { ignore(self); logger.write_string(source()) }
fn[T : Show] wrap(value : T) -> String { value.to_string() }
pub fn go() -> Unit { sink(wrap(Box::{})) } // alert
'''),
    "utf8_alias": ('import { "moonbitlang/core/encoding/utf8" @codec }\n', '''fn sink(value : Bytes) -> Unit { ignore(value) }
fn wrap(value : String, flag~ : Bool) -> Bytes { @codec.encode(value, bom=flag) }
pub fn go(value : String, flag : Bool) -> Unit {
  sink(wrap("safe", flag~))
  sink(wrap(value, flag=false)) // alert
}
'''),
    "show_two_types": ("", '''fn sink(value : String) -> Unit { ignore(value) }
fn source() -> String { "dirty" }
pub struct Dirty {}
pub struct Safe {}
pub impl Show for Dirty with fn output(self, logger) -> Unit { ignore(self); logger.write_string(source()) }
pub impl Show for Safe with fn output(self, logger) -> Unit { ignore(self); logger.write_string("safe") }
fn[T : Show] wrap(value : T) -> String { value.to_string() }
pub fn go() -> Unit {
  sink(wrap(Dirty::{})) // alert
  sink(wrap(Safe::{}))
  sink(wrap("safe"))
}
'''),
    "show_chain": ("", '''fn sink(value : String) -> Unit { ignore(value) }
fn source() -> String { "dirty" }
pub struct Box {}
pub impl Show for Box with fn output(self, logger) -> Unit { ignore(self); logger.write_string(source()) }
fn[T : Show] first(value : T) -> String { value.to_string() }
fn[T : Show] second(value : T) -> String { first(value) }
pub fn go() -> Unit { sink(second(Box::{})) } // alert
pub fn safe() -> Unit { sink(second("safe")) }
'''),
    "show_static": ("", '''fn sink(value : String) -> Unit { ignore(value) }
fn source() -> String { "dirty" }
pub struct Box {}
pub impl Show for Box with fn output(self, logger) -> Unit { ignore(self); logger.write_string(source()) }
fn[T : Show] wrap(value : T) -> String { Show::to_string(value) }
pub fn go() -> Unit { sink(wrap(Box::{})) } // alert
pub fn safe() -> Unit { sink(wrap("safe")) }
'''),
    "show_override": ("", '''fn sink(value : String) -> Unit { ignore(value) }
fn source() -> String { "dirty" }
pub struct Box {}
pub impl Show for Box with fn to_string(self) -> String { ignore(self); source() }
fn[T : Show] wrap(value : T) -> String { value.to_string() }
pub fn go() -> Unit { sink(wrap(Box::{})) } // alert
pub fn safe() -> Unit { sink(wrap("safe")) }
'''),
    "show_logger_alias": ("", '''fn sink(value : String) -> Unit { ignore(value) }
fn source() -> String { "dirty" }
pub struct Box {}
pub impl Show for Box with fn output(self, logger) -> Unit { ignore(self); let alias_logger = logger; alias_logger.write_string(source()) }
fn[T : Show] wrap(value : T) -> String { value.to_string() }
pub fn go() -> Unit { sink(wrap(Box::{})) } // alert
'''),
    "show_helper_write": ("", '''fn sink(value : String) -> Unit { ignore(value) }
fn source() -> String { "dirty" }
fn emit(logger : &Logger) -> Unit { logger.write_string(source()) }
pub struct Box {}
pub impl Show for Box with fn output(self, logger) -> Unit { ignore(self); emit(logger) }
fn[T : Show] wrap(value : T) -> String { value.to_string() }
pub fn go() -> Unit { sink(wrap(Box::{})) } // alert
'''),
    "show_ignored_source": ("", '''fn sink(value : String) -> Unit { ignore(value) }
fn source() -> String { "dirty" }
pub struct Box {}
pub impl Show for Box with fn output(self, logger) -> Unit { ignore(self); ignore(source()); logger.write_string("safe") }
fn[T : Show] wrap(value : T) -> String { value.to_string() }
pub fn go() -> Unit { sink(wrap(Box::{})) }
'''),
    "show_inherent_homonym": ("", '''fn sink(value : String) -> Unit { ignore(value) }
fn source() -> String { "dirty" }
pub struct Box {}
pub impl Show for Box with fn output(self, logger) -> Unit { ignore(self); logger.write_string("safe") }
fn Box::to_string(self : Box) -> String { ignore(self); source() }
fn[T : Show] wrap(value : T) -> String { value.to_string() }
pub fn go() -> Unit {
  sink(wrap(Box::{}))
  sink(Box::{}.to_string()) // alert
}
'''),
    "show_sink_wrapper": ("", '''fn sink(value : String) -> Unit { ignore(value) }
fn source() -> String { "dirty" }
pub struct Box {}
pub impl Show for Box with fn output(self, logger) -> Unit { ignore(self); logger.write_string(source()) }
fn[T : Show] emit(value : T) -> Unit { sink(value.to_string()) }
pub fn go() -> Unit { emit(Box::{}) } // alert
pub fn safe() -> Unit { emit("safe") }
'''),
    "show_write_object": ("", '''fn sink(value : String) -> Unit { ignore(value) }
fn source() -> String { "dirty" }
pub struct Inner {}
pub struct Outer {}
pub impl Show for Inner with fn output(self, logger) -> Unit { ignore(self); logger.write_string(source()) }
pub impl Show for Outer with fn output(self, logger) -> Unit { ignore(self); logger.write_object(Inner::{}) }
fn[T : Show] wrap(value : T) -> String { value.to_string() }
pub fn go() -> Unit { sink(wrap(Outer::{})) } // alert
'''),
    'show_sink_chain': ('', 'fn sink(value : String) -> Unit { ignore(value) }\nfn source() -> String { "dirty" }\npub struct Box {}\npub impl Show for Box with fn output(self, logger) -> Unit { ignore(self); logger.write_string(source()) }\nfn[T : Show] emit(value : T) -> Unit { sink(value.to_string()) }\nfn[T : Show] relay(value : T) -> Unit { emit(value) }\npub fn go() -> Unit { relay(Box::{}) } // alert\npub fn safe() -> Unit { relay("safe") }\n'),
    'show_sink_method': ('', 'fn sink(value : String) -> Unit { ignore(value) }\nfn source() -> String { "dirty" }\npub struct Box {}\npub struct Writer {}\npub impl Show for Box with fn output(self, logger) -> Unit { ignore(self); logger.write_string(source()) }\nfn[T : Show] Writer::emit(self : Writer, value : T) -> Unit { ignore(self); sink(value.to_string()) }\npub fn go() -> Unit { Writer::{}.emit(Box::{}) } // alert\npub fn safe() -> Unit { Writer::{}.emit("safe") }\n'),
    'show_helper_object': ('', 'fn sink(value : String) -> Unit { ignore(value) }\nfn source() -> String { "dirty" }\npub struct Inner {}\npub struct Outer {}\nfn[T : Show] emit(logger : &Logger, value : T) -> Unit { logger.write_object(value) }\npub impl Show for Inner with fn output(self, logger) -> Unit { ignore(self); logger.write_string(source()) }\npub impl Show for Outer with fn output(self, logger) -> Unit { ignore(self); emit(logger, Inner::{}) }\nfn[T : Show] wrap(value : T) -> String { value.to_string() }\npub fn go() -> Unit { sink(wrap(Outer::{})) } // alert\n'),
    'show_builtin_literals': ('', "fn sink(value : String) -> Unit { ignore(value) }\nfn[T : Show] wrap(value : T) -> String { value.to_string() }\npub fn go(value : Int) -> Unit {\n  sink(wrap(42))\n  sink(wrap(true))\n  sink(wrap('a'))\n  sink(wrap(value)) // alert\n}\n"),
    'show_factory_return': ('', 'fn sink(value : String) -> Unit { ignore(value) }\nfn source() -> String { "dirty" }\npub struct Box {}\npub impl Show for Box with fn output(self, logger) -> Unit { ignore(self); logger.write_string(source()) }\nfn make() -> Box { Box::{} }\nfn[T : Show] wrap(value : T) -> String { value.to_string() }\npub fn go() -> Unit { sink(wrap(make())) } // alert\n'),
    'show_local_trait': ('', 'fn sink(value : String) -> Unit { ignore(value) }\nfn source() -> String { "dirty" }\ntrait Show { to_string(Self) -> String }\nstruct Box {}\nimpl Show for Box with fn to_string(self) -> String { ignore(self); source() }\npub fn go() -> Unit { sink(Box::{}.to_string()) } // alert\n'),
    'utf8_local_homonym': ('', 'fn sink(value : Bytes) -> Unit { ignore(value) }\nfn source() -> Bytes { b"dirty" }\nfn encode(value : String) -> Bytes { ignore(value); source() }\npub fn go() -> Unit { sink(encode("safe")) } // alert\n'),
}
results = {}
for name, (imports, source) in cases.items():
    project = root / name
    project.mkdir(exist_ok=True)
    (project / "moon.mod").write_text('name = "review/conversion"\n')
    (project / "moon.pkg").write_text(imports)
    (project / "main.mbt").write_text(source)
    (project / "taint-rules.json").write_text(json.dumps({
        "sources": [{"method": "source", "kind": "RequestData"}],
        "sinks": [{"method": "sink", "kind": "HeaderValue", "value_slot": 0}],
    }))
    checked = subprocess.run(["moon", "check"], cwd=project, text=True, capture_output=True, timeout=60)
    (project / "check.log").write_text(checked.stdout + checked.stderr)
    result = {"compile": checked.returncode, "expected": [
        i for i, line in enumerate(source.splitlines(), 1) if "// alert" in line
    ]}
    if checked.returncode == 0:
        for mode, flags in (("ast", []), ("cfg", ["--cfg-engine"])):
            run = subprocess.run([binary, "--format", "json", "--mode", "deep", *flags, str(project)],
                                 text=True, capture_output=True, timeout=60)
            (project / (mode + ".json")).write_text(run.stdout)
            report = json.loads(run.stdout)
            result[mode] = {"rc": run.returncode, "lines": [f["line"] for f in report["findings"]]}
    results[name] = result
    print(name, json.dumps(result), flush=True)
(root / "results.json").write_text(json.dumps(results, indent=2))
if any(result["compile"] != 0 for result in results.values()):
    raise SystemExit(2)
failed = [name for name, result in results.items() if any(
    result[mode]["rc"] != 0 or result[mode]["lines"] != result["expected"] for mode in ("ast", "cfg")
)]
print("Semantic mismatches:", ", ".join(failed) if failed else "none")
raise SystemExit(1 if failed else 0)
