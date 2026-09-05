// Taint rule DSL: project-level source/sink/sanitizer vocabularies.
// Review directive (docs/ir/PLAN.md phase 2): rule semantics must live in
// configuration, not inside the solver. Built-in tables remain the base;
// entries from `taint-rules.json` (or the "taint" section of
// `.moon-audit.json`) are ADDED on top, so an absent file reproduces the
// current behavior exactly (regression guarantee). See docs/ir/RULES-DSL.md.

///|
pub(all) struct TaintMethodRule {
  method_name : String // method/function name to match (exact)
  kind : String // e.g. "QueryParam", "HeaderValue" (see RULES-DSL.md)
  value_slot : Int // sinks: positional index of the value argument (default 1)
} derive(Debug)

///|
pub(all) enum CallbackTiming {
  Immediate // executed during the call (Array::map, raise? polymorphic)
  Deferred // stored, executed on later advance (Iter::map)
} derive(Eq, Debug)

///|
/// Callback model v2 (docs/ir/libmodels/SCHEMA-v2.md). v1 tuple
/// `(name, placeholders)` remains the engine-facing form; v2 records timing
/// and trait-callback edges for the M5 effect solver (parsed now, solved then).
pub(all) struct LibModelCallback {
  name : String
  placeholders : Array[String]
  timing : CallbackTiming // default Immediate (v1 semantics)
} derive(Debug)

///|
/// Trait-callback edge: calling `method` re-enters user code via the
/// `trait_method` of the receiver's key/elem type (e.g. Map::get -> hash).
pub(all) struct TraitCallbackEdge {
  lib_method : String // library method ("Map::get")
  trait_method : String // user-implementable method ("hash")
  note : String // conservative-approximation declaration
} derive(Debug)

///|
pub(all) struct TaintRuleset {
  sources : Array[TaintMethodRule]
  sinks : Array[TaintMethodRule]
  sanitizers : Array[TaintMethodRule]
  // library-model extensions (A2): fn name -> return type expression,
  // callback key -> param placeholders ("K"/"V"/"E" = receiver type args)
  fn_types : Array[(String, String)]
  callbacks : Array[(String, Array[String])]
  extends : Array[String] // model names to merge (resolved post-parse)
  // library-model v2 (minimal read path; full solving deferred to M5)
  cb_timing : Array[(String, CallbackTiming)] // name -> timing (parsed)
  trait_edges : Array[TraitCallbackEdge] // declared re-entry edges
} derive(Debug)

///|
pub fn TaintRuleset::empty() -> TaintRuleset {
  {
    sources: [],
    sinks: [],
    sanitizers: [],
    fn_types: [],
    callbacks: [],
    extends: [],
    cb_timing: [],
    trait_edges: [],
  }
}

// ── loading ───────────────────────────────────────────────────────────────

///|
pub fn load_taint_rules(root : String) -> (TaintRuleset, String) {
  // priority 1: dedicated <root>/taint-rules.json
  let dedicated = root + "/taint-rules.json"
  let dedicated_ok = @fs.is_file(dedicated) catch { _ => false }
  if dedicated_ok {
    let rs = read_ruleset_file(dedicated)
    if rs.size() > 0 {
      return (rs, dedicated)
    }
  }
  // priority 2: "taint" section of <root>/.moon-audit.json
  let combined = root + "/.moon-audit.json"
  let combined_ok = @fs.is_file(combined) catch { _ => false }
  if combined_ok {
    let content = @fs.read_file_to_string(combined) catch {
      _ => return (TaintRuleset::empty(), "built-in defaults")
    }
    let json = @json.parse(content) catch {
      _ => return (TaintRuleset::empty(), "built-in defaults")
    }
    match json {
      Object(obj) =>
        match obj.get("taint") {
          Some(Object(_)) => {
            let rs = parse_taint_section(obj.get("taint"))
            if rs.size() > 0 {
              // combined path must resolve extends too (parity with the
              // dedicated-file path) — gate4 finding
              resolve_extends(rs, combined)
              return (rs, combined + " [taint section]")
            }
          }
          _ => ()
        }
      _ => ()
    }
  }
  (TaintRuleset::empty(), "built-in defaults")
}

///|
fn read_ruleset_file(path : String) -> TaintRuleset {
  let content = @fs.read_file_to_string(path) catch {
    _ => return TaintRuleset::empty()
  }
  let j = @json.parse(content) catch { _ => return TaintRuleset::empty() }
  let rs = parse_taint_section(Some(j))
  resolve_extends(rs, path)
  rs
}

///|
fn resolve_extends(rs : TaintRuleset, from_path : String) -> Unit {
  // "extends": ["mongoose", ...] — merge built-in/user models (ADD-only).
  // User models resolve to <dir(from_path)>/libmodels/<name>.json first,
  // built-in embedded models second.
  let names = rs.extends.copy()
  rs.extends.clear()
  for name in names {
    let user_model = model_dir_of(from_path) + "/libmodels/" + name + ".json"
    let user_ok = @fs.is_file(user_model) catch { _ => false }
    if user_ok {
      let content = @fs.read_file_to_string(user_model) catch { _ => continue }
      let j = @json.parse(content) catch { _ => continue }
      let _ = merge_model_json(rs, j)
    } else if !extend_ruleset_with_model(rs, name) {
      // unknown model name: ignore (ADD-only semantics, no failure)
      ignore(name)
    }
  }
}

///|
fn model_dir_of(path : String) -> String {
  let idx = find_last_sep(path)
  if idx >= 0 {
    Show::to_string(path[:idx])
  } else {
    "."
  }
}

///|
fn find_last_sep(s : String) -> Int {
  let mut best = -1
  for i in 0..<s.length() {
    if s[i] == '/' {
      best = i
    }
  }
  best
}

///|
fn parse_taint_section(node : Json?) -> TaintRuleset {
  let rs = TaintRuleset::empty()
  match node {
    Some(Object(obj)) => {
      for r in parse_rule_array(obj.get("sources")) {
        rs.sources.push(r)
      }
      for r in parse_rule_array(obj.get("sinks")) {
        rs.sinks.push(r)
      }
      for r in parse_rule_array(obj.get("sanitizers")) {
        rs.sanitizers.push(r)
      }
      // library-model sections (A2): types / callbacks / extends
      match obj.get("types") {
        Some(Object(types)) =>
          types.each(fn(k, v) {
            match v {
              String(s) => rs.fn_types.push((k, s))
              _ => ()
            }
          })
        _ => ()
      }
      match obj.get("callbacks") {
        Some(Object(cbs)) =>
          cbs.each(fn(k, v) {
            match v {
              Array(arr) => {
                let placeholders : Array[String] = []
                for item in arr {
                  match item {
                    String(s) => placeholders.push(s)
                    _ => ()
                  }
                }
                rs.callbacks.push((k, placeholders))
              }
              // v2 object form: { "slots": [...], "timing": "deferred" }
              Object(cb) => {
                let placeholders : Array[String] = []
                match cb.get("slots") {
                  Some(Array(sl)) =>
                    for item in sl {
                      match item {
                        String(s) => placeholders.push(s)
                        _ => ()
                      }
                    }
                  _ => ()
                }
                let timing : CallbackTiming = match cb.get("timing") {
                  Some(String("deferred")) => Deferred
                  _ => Immediate
                }
                rs.callbacks.push((k, placeholders))
                rs.cb_timing.push((k, timing))
              }
              _ => ()
            }
          })
        _ => ()
      }
      match obj.get("trait_edges") {
        Some(Array(arr)) =>
          for item in arr {
            match item {
              Object(edge) => {
                let lib_method = match edge.get("method") {
                  Some(String(s)) => s
                  _ => ""
                }
                let trait_method = match edge.get("trait_method") {
                  Some(String(s)) => s
                  _ => ""
                }
                let note = match edge.get("note") {
                  Some(String(s)) => s
                  _ => ""
                }
                if lib_method != "" && trait_method != "" {
                  rs.trait_edges.push({ lib_method, trait_method, note, })
                }
              }
              _ => ()
            }
          }
        _ => ()
      }
      match obj.get("extends") {
        Some(Array(arr)) =>
          for item in arr {
            match item {
              String(s) => rs.extends.push(s)
              _ => ()
            }
          }
        _ => ()
      }
      rs
    }
    _ => rs
  }
}

///|
fn parse_rule_array(node : Json?) -> Array[TaintMethodRule] {
  let out : Array[TaintMethodRule] = []
  match node {
    Some(Array(arr)) => {
      for item in arr {
        match item {
          Object(rule_obj) => {
            let mname = match rule_obj.get("method") {
              Some(String(s)) => s
              _ => ""
            }
            if mname.length() > 0 {
              let kind = match rule_obj.get("kind") {
                Some(String(s)) => s
                _ => ""
              }
              let value_slot = match rule_obj.get("value_slot") {
                Some(Number(n, ..)) => n.to_int()
                _ => 1
              }
              out.push({ method_name: mname, kind, value_slot, })
            }
          }
          _ => ()
        }
      }
      out
    }
    _ => out
  }
}

// ── engine queries (config entries ADD to the built-in base) ─────────────

///|
pub fn TaintRuleset::source_hit(self : TaintRuleset, mname : String) -> Bool {
  for r in self.sources {
    if r.method_name == mname {
      return true
    }
  }
  false
}

// sinks reporting under CWE-113 (kind "" or "HeaderValue")

///|
pub fn TaintRuleset::header_sink_hit(
  self : TaintRuleset,
  mname : String,
) -> Bool {
  for r in self.sinks {
    if r.method_name == mname && (r.kind == "" || r.kind == "HeaderValue") {
      return true
    }
  }
  false
}

///|
pub fn TaintRuleset::sink_value_slot(
  self : TaintRuleset,
  mname : String,
) -> Int? {
  for r in self.sinks {
    if r.method_name == mname {
      return Some(r.value_slot)
    }
  }
  None
}

///|
pub fn TaintRuleset::sanitizer_hit(self : TaintRuleset, mname : String) -> Bool {
  for r in self.sanitizers {
    if r.method_name == mname {
      return true
    }
  }
  false
}

///|
pub fn TaintRuleset::size(self : TaintRuleset) -> Int {
  self.sources.length() +
  self.sinks.length() +
  self.sanitizers.length() +
  self.extends.length() +
  self.fn_types.length() +
  self.callbacks.length() +
  self.cb_timing.length() +
  self.trait_edges.length()
}

///|
fn or_slot(slot : Int?) -> Int {
  match slot {
    Some(s) => s
    None => 1
  }
}

// sinks reporting under CWE-116/tainted-output (kind "Output") —
// output channels carrying tainted data out of the program (A2)

///|
pub fn TaintRuleset::output_sink_hit(
  self : TaintRuleset,
  mname : String,
) -> Bool {
  for r in self.sinks {
    if r.method_name == mname && r.kind == "Output" {
      return true
    }
  }
  false
}

///|
pub fn TaintRuleset::output_sink_slot(
  self : TaintRuleset,
  mname : String,
) -> Int? {
  for r in self.sinks {
    if r.method_name == mname && r.kind == "Output" {
      return Some(r.value_slot)
    }
  }
  None
}

///|
pub fn TaintRuleset::apply_to_symbols(
  self : TaintRuleset,
  symbols : PkgSymbols,
) -> Unit {
  // register model return types for ty-recon (ir-stats / call graph)
  for pair in self.fn_types {
    symbols.lib_fn_ret[pair.0] = parse_type_expr(pair.1)
  }
  for pair in self.callbacks {
    symbols.lib_callbacks[pair.0] = pair.1
  }
}
