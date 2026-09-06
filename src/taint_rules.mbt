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
} derive(Eq, Debug)

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

///|
/// T5.3: the DEFERRED model key for `callee`, if any — the returned key
/// is what deferred-callback facts record. Name-based suffix match
/// ("Array::map" matches a call to `map`): the flow engine carries no
/// receiver types, so the qualified model key is matched against the
/// bare callee name (honest boundary, documented).
pub fn TaintRuleset::cb_timing_deferred_key(
  self : TaintRuleset,
  callee : String,
) -> String? {
  for pair in self.cb_timing {
    let (k, t) = pair
    match t {
      Deferred =>
        if k == callee || k.has_suffix("::" + callee) {
          return Some(k)
        }
      Immediate => ()
    }
  }
  None
}

///|
pub fn TaintRuleset::cb_timing_deferred(
  self : TaintRuleset,
  callee : String,
) -> Bool {
  self.cb_timing_deferred_key(callee) != None
}

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

// ── loading (T5.1: ONE parse pipeline + ONE merge for all entries) ──────
//
// Entry paths (all funnel through parse_ruleset_json + append_ruleset):
//   A. dedicated <root>/taint-rules.json
//   B. "taint" section of <root>/.moon-audit.json
//   C. "extends" models (user <dir>/libmodels/<name>.json, then built-in)
// Conflict semantics (documented in docs/ir/RULES-DSL.md):
//   - arrays (sources/sinks/sanitizers/callbacks/trait_edges): ADD-only;
//     exact duplicates warn once and are kept (first-hit queries, benign)
//   - fn_types: same key with DIFFERENT value warns "last wins" and the
//     later entry replaces the earlier (apply_to_symbols is map-assign)
//   - cb_timing: same name with different timing warns, later wins
//   - unknown fields at every level produce warnings (never silently
//     dropped); scan output discloses them via analysis-scope
//     model-warnings=N plus bounded [model] lines in the errors channel

///|
fn warn(warnings : Array[String], msg : String) -> Unit {
  if !warnings.contains(msg) {
    warnings.push(msg)
  }
}

///|
pub fn load_taint_rules(root : String) -> (TaintRuleset, String, Array[String]) {
  let warnings : Array[String] = []
  // priority 1: dedicated <root>/taint-rules.json
  let dedicated = root + "/taint-rules.json"
  let dedicated_ok = @fs.is_file(dedicated) catch { _ => false }
  if dedicated_ok {
    let (rs, w) = read_ruleset_file(dedicated)
    for x in w {
      warnings.push(x)
    }
    if rs.size() > 0 {
      return (rs, dedicated, warnings)
    }
  }
  // priority 2: "taint" section of <root>/.moon-audit.json
  let combined = root + "/.moon-audit.json"
  let combined_ok = @fs.is_file(combined) catch { _ => false }
  if combined_ok {
    let content = @fs.read_file_to_string(combined) catch { _ => "" }
    let json = @json.parse(content) catch {
      _ => return (TaintRuleset::empty(), "built-in defaults", warnings)
    }
    match json {
      Object(obj) =>
        match obj.get("taint") {
          Some(tnode) => {
            let rs = parse_ruleset_json(
              tnode,
              combined + " [taint section]",
              warnings,
            )
            if rs.size() > 0 {
              let visited : Array[String] = []
              resolve_extends(rs, combined, warnings, visited)
              return (rs, combined + " [taint section]", warnings)
            }
          }
          _ => ()
        }
      _ => ()
    }
  }
  (TaintRuleset::empty(), "built-in defaults", warnings)
}

///|
fn read_ruleset_file(path : String) -> (TaintRuleset, Array[String]) {
  let warnings : Array[String] = []
  let content = @fs.read_file_to_string(path) catch {
    _ => return (TaintRuleset::empty(), warnings)
  }
  let j = @json.parse(content) catch {
    _ => {
      warn(warnings, "taint rules: unparseable JSON in " + path + " (ignored)")
      return (TaintRuleset::empty(), warnings)
    }
  }
  let rs = parse_ruleset_json(j, path, warnings)
  let visited : Array[String] = []
  resolve_extends(rs, path, warnings, visited)
  (rs, warnings)
}

// known top-level keys (name/description are model metadata, allowed)

///|
fn is_known_toplevel(k : String) -> Bool {
  match k {
    "sources"
    | "sinks"
    | "sanitizers"
    | "types"
    | "callbacks"
    | "trait_edges"
    | "extends"
    | "name"
    | "description" => true
    _ => false
  }
}

// ── single parser: Json -> TaintRuleset (+warnings) ──────────────────────

///|
pub fn parse_ruleset_json(
  j : Json,
  origin : String,
  warnings : Array[String],
) -> TaintRuleset {
  let rs = TaintRuleset::empty()
  match j {
    Object(obj) => {
      obj.each(fn(k, _) {
        if !is_known_toplevel(k) {
          warn(
            warnings,
            "unknown field '" + k + "' in " + origin + " (ignored)",
          )
        }
      })
      for r in parse_rule_array(obj.get("sources"), "sources", origin, warnings) {
        rs.sources.push(r)
      }
      for r in parse_rule_array(obj.get("sinks"), "sinks", origin, warnings) {
        rs.sinks.push(r)
      }
      for
        r in parse_rule_array(
          obj.get("sanitizers"),
          "sanitizers",
          origin,
          warnings,
        ) {
        rs.sanitizers.push(r)
      }
      match obj.get("types") {
        Some(Object(types)) =>
          types.each(fn(k, v) {
            match v {
              String(s) => merge_fn_type(rs, k, s, origin, warnings)
              _ =>
                warn(
                  warnings,
                  "types.'" + k + "' non-string in " + origin + " (ignored)",
                )
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
                push_callback(rs, k, placeholders, warnings)
              }
              // v2 object form: { "slots": [...], "timing": "deferred" }
              Object(cb) => {
                cb.each(fn(k2, _) {
                  if k2 != "slots" && k2 != "timing" {
                    warn(
                      warnings,
                      "unknown field '" +
                      k2 +
                      "' in callbacks." +
                      k +
                      " of " +
                      origin,
                    )
                  }
                })
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
                push_callback(rs, k, placeholders, warnings)
                merge_cb_timing(rs, k, timing, origin, warnings)
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
                edge.each(fn(k2, _) {
                  if k2 != "method" && k2 != "trait_method" && k2 != "note" {
                    warn(
                      warnings,
                      "unknown field '" + k2 + "' in trait_edges of " + origin,
                    )
                  }
                })
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
                  let dup = rs.trait_edges.any(fn(e) {
                    e.lib_method == lib_method && e.trait_method == trait_method
                  })
                  if !dup {
                    rs.trait_edges.push({ lib_method, trait_method, note, })
                  }
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
              String(s) => if !rs.extends.contains(s) { rs.extends.push(s) }
              _ => warn(warnings, "non-string entry in extends of " + origin)
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
fn merge_fn_type(
  rs : TaintRuleset,
  key : String,
  val : String,
  origin : String,
  warnings : Array[String],
) -> Unit {
  for i in 0..<rs.fn_types.length() {
    let (k, v) = rs.fn_types[i]
    if k == key {
      if v == val {
        return // exact duplicate: keep one, no warning
      }
      warn(
        warnings,
        "conflict: types['" +
        key +
        "'] '" +
        v +
        "' vs '" +
        val +
        "' in " +
        origin +
        " (last wins)",
      )
      rs.fn_types[i] = (key, val)
      return
    }
  }
  rs.fn_types.push((key, val))
}

///|
fn push_callback(
  rs : TaintRuleset,
  name : String,
  placeholders : Array[String],
  warnings : Array[String],
) -> Unit {
  let dup = rs.callbacks.any(fn(c) { c.0 == name && c.1 == placeholders })
  if dup {
    warn(warnings, "duplicate callback '" + name + "' (kept once)")
    return
  }
  rs.callbacks.push((name, placeholders))
}

///|
fn merge_cb_timing(
  rs : TaintRuleset,
  name : String,
  timing : CallbackTiming,
  origin : String,
  warnings : Array[String],
) -> Unit {
  for i in 0..<rs.cb_timing.length() {
    let (n, t) = rs.cb_timing[i]
    if n == name {
      if t != timing {
        warn(
          warnings,
          "conflict: callbacks.'" +
          name +
          "' timing differs across " +
          origin +
          " (last wins)",
        )
        rs.cb_timing[i] = (name, timing)
      }
      return
    }
  }
  rs.cb_timing.push((name, timing))
}

///|
fn parse_rule_array(
  node : Json?,
  cat : String,
  origin : String,
  warnings : Array[String],
) -> Array[TaintMethodRule] {
  let out : Array[TaintMethodRule] = []
  match node {
    Some(Array(arr)) => {
      for item in arr {
        match item {
          Object(rule_obj) => {
            rule_obj.each(fn(k2, _) {
              if k2 != "method" && k2 != "kind" && k2 != "value_slot" {
                warn(
                  warnings,
                  "unknown field '" + k2 + "' in " + cat + " of " + origin,
                )
              }
            })
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
            } else {
              warn(
                warnings,
                cat + " rule missing 'method' in " + origin + " (skipped)",
              )
            }
          }
          _ => warn(warnings, "non-object entry in " + cat + " of " + origin)
        }
      }
      out
    }
    _ => out
  }
}

// ── single merge: ADD parsed ext into base (documented conflicts) ────────

///|
pub fn append_ruleset(
  base : TaintRuleset,
  ext : TaintRuleset,
  origin : String,
  warnings : Array[String],
) -> Unit {
  for r in ext.sources {
    if !base.sources.contains(r) {
      base.sources.push(r)
    }
  }
  for r in ext.sinks {
    if !base.sinks.contains(r) {
      base.sinks.push(r)
    }
  }
  for r in ext.sanitizers {
    if !base.sanitizers.contains(r) {
      base.sanitizers.push(r)
    }
  }
  for pair in ext.fn_types {
    merge_fn_type(base, pair.0, pair.1, origin, warnings)
  }
  for c in ext.callbacks {
    push_callback(base, c.0, c.1, warnings)
  }
  for pair in ext.cb_timing {
    merge_cb_timing(base, pair.0, pair.1, origin, warnings)
  }
  for e in ext.trait_edges {
    let dup = base.trait_edges.any(fn(x) {
      x.lib_method == e.lib_method && x.trait_method == e.trait_method
    })
    if !dup {
      base.trait_edges.push(e)
    }
  }
}

// ── extends resolution (user models first, built-ins second) ─────────────

///|
fn try_parse_model_text(
  text : String,
  origin : String,
  warnings : Array[String],
) -> TaintRuleset? {
  let j = @json.parse(text) catch { _ => return None }
  Some(parse_ruleset_json(j, origin, warnings))
}

///|
fn try_parse_model(path : String, warnings : Array[String]) -> TaintRuleset? {
  let content = @fs.read_file_to_string(path) catch { _ => return None }
  let j = @json.parse(content) catch {
    _ => {
      warn(warnings, "extends: unparseable JSON in " + path + " (ignored)")
      return None
    }
  }
  Some(parse_ruleset_json(j, path, warnings))
}

///|
pub fn resolve_extends(
  rs : TaintRuleset,
  from_path : String,
  warnings : Array[String],
  visited : Array[String],
) -> Unit {
  let names = rs.extends.copy()
  rs.extends.clear()
  for name in names {
    if visited.contains(name) {
      warn(warnings, "extends cycle detected at '" + name + "' (skipped)")
      continue
    }
    visited.push(name)
    let user_model = model_dir_of(from_path) + "/libmodels/" + name + ".json"
    let user_ok = @fs.is_file(user_model) catch { _ => false }
    let mut ext : TaintRuleset = TaintRuleset::empty()
    let mut origin = "builtin:" + name
    let mut have_model = false
    if user_ok {
      match try_parse_model(user_model, warnings) {
        Some(parsed) => {
          ext = parsed
          origin = user_model
          have_model = true
        }
        None => ()
      }
    } else {
      // built-in embedded models (mongoose ...) — same pipeline as user
      match builtin_model_json(name) {
        Some(json_text) =>
          match try_parse_model_text(json_text, "builtin:" + name, warnings) {
            Some(parsed) => {
              ext = parsed
              have_model = true
            }
            None => ()
          }
        None =>
          warn(warnings, "extends: unknown model '" + name + "' (ignored)")
      }
    }
    // nested extends: resolve the model's own extends BEFORE appending so
    // each model merges exactly once, innermost first
    if have_model && ext.size() > 0 {
      resolve_extends(ext, origin, warnings, visited)
      append_ruleset(rs, ext, origin, warnings)
    }
  }
}

///|
fn model_dir_of(path : String) -> String {
  // model files live in <base>/libmodels/<name>.json — nested extends must
  // search the SAME libmodels dir, i.e. strip back to <base>
  let lm = find_sub(path, "/libmodels/")
  if lm >= 0 {
    return Show::to_string(path[:lm])
  }
  let idx = find_last_sep(path)
  if idx >= 0 {
    Show::to_string(path[:idx])
  } else {
    "."
  }
}

///|
fn find_sub(s : String, needle : String) -> Int {
  let n = needle.length()
  let mut i = 0
  while i + n <= s.length() {
    if Show::to_string(s[i:i + n]) == needle {
      return i
    }
    i += 1
  }
  -1
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
