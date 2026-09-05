// Library models: type/taint behavior for extern bindings and container
// APIs whose semantics live outside MoonBit sources (C FFI, core traits).
//
// Two layers:
//   1. Built-in models embedded below (mongoose) — activated explicitly via
//      `"extends": ["mongoose"]` in taint-rules.json (opt-in, no
//      over-broad name matching for projects that don't use the library).
//   2. The same JSON shape for user models (docs/ir/libmodels/*.json are
//      the shipped documentation copies; users copy or reference them).
//
// Model entries are ADD-only, exactly like the taint rule DSL (A1):
// absent extends = current behavior unchanged.

///| Built-in "mongoose" model: mocket's C HTTP/WS server bindings.

///| Sources = request-derived data crossing the FFI boundary; sinks =

///|
/// output channels carrying data back out (kind "Output" -> CWE-116).
let mongoose_model_json : String =
  #|{
  #|  "name": "mongoose",
  #|  "description": "mocket native mongoose C bindings (req_*/res_*/ws_* externs)",
  #|  "types": {
  #|    "create_server": "Server",
  #|    "server_listen_address": "String",
  #|    "ws_msg_body_len": "Int",
  #|    "ws_msg_copy": "Bytes"
  #|  },
  #|  "sources": [
  #|    { "method": "url",       "kind": "RequestData" },
  #|    { "method": "headers",   "kind": "RequestData" },
  #|    { "method": "body",      "kind": "RequestBody" },
  #|    { "method": "req_method","kind": "RequestData" },
  #|    { "method": "ws_msg_copy","kind": "RequestBody" }
  #|  ],
  #|  "sinks": [
  #|    { "method": "ws_send_native", "kind": "Output", "value_slot": 1 },
  #|    { "method": "end_bytes",      "kind": "Output", "value_slot": 1 }
  #|  ],
  #|  "sanitizers": []
  #|}

///|
fn builtin_model_json(name : String) -> String? {
  match name {
    "mongoose" => Some(mongoose_model_json)
    _ => None
  }
}

///|
pub fn builtin_model_names() -> Array[String] {
  ["mongoose"]
}

///|
pub fn extend_ruleset_with_model(rs : TaintRuleset, name : String) -> Bool {
  let json_text = match builtin_model_json(name) {
    Some(t) => t
    None =>
      // user model: <cwd or target>/libmodels/<name>.json — resolved by
      // the caller (load_taint_rules) which knows the project root
      return false
  }
  let j = @json.parse(json_text) catch { _ => return false }
  merge_model_json(rs, j)
}

///|
fn merge_model_json(rs : TaintRuleset, j : Json) -> Bool {
  match j {
    Object(obj) => {
      for r in parse_rule_array(obj.get("sources")) {
        rs.sources.push(r)
      }
      for r in parse_rule_array(obj.get("sinks")) {
        rs.sinks.push(r)
      }
      for r in parse_rule_array(obj.get("sanitizers")) {
        rs.sanitizers.push(r)
      }
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
              _ => ()
            }
          })
        _ => ()
      }
      true
    }
    _ => false
  }
}

// ── type expression parser: "Map[Int, String]" -> IRConcrete ─────────────
// Supports: primitives, Name, @pkg.Name, Name[args]. Enough for lib models;
// full syntax stays with the real parser (AST types / .mbti ingestion).

///|
pub fn parse_type_expr(s : String) -> IRType {
  let t = s.trim()
  parse_type_at(Show::to_string(t), 0).0
}

///|
fn parse_type_at(s : String, start : Int) -> (IRType, Int) {
  let mut i = start
  // skip whitespace
  while i < s.length() && (s[i] == ' ' || s[i] == '\t') {
    i += 1
  }
  // optional package qualifier: @pkg.Name
  let mut pkg_prefix = ""
  if i < s.length() && s[i] == '@' {
    let mut j = i + 1
    while j < s.length() && s[j] != '.' && s[j] != '[' {
      j += 1
    }
    if j < s.length() && s[j] == '.' {
      pkg_prefix = Show::to_string(s[i + 1:j]) + "::"
      i = j + 1
    }
  }
  // name (slice once — String indexing yields code units)
  let name_start = i
  while i < s.length() {
    let c = s[i]
    let alnum = (c >= 'a' && c <= 'z') ||
      (c >= 'A' && c <= 'Z') ||
      (c >= '0' && c <= '9') ||
      c == '_'
    if alnum {
      i += 1
    } else {
      break
    }
  }
  if i == name_start {
    return (IRUnresolved, i)
  }
  let full = pkg_prefix + Show::to_string(s[name_start:i])
  // generic args
  let args : Array[IRType] = []
  if i < s.length() && s[i] == '[' {
    let mut j = i + 1
    while j < s.length() && s[j] != ']' {
      let (arg_ty, next) = parse_type_at(s, j)
      if arg_ty != IRUnresolved {
        args.push(arg_ty)
      }
      j = next
      while j < s.length() && (s[j] == ',' || s[j] == ' ' || s[j] == '\t') {
        j += 1
      }
    }
    i = if j < s.length() { j + 1 } else { j }
  }
  (IRConcrete(full, args), i)
}
