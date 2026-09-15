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

///| Built-in "core-callbacks" model: T5.3 callback TIMING for core

///| containers (SCHEMA-v2 table): immediate = executes during the call

///| (current engine behavior); deferred = stored, executed on advance —

///| the engine records a deferred-callback fact instead of executing.

///|
let core_callbacks_model_json : String =
  #|{
  #|  "name": "core-callbacks",
  #|  "description": "core container callback timing (Array::map executes during the call; Iter::map stores and executes on advance)",
  #|  "callbacks": {
  #|    "Array::map":     { "slots": ["T"], "timing": "immediate" },
  #|    "Array::filter":  { "slots": ["T"], "timing": "immediate" },
  #|    "Array::sort_by": { "slots": ["T"], "timing": "immediate" },
  #|    "Iter::map":      { "slots": ["T"], "timing": "deferred" }
  #|  }
  #|}

///|
fn builtin_model_json(name : String) -> String? {
  match name {
    "mongoose" => Some(mongoose_model_json)
    "core-callbacks" => Some(core_callbacks_model_json)
    "async" => Some(async_model_json)
    _ => None
  }
}

///|
pub fn builtin_model_names() -> Array[String] {
  ["mongoose", "core-callbacks", "async"]
}

///|
pub fn extend_ruleset_with_model(rs : TaintRuleset, name : String) -> Bool {
  // T5.1: built-in models go through the SAME parse/merge pipeline as
  // user models and the inline/dedicated entries (single code path).
  let json_text = match builtin_model_json(name) {
    Some(t) => t
    None => return false
  }
  let warnings : Array[String] = []
  let j = @json.parse(json_text) catch { _ => return false }
  let ext = parse_ruleset_json(j, "builtin:" + name, warnings)
  if ext.size() == 0 {
    return false
  }
  append_ruleset(rs, ext, "builtin:" + name, warnings)
  true
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

// ── P4a: Core container model (Array/Map/String) ─────────────────────────
// Expresses the SAME information as builtin_method_ret, but in the model
// JSON DSL — a first step toward migrating hardcoded tables to models.
// When "core-containers" is extended, these types are consulted BEFORE
// builtin_method_ret (which becomes the fallback for unmapped methods).

///|
let core_containers_model_json : String =
  #|{
  #|  "name": "core-containers",
  #|  "description": "P4a: Array/Map/String method return types + callback timing",
  #|  "types": {
  #|    "Array::map": "Array[T]",
  #|    "Array::filter": "Array[T]",
  #|    "Array::rev": "Array[T]",
  #|    "Array::sort": "Array[T]",
  #|    "Array::concat": "Array[T]",
  #|    "Array::flatten": "Array[T]",
  #|    "Array::dedup": "Array[T]",
  #|    "Array::take": "Array[T]",
  #|    "Array::skip": "Array[T]",
  #|    "Array::drop": "Array[T]",
  #|    "Array::to_array": "Array[T]",
  #|    "Array::copy": "Array[T]",
  #|    "Array::iter": "Iter",
  #|    "Array::join": "String",
  #|    "Array::to_string": "String",
  #|    "Array::fold": "String",
  #|    "Array::exists": "Bool",
  #|    "Array::contains": "Bool",
  #|    "Array::length": "Int",
  #|    "Array::size": "Int",
  #|    "Array::blit": "Unit",
  #|    "Array::sort_by": "Unit",
  #|    "Map::get": "Option[V]",
  #|    "Map::get_or_default": "V",
  #|    "Map::get_or_init": "V",
  #|    "Map::at": "V",
  #|    "Map::get_unsafe": "V",
  #|    "Map::set": "Unit",
  #|    "Map::remove": "Unit",
  #|    "Map::clear": "Unit",
  #|    "Map::contains": "Bool",
  #|    "Map::length": "Int",
  #|    "Map::size": "Int",
  #|    "Map::keys": "Array[K]",
  #|    "Map::values": "Array[V]",
  #|    "Map::each": "Unit",
  #|    "Map::map": "Map[K,V]",
  #|    "Map::filter": "Map[K,V]",
  #|    "Map::iter": "Iter",
  #|    "Map::iter2": "Iter",
  #|    "String::to_string": "String",
  #|    "String::to_owned": "String",
  #|    "String::rev": "String",
  #|    "String::concat": "String",
  #|    "String::repeat": "String",
  #|    "String::substring": "String",
  #|    "String::trim": "String",
  #|    "String::trim_start": "String",
  #|    "String::trim_end": "String",
  #|    "String::to_uppercase": "String",
  #|    "String::to_lowercase": "String",
  #|    "String::replace": "String",
  #|    "String::pad_left": "String",
  #|    "String::pad_right": "String",
  #|    "String::length": "Int",
  #|    "String::char_length": "Int",
  #|    "String::codeunit_size": "Int",
  #|    "String::compare": "Int",
  #|    "String::hash": "Int",
  #|    "String::is_empty": "Bool",
  #|    "String::contains": "Bool",
  #|    "String::starts_with": "Bool",
  #|    "String::ends_with": "Bool",
  #|    "String::find": "Int",
  #|    "String::last_of": "Int",
  #|    "String::count_of": "Int",
  #|    "String::chars": "Array[Char]",
  #|    "String::split": "Array[String]",
  #|    "String::split_char": "Array[String]",
  #|    "String::split_whitespace": "Array[String]",
  #|    "String::bytes": "Array[Byte]",
  #|    "String::lines": "Array[String]",
  #|    "String::view": "StringView",
  #|    "Buffer::to_string": "String",
  #|    "Buffer::to_bytes": "Bytes",
  #|    "Buffer::to_owned": "String",
  #|    "Buffer::length": "Int",
  #|    "Buffer::size": "Int",
  #|    "Iter::to_array": "Array[T]",
  #|    "Iter::collect": "Array[T]",
  #|    "Iter::map": "Array[T]",
  #|    "Iter::filter": "Array[T]",
  #|    "StringBuilder::to_string": "String",
  #|    "StringBuilder::length": "Int"
  #|  },
  #|  "callbacks": {
  #|    "Array::map":    { "slots": ["T"], "timing": "immediate" },
  #|    "Array::filter": { "slots": ["T"], "timing": "immediate" },
  #|    "Array::each":   { "slots": ["T"], "timing": "immediate" },
  #|    "Array::sort_by":{ "slots": ["T"], "timing": "immediate" },
  #|    "Map::each":     { "slots": ["K","V"], "timing": "immediate" },
  #|    "Iter::map":     { "slots": ["T"], "timing": "deferred" }
  #|  }
  #|}

///|
pub fn core_model_types() -> Map[String, IRType] {
  // Parse the model's types entries into IRType via parse_type_expr
  let result : Map[String, IRType] = Map([])
  let j = @json.parse(core_containers_model_json) catch { _ => return result }
  match j {
    Object(obj) =>
      match obj.get("types") {
        Some(Object(types)) =>
          types.each(fn(k, v) {
            match v {
              String(s) => result[k] = parse_type_expr(s)
              _ => ()
            }
          })
        _ => ()
      }
    _ => ()
  }
  result
}

///| Built-in "async" model: moonbitlang/async semantics (P4b).

///|
/// - spawn callbacks are DEFERRED (stored, executed on scheduler advance)
/// - HTTP response bodies arrive from the network → tainted source
/// - file reads produce untrusted data → tainted source
/// - file writes send data out → sink (Output kind, CWE-116 path)
/// - websocket recv → tainted; send → sink

///|
/// Activated via `"extends": ["async"]` in taint-rules.json (opt-in).
let async_model_json : String =
  #|{
  #|  "name": "async",
  #|  "description": "moonbitlang/async: spawn timing + HTTP/file/ws semantics",
  #|  "types": {
  #|    "spawn": "Task",
  #|    "get": "Response",
  #|    "post": "Response",
  #|    "read_file": "Bytes"
  #|  },
  #|  "sources": [
  #|    { "method": "get",        "kind": "RequestData", "value_slot": 1 },
  #|    { "method": "post",       "kind": "RequestData", "value_slot": 1 },
  #|    { "method": "put",        "kind": "RequestData", "value_slot": 1 },
  #|    { "method": "read_file",  "kind": "RequestBody" },
  #|    { "method": "recv",       "kind": "RequestData" }
  #|  ],
  #|  "sinks": [
  #|    { "method": "write_file",   "kind": "Output", "value_slot": 1 },
  #|    { "method": "send_text",    "kind": "Output", "value_slot": 1 },
  #|    { "method": "send_binary",  "kind": "Output", "value_slot": 1 },
  #|    { "method": "send_close",   "kind": "Output", "value_slot": 1 }
  #|  ],
  #|  "sanitizers": [],
  #|  "callbacks": {
  #|    "spawn":      { "slots": [], "timing": "deferred" },
  #|    "spawn_bg":   { "slots": [], "timing": "deferred" },
  #|    "spawn_loop": { "slots": [], "timing": "deferred" },
  #|    "iterate":    { "slots": [], "timing": "immediate" }
  #|  }
  #|}
