// Baseline file support: generate and filter known findings.

///|
pub fn generate_baseline(findings : Array[Finding]) -> String {
  let buf = StringBuilder::new()
  buf.write_string("[\n")
  for i, f in findings {
    if i > 0 {
      buf.write_string(",\n")
    }
    buf.write_string("  {\n")
    buf.write_string("    \"rule_id\": \"")
    buf.write_string(escape_json_str(rule_id_str(f.rule_id)))
    buf.write_string("\",\n")
    buf.write_string("    \"fingerprint\": \"")
    buf.write_string(escape_json_str(f.fingerprint))
    buf.write_string("\",\n")
    buf.write_string("    \"file\": \"")
    buf.write_string(escape_json_str(f.file))
    buf.write_string("\",\n")
    buf.write_string("    \"line\": ")
    buf.write_string(f.line.to_string())
    buf.write_string(",\n")
    buf.write_string("    \"message\": \"")
    buf.write_string(escape_json_str(f.message))
    buf.write_string("\"\n")
    buf.write_string("  }")
  }
  buf.write_string("\n]\n")
  buf.to_string()
}

///|
pub fn load_baseline(path : String) -> Map[String, Bool] {
  let keys : Map[String, Bool] = Map([])
  let content = @fs.read_file_to_string(path) catch { _ => return keys }
  let json = @json.parse(content) catch { _ => return keys }
  match json {
    Array(arr) =>
      for item in arr {
        match item {
          Object(obj) => {
            let rule_id = match obj.get("rule_id") {
              Some(String(s)) => s
              _ => ""
            }
            let fingerprint = match obj.get("fingerprint") {
              Some(String(s)) => s
              _ => ""
            }
            if rule_id.length() > 0 && fingerprint.length() > 0 {
              keys[rule_id + ":" + fingerprint] = true
            }
          }
          _ => ()
        }
      }
    _ => ()
  }
  keys
}

///|
pub fn filter_baseline(
  findings : Array[Finding],
  baseline : Map[String, Bool],
) -> Array[Finding] {
  if baseline.length() == 0 {
    return findings
  }
  findings.filter(fn(f) {
    let key = rule_id_str(f.rule_id) + ":" + f.fingerprint
    !baseline.contains(key)
  })
}

///|
fn escape_json_str(s : String) -> String {
  let buf = StringBuilder::new()
  for i = 0; i < s.length(); i = i + 1 {
    let ch = s[i]
    if ch == char16('"') {
      buf.write_string("\\\"")
    } else if ch == char16('\\') {
      buf.write_string("\\\\")
    } else if ch == char16('\n') {
      buf.write_string("\\n")
    } else if ch == char16('\r') {
      buf.write_string("\\r")
    } else if ch == char16('\t') {
      buf.write_string("\\t")
    } else {
      buf.write_string(ch.to_int().unsafe_to_char().to_string())
    }
  }
  buf.to_string()
}
