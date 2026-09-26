// Legacy MoonBit project metadata accepts JSON with comments and trailing
// commas. Normalize only these lexical extensions; retain strict JSON values.

///|
fn parse_project_json(source : String) -> Json? {
  let chars = source.to_array()
  let clean = StringBuilder()
  let mut i = 0
  while i < chars.length() {
    let ch = chars[i]
    if ch == '"' {
      clean.write_char(ch)
      i += 1
      while i < chars.length() {
        let next = chars[i]
        clean.write_char(next)
        i += 1
        if next == '\\' && i < chars.length() {
          clean.write_char(chars[i])
          i += 1
        } else if next == '"' {
          break
        }
      }
      continue
    }
    if ch == '/' && i + 1 < chars.length() && chars[i + 1] == '/' {
      clean.write_char(' ')
      i += 2
      while i < chars.length() && chars[i] != '\n' && chars[i] != '\r' {
        i += 1
      }
      continue
    }
    if ch == '/' && i + 1 < chars.length() && chars[i + 1] == '*' {
      clean.write_char(' ')
      i += 2
      while i + 1 < chars.length() && !(chars[i] == '*' && chars[i + 1] == '/') {
        i += 1
      }
      if i + 1 >= chars.length() {
        return None
      }
      i += 2
      continue
    }
    clean.write_char(ch)
    i += 1
  }
  let chars = clean.to_string().to_array()
  let normalized = StringBuilder()
  i = 0
  while i < chars.length() {
    let ch = chars[i]
    if ch == '"' {
      normalized.write_char(ch)
      i += 1
      while i < chars.length() {
        let next = chars[i]
        normalized.write_char(next)
        i += 1
        if next == '\\' && i < chars.length() {
          normalized.write_char(chars[i])
          i += 1
        } else if next == '"' {
          break
        }
      }
      continue
    }
    if ch == ',' {
      let mut next = i + 1
      while next < chars.length() &&
            (
              chars[next] == ' ' ||
              chars[next] == '\t' ||
              chars[next] == '\r' ||
              chars[next] == '\n'
            ) {
        next += 1
      }
      let mut previous = i - 1
      while previous >= 0 &&
            (
              chars[previous] == ' ' ||
              chars[previous] == '\t' ||
              chars[previous] == '\r' ||
              chars[previous] == '\n'
            ) {
        previous -= 1
      }
      if next < chars.length() &&
        (chars[next] == '}' || chars[next] == ']') &&
        previous >= 0 &&
        chars[previous] != '{' &&
        chars[previous] != '[' &&
        chars[previous] != ',' &&
        chars[previous] != ':' {
        i += 1
        continue
      }
    }
    normalized.write_char(ch)
    i += 1
  }
  let text = normalized.to_string()
  let parsed = @json.parse(text) catch { _ => return None }
  if duplicate_json_top_key(text) {
    None
  } else {
    Some(parsed)
  }
}

///|
// The standard JSON parser validates syntax but its map discards duplicates.
// Inspect only top-level member names of already validated JSON; decode keys
// with the same JSON parser so escaped spellings cannot create a second identity.
fn duplicate_json_top_key(source : String) -> Bool {
  let chars = source.to_array()
  let seen : Map[String, Bool] = Map([])
  let mut depth = 0
  let mut expect_key = false
  let mut i = 0
  while i < chars.length() {
    let ch = chars[i]
    if ch == '"' {
      let key = StringBuilder()
      key.write_char(ch)
      i += 1
      while i < chars.length() {
        let next = chars[i]
        key.write_char(next)
        i += 1
        if next == '\\' && i < chars.length() {
          key.write_char(chars[i])
          i += 1
        } else if next == '"' {
          break
        }
      }
      if depth == 1 && expect_key {
        let value = @json.parse(key.to_string()) catch { _ => return true }
        if value is String(name) {
          if seen.contains(name) {
            return true
          }
          seen[name] = true
        }
        expect_key = false
      }
      continue
    }
    if ch == '{' || ch == '[' {
      depth += 1
      if depth == 1 && ch == '{' {
        expect_key = true
      }
    } else if ch == '}' || ch == ']' {
      depth -= 1
    } else if ch == ',' && depth == 1 {
      expect_key = true
    }
    i += 1
  }
  false
}
