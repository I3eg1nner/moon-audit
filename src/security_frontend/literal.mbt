// The pinned parser retains source spelling, not decoded string contents.
// Decode reviewed simple escapes; other forms must not hide HTML delimiters.

///|
fn literal_value(repr : String) -> String? {
  let result = StringBuilder()
  let mut escaped = false
  for ch in repr.iter() {
    if escaped {
      let decoded = match ch {
        '"' => '"'
        '\\' => '\\'
        '/' => '/'
        'n' => '\n'
        'r' => '\r'
        't' => '\t'
        'b' => '\b'
        'f' => '\u000c'
        _ => return None
      }
      result.write_char(decoded)
      escaped = false
    } else if ch == '\\' {
      escaped = true
    } else {
      result.write_char(ch)
    }
  }
  if escaped {
    None
  } else {
    Some(result.to_string())
  }
}
