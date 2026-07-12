///|
pub fn has_labelled_arg(
  args : @list.List[@syntax.Argument],
  name : String,
) -> Bool {
  args.any(fn(arg) {
    match arg.kind {
      Labelled(label) => label.name == name
      LabelledPun(label) => label.name == name
      LabelledOption(label~, ..) => label.name == name
      LabelledOptionPun(label~, ..) => label.name == name
      _ => false
    }
  })
}

///|
pub fn has_labelled_bool_arg(
  args : @list.List[@syntax.Argument],
  name : String,
  value : Bool,
) -> Bool {
  args.any(fn(arg) {
    let name_matches = match arg.kind {
      Labelled(label) => label.name == name
      _ => false
    }
    if !name_matches {
      return false
    }
    match arg.value {
      Constant(c=Bool(b), ..) => b == value
      _ => false
    }
  })
}

///|
pub fn get_labelled_string_value(
  args : @list.List[@syntax.Argument],
  name : String,
) -> String? {
  let mut result : String? = None
  args.each(fn(arg) {
    let name_matches = match arg.kind {
      Labelled(label) => label.name == name
      _ => false
    }
    if name_matches {
      match arg.value {
        Constant(c=String(s), ..) => result = Some(s)
        _ => ()
      }
    }
  })
  result
}

///|
pub fn is_constant_string(expr : @syntax.Expr) -> Bool {
  match expr {
    Constant(c=String(_), ..) => true
    _ => false
  }
}

///|
pub fn is_any_constant(expr : @syntax.Expr) -> Bool {
  match expr {
    Constant(..) => true
    _ => false
  }
}

///|
pub fn get_source_line(source : String, line_num : Int) -> String {
  let idx = line_num - 1
  let mut i = 0
  for line in source.split("\n") {
    if i == idx {
      return line.to_owned()
    }
    i += 1
  }
  ""
}

///|
fn make_finding(
  rule_id : RuleId,
  severity : Severity,
  confidence : Confidence,
  message : String,
  file : String,
  source : String,
  loc : @basic.Location,
) -> Finding {
  let line = loc.start.lnum
  let col = loc.start.column()
  let end_line = loc.end.lnum
  let end_col = loc.end.column()
  let snippet = get_source_line(source, line)
  {
    rule_id,
    severity,
    confidence,
    message,
    file,
    line,
    column: col,
    end_line,
    end_column: end_col,
    snippet,
    fingerprint: compute_fingerprint(rule_id, snippet),
  }
}

///|
pub fn compute_fingerprint(rule_id : RuleId, snippet : String) -> String {
  let input = rule_id_str(rule_id) + ":" + snippet
  let mut h : UInt = 2166136261U
  for i = 0; i < input.length(); i = i + 1 {
    h = h.lxor(input[i].to_uint())
    h = h * 16777619U
  }
  h.to_string()
}

///|
fn is_security_relevant_replace(args : @list.List[@syntax.Argument]) -> Bool {
  let old_val = get_labelled_string_value(args, "old")
  let new_val = get_labelled_string_value(args, "new")
  match (old_val, new_val) {
    (Some(old), Some(new_str)) => {
      let is_metachar = old == "<" || old == ">" || old == "&"
      let is_quote = old == "\"" || old == "'"
      let is_entity = new_str.has_prefix("&") && new_str.has_suffix(";")
      let is_percent = new_str.has_prefix("%")
      if is_metachar && (is_entity || is_percent) {
        return true
      }
      if is_quote && is_entity {
        return true
      }
      if old.has_prefix("<") && old.has_suffix(">") && new_str.length() == 0 {
        return true
      }
      false
    }
    _ => false
  }
}

///|
fn is_cookie_value_empty(args : @list.List[@syntax.Argument]) -> Bool {
  let mut pos_idx = 0
  let mut result = false
  args.each(fn(arg) {
    match arg.kind {
      Labelled(_)
      | LabelledPun(_)
      | LabelledOption(..)
      | LabelledOptionPun(..) => ()
      _ => {
        if pos_idx == 1 {
          match arg.value {
            Constant(c=String(s), ..) => if s.length() == 0 { result = true }
            _ => ()
          }
        }
        pos_idx += 1
      }
    }
  })
  result
}
