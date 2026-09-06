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
pub fn is_constant_ident(name : @syntax.LongIdent) -> Bool {
  let n = match name {
    Ident(name~) => name
    Dot(id~, ..) => id
  }
  if n.length() == 0 {
    return false
  }
  let first = n[0]
  let upper_a : UInt16 = 65
  let upper_z : UInt16 = 90
  if first >= upper_a && first <= upper_z {
    return true
  }
  let underscore : UInt16 = 95
  let all_upper_or_underscore = fn() -> Bool {
    for i = 0; i < n.length(); i = i + 1 {
      let c = n[i]
      if !((c >= upper_a && c <= upper_z) ||
        c == underscore ||
        (c >= 48 && c <= 57)) {
        return false
      }
    }
    true
  }
  all_upper_or_underscore()
}

///|
fn is_sanitize_call_name(name : String) -> Bool {
  // T5.5: FULL-SYMBOL whitelist — substring auto-clean removed (review
  // T5.5: "sanitize/escape/encode substring must not clear taint").
  // A name merely CONTAINING one of these words is no longer a sanitizer;
  // only these exact symbols (grounded in corpus + official naming), plus
  // DSL/model-declared entries (exact form) via sanitizer_hit, clean.
  match name {
    "html_escape"
    | "escape_html"
    | "url_encode"
    | "encode_uri"
    | "crlf_strip"
    | "sanitize_header_value" => true
    _ => false
  }
}

///|
fn is_crlf_like(s : String) -> Bool {
  s == "\\r" ||
  s == "\\n" ||
  s == "\\r\\n" ||
  s == "\r" ||
  s == "\n" ||
  s == "\r\n"
}

///|
fn is_crlf_stripping_chain(expr : @syntax.Expr) -> Bool {
  match expr {
    DotApply(self~, method_name~, args~, ..) =>
      if method_name.name == "replace_all" || method_name.name == "replace" {
        let old_val = get_labelled_string_value(args, "old")
        match old_val {
          Some(s) =>
            if is_crlf_like(s) {
              is_crlf_stripping_chain(self)
            } else {
              false
            }
          _ => false
        }
      } else {
        false
      }
    Ident(..) | Field(..) | Constant(..) => true
    _ => false
  }
}

///|
fn apply_func_name(func : @syntax.Expr) -> String? {
  match func {
    Ident(id~, ..) =>
      match id.name {
        Ident(name~) => Some(name)
        Dot(id~, ..) => Some(id)
      }
    _ => None
  }
}

///|
fn any_arg_is_sanitized(args : @list.List[@syntax.Argument]) -> Bool {
  let mut result = false
  args.each(fn(arg) {
    if is_sanitized_expr(arg.value) || is_safe_value(arg.value) {
      result = true
    }
  })
  result
}

///|
pub fn is_sanitized_expr(expr : @syntax.Expr) -> Bool {
  match expr {
    Apply(func~, args~, ..) =>
      match apply_func_name(func) {
        Some(name) =>
          if is_sanitize_call_name(name) {
            true
          } else {
            any_arg_is_sanitized(args)
          }
        _ => false
      }
    DotApply(method_name~, ..) =>
      if is_sanitize_call_name(method_name.name) {
        true
      } else {
        is_crlf_stripping_chain(expr)
      }
    _ => is_crlf_stripping_chain(expr)
  }
}

///|
fn is_safe_source_text(s : String) -> Bool {
  if s.length() == 0 {
    return true
  }
  let first = s[0]
  let upper_a : UInt16 = 65
  let upper_z : UInt16 = 90
  if first >= upper_a && first <= upper_z {
    return true
  }
  false
}

///|
fn interp_elems_are_safe(elems : @list.List[@syntax.InterpElem]) -> Bool {
  let mut safe = true
  elems.each(fn(elem) {
    match elem {
      Literal(..) => ()
      Expr(expr~, ..) => if !is_safe_value(expr) { safe = false }
      Source(src) => if !is_safe_source_text(src.source) { safe = false }
    }
  })
  safe
}

///|
fn match_branches_all_constant(cases : @list.List[@syntax.Case]) -> Bool {
  let mut all_const = true
  cases.each(fn(case) {
    match case {
      { body, .. } => if !is_safe_value(body) { all_const = false }
    }
  })
  all_const
}

///|
pub fn is_safe_value(expr : @syntax.Expr) -> Bool {
  match expr {
    Constant(..) => true
    Constr(..) => true
    Ident(id~, ..) => is_constant_ident(id.name)
    Interp(elems~, ..) => interp_elems_are_safe(elems)
    Field(..) => true
    Match(cases~, ..) => match_branches_all_constant(cases)
    _ => is_sanitized_expr(expr)
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
