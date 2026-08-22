// CWE-113: HTTP Response Splitting via CRLF Injection.
// Detects when user-controlled input is passed to response header setters
// without CRLF sanitization.

///|
priv struct Cwe113Visitor {
  findings : Array[Finding]
  file : String
  source : String
  severity : Severity
  safe_vars : Map[String, Bool]
}

///|
pub fn cwe113_info() -> RuleInfo {
  {
    id: { cwe: 113, variant: "crlf-injection" },
    name: "HTTP Response Splitting via CRLF Injection",
    description: "Response header values set from user input without CRLF (\\r\\n) sanitization allow HTTP response splitting, enabling session fixation, XSS, and cache poisoning.",
    default_severity: Error,
  }
}

///|
pub fn run_cwe113(
  impls : @list.List[@syntax.Impl],
  file : String,
  source : String,
  findings : Array[Finding],
  severity : Severity,
) -> Unit {
  let visitor : Cwe113Visitor = {
    findings,
    file,
    source,
    severity,
    safe_vars: {},
  }
  impls.each(fn(impl_) { @syntax.IterVisitor::visit_Impl(visitor, impl_) })
}

///|
fn is_header_setter(method_name : String) -> Bool {
  method_name == "set_header" ||
  method_name == "add_header" ||
  method_name == "append_header" ||
  method_name == "set_response_header"
}

///|
fn is_safe_for_header(env : Cwe113Visitor, expr : @syntax.Expr) -> Bool {
  if is_safe_value(expr) {
    return true
  }
  match expr {
    Ident(id~, ..) => {
      let name = match id.name {
        Ident(name~) => name
        Dot(id~, ..) => id
      }
      env.safe_vars.contains(name)
    }
    _ => false
  }
}

///|
fn has_dynamic_header_value(
  env : Cwe113Visitor,
  args : @list.List[@syntax.Argument],
) -> Bool {
  let mut pos_idx = 0
  let mut result = false
  args.each(fn(arg) {
    match arg.kind {
      Labelled(label) =>
        if label.name == "value" && !is_safe_for_header(env, arg.value) {
          result = true
        }
      LabelledPun(_) | LabelledOption(..) | LabelledOptionPun(..) => ()
      _ => {
        if pos_idx == 1 && !is_safe_for_header(env, arg.value) {
          result = true
        }
        pos_idx += 1
      }
    }
  })
  result
}

///|
fn extract_pattern_name(pat : @syntax.Pattern) -> String? {
  match pat {
    Var(binder) => Some(binder.name)
    Constraint(pat~, ..) => extract_pattern_name(pat)
    _ => None
  }
}

///|
impl @syntax.IterVisitor for Cwe113Visitor with fn visit_Expr_Let(
  env,
  pattern~,
  expr~,
  body~,
  loc~,
) {
  match extract_pattern_name(pattern) {
    Some(name) =>
      if is_safe_value(expr) || is_sanitized_expr(expr) {
        env.safe_vars.set(name, true)
      }
    None => ()
  }
  @syntax.IterVisitor::base(env).visit_Expr_Let(pattern~, expr~, body~, loc~)
}

///|
impl @syntax.IterVisitor for Cwe113Visitor with fn visit_Expr_DotApply(
  env,
  self~,
  method_name~,
  args~,
  return_self~,
  loc~,
) {
  if is_header_setter(method_name.name) && has_dynamic_header_value(env, args) {
    env.findings.push(
      make_finding(
        { cwe: 113, variant: "crlf-injection" },
        env.severity,
        Medium,
        "Response header set with dynamic value without CRLF sanitization. Attacker can inject \\r\\n to split the HTTP response, enabling session fixation or XSS.",
        env.file,
        env.source,
        loc,
      ),
    )
  }
  @syntax.IterVisitor::base(env).visit_Expr_DotApply(
    self~,
    method_name~,
    args~,
    return_self~,
    loc~,
  )
}
