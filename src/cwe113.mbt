// CWE-113: HTTP Response Splitting via CRLF Injection.
// Syntax-only review hint retained from the pre-interprocedural scanner.
// Does not establish user control, API identity, or sanitizer semantics.

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
    id: { cwe: 113, variant: "crlf-injection", },
    name: "Dynamic Header Call Review",
    description: "Dynamic header-shaped argument. Confirm API identity and CRLF rejection at the real serialization boundary.",
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
    safe_vars: Map([]),
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
fn is_safe_header_value(env : Cwe113Visitor, expr : @syntax.Expr) -> Bool {
  if is_constant_string(expr) {
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
    Match(cases~, ..) => match_branches_all_constant(cases)
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
        if label.name == "value" && !is_safe_header_value(env, arg.value) {
          result = true
        }
      LabelledPun(_) | LabelledOption(..) | LabelledOptionPun(..) => ()
      _ => {
        if pos_idx == 1 && !is_safe_header_value(env, arg.value) {
          result = true
        }
        pos_idx += 1
      }
    }
  })
  result
}

///|
fn is_all_constant_match(expr : @syntax.Expr) -> Bool {
  match expr {
    Match(cases~, ..) => match_branches_all_constant(cases)
    _ => false
  }
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
    Some(name) => {
      let safe = is_constant_string(expr) ||
        is_sanitized_expr(expr) ||
        is_all_constant_match(expr)
      if safe {
        env.safe_vars[name] = true
      }
    }
    None => ()
  }
  @syntax.IterVisitor::visit_Expr_Let(
    @syntax.IterVisitor::base(env),
    pattern~,
    expr~,
    body~,
    loc~,
  )
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
        { cwe: 113, variant: "crlf-injection", },
        env.severity,
        Low,
        "Dynamic header-shaped argument. Confirm API identity and CRLF rejection at the real serialization boundary.",
        env.file,
        env.source,
        loc,
      ),
    )
  }
  @syntax.IterVisitor::visit_Expr_DotApply(
    @syntax.IterVisitor::base(env),
    self~,
    method_name~,
    args~,
    return_self~,
    loc~,
  )
}
