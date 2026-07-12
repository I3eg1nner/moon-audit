// CWE-676: Use of potentially dangerous unsafe_* functions that bypass MoonBit's safety guarantees.
// Filter: skip when call is inside a guard body — the guard validates input before the unsafe call.

///|
priv struct Cwe676Visitor {
  findings : Array[Finding]
  file : String
  source : String
  severity : Severity
  mut in_guard_body : Bool
}

///|
pub fn cwe676_info() -> RuleInfo {
  {
    id: { cwe: 676, variant: "unsafe-call" },
    name: "Use of Potentially Dangerous unsafe_ Function",
    description: "Calls to unsafe_* functions (unsafe_to_char, unsafe_to_byte, etc.) bypass runtime safety checks and may cause undefined behavior on invalid input.",
    default_severity: Warning,
  }
}

///|
pub fn run_cwe676(
  impls : @list.List[@syntax.Impl],
  file : String,
  source : String,
  findings : Array[Finding],
  severity : Severity,
) -> Unit {
  let visitor : Cwe676Visitor = {
    findings,
    file,
    source,
    severity,
    in_guard_body: false,
  }
  impls.each(fn(impl_) { @syntax.IterVisitor::visit_Impl(visitor, impl_) })
}

///|
fn is_unsafe_method_name(name : String) -> Bool {
  name.has_prefix("unsafe_")
}

///|
impl @syntax.IterVisitor for Cwe676Visitor with fn visit_Expr_Guard(
  env,
  cond~,
  otherwise~,
  body~,
  loc~,
) {
  let _ = loc
  env.base().visit_Expr(cond)
  match otherwise {
    Some(else_expr) => env.base().visit_Expr(else_expr)
    None => ()
  }
  let prev = env.in_guard_body
  env.in_guard_body = true
  env.base().visit_Expr(body)
  env.in_guard_body = prev
}

///|
impl @syntax.IterVisitor for Cwe676Visitor with fn visit_Expr_DotApply(
  env,
  self~,
  method_name~,
  args~,
  return_self~,
  loc~,
) {
  if is_unsafe_method_name(method_name.name) && !env.in_guard_body {
    env.findings.push(
      make_finding(
        { cwe: 676, variant: "unsafe-call" },
        env.severity,
        High,
        "unsafe_* function bypasses runtime safety checks. Ensure input is validated before this call, or use a safe alternative.",
        env.file,
        env.source,
        loc,
      ),
    )
  }
  env.base().visit_Expr_DotApply(self~, method_name~, args~, return_self~, loc~)
}

///|
impl @syntax.IterVisitor for Cwe676Visitor with fn visit_Expr_Apply(
  env,
  func~,
  args~,
  loc~,
) {
  let is_unsafe = match func {
    Ident(id~, ..) =>
      match id.name {
        Ident(name=n) => is_unsafe_method_name(n)
        Dot(id=n, ..) => is_unsafe_method_name(n)
      }
    Method(method_name~, ..) => is_unsafe_method_name(method_name.name)
    _ => false
  }
  if is_unsafe && !env.in_guard_body {
    env.findings.push(
      make_finding(
        { cwe: 676, variant: "unsafe-call" },
        env.severity,
        High,
        "unsafe_* function bypasses runtime safety checks. Ensure input is validated before this call, or use a safe alternative.",
        env.file,
        env.source,
        loc,
      ),
    )
  }
  env.base().visit_Expr_Apply(func~, args~, loc~)
}
