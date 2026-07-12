// CWE-676: Use of potentially dangerous unsafe_* functions that bypass MoonBit's safety guarantees.
// Filters:
//   - Skip performance-oriented unsafe ops (get/set/blit/reinterpret/read/write/pop)
//     that only skip bounds checks but don't produce potentially invalid values.
//   - Skip when call is inside a guard body — the guard validates input before the unsafe call.
// Only report type-conversion unsafe ops (to_*/from_*/new/cast) that can produce invalid values.

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
fn is_dangerous_unsafe(name : String) -> Bool {
  if !name.has_prefix("unsafe_") {
    return false
  }
  let suffix = name[7:].to_owned()
  if suffix.has_prefix("to_") || suffix.has_prefix("from_") {
    return true
  }
  suffix == "new" || suffix == "cast"
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
  if is_dangerous_unsafe(method_name.name) && !env.in_guard_body {
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
  let unsafe_name = match func {
    Ident(id~, ..) =>
      match id.name {
        Ident(name=n) => n
        Dot(id=n, ..) => n
      }
    Method(method_name~, ..) => method_name.name
    _ => ""
  }
  if is_dangerous_unsafe(unsafe_name) && !env.in_guard_body {
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
