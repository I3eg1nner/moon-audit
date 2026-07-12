// CWE-248: panic()/abort() in library code can crash the entire program.
// Flagged in non-main, non-test files where callers cannot recover.

///|
priv struct Cwe248Visitor {
  findings : Array[Finding]
  file : String
  source : String
  severity : Severity
}

///|
pub fn cwe248_info() -> RuleInfo {
  {
    id: { cwe: 248, variant: "panic-reachable" },
    name: "Reachable panic/abort in Library Code",
    description: "panic() or abort() in library code terminates the program. Callers cannot recover. Use Result/Option or raise an error instead.",
    default_severity: Warning,
  }
}

///|
pub fn run_cwe248(
  impls : @list.List[@syntax.Impl],
  file : String,
  source : String,
  findings : Array[Finding],
  severity : Severity,
) -> Unit {
  let visitor : Cwe248Visitor = { findings, file, source, severity }
  impls.each(fn(impl_) { @syntax.IterVisitor::visit_Impl(visitor, impl_) })
}

///|
fn is_panic_func(func : @syntax.Expr) -> Bool {
  match func {
    Ident(id~, ..) =>
      match id.name {
        Ident(name="panic") | Ident(name="abort") => true
        _ => false
      }
    _ => false
  }
}

///|
impl @syntax.IterVisitor for Cwe248Visitor with fn visit_Expr_Apply(
  env,
  func~,
  args~,
  loc~,
) {
  if is_panic_func(func) {
    env.findings.push(
      make_finding(
        { cwe: 248, variant: "panic-reachable" },
        env.severity,
        Medium,
        "panic()/abort() terminates the program. In library code, prefer returning Result or raising an error so callers can handle the failure.",
        env.file,
        env.source,
        loc,
      ),
    )
  }
  env.base().visit_Expr_Apply(func~, args~, loc~)
}
