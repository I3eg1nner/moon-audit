// CWE-248: calls named panic/abort are syntax hints, not resolved runtime facts.
// As of 2026-09-28 the legacy noise heuristics (guard-else containment, unwrap
// function names, message keywords such as "unreachable"/"invalid", zero-arg
// panic and .wasm/.js/.native filename suffixes) no longer suppress findings:
// none of them proved unreachability, and they hid actually reachable
// terminations. Every bare, unqualified panic/abort call in parsed selected
// sources is now reported as a candidate.

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
    id: { cwe: 248, variant: "panic-reachable", },
    name: "Panic/Abort Syntax in Library Code",
    description: "Call named panic/abort may terminate execution if it resolves to the builtin. Review reachability and input conditions; bare calls in parsed selected sources are reported without further syntactic exemption.",
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
  let visitor : Cwe248Visitor = { findings, file, source, severity, }
  impls.each(fn(impl_) { @syntax.IterVisitor::visit_Impl(visitor, impl_) })
}

///|
fn get_panic_kind(func : @syntax.Expr) -> String {
  match func {
    Ident(id~, ..) =>
      match id.name {
        Ident(name="panic") => "panic"
        Ident(name="abort") => "abort"
        _ => ""
      }
    _ => ""
  }
}

///|
impl @syntax.IterVisitor for Cwe248Visitor with fn visit_Expr_Apply(
  env,
  func~,
  args~,
  loc~,
) {
  if get_panic_kind(func) != "" {
    env.findings.push(
      make_finding(
        { cwe: 248, variant: "panic-reachable", },
        env.severity,
        Medium,
        "Call named panic/abort may terminate execution if it resolves to the builtin. Review reachability and input conditions; bare calls in parsed selected sources are reported without further syntactic exemption.",
        env.file,
        env.source,
        loc,
      ),
    )
  }
  @syntax.IterVisitor::visit_Expr_Apply(
    @syntax.IterVisitor::base(env),
    func~,
    args~,
    loc~,
  )
}
