// CWE-704: Incorrect Type Conversion — .cast() bypasses MoonBit's type system.
// Filter: skip files containing extern "js" — FFI bindings require .cast() as the only conversion mechanism.

///|
priv struct Cwe704Visitor {
  findings : Array[Finding]
  file : String
  source : String
  severity : Severity
}

///|
pub fn cwe704_info() -> RuleInfo {
  {
    id: { cwe: 704, variant: "unsafe-cast", },
    name: "Cast-named Method Review",
    description: "Method name suggests a cast. Resolve its declaration and conversion guarantees before treating it as a type-safety issue.",
    default_severity: Warning,
  }
}

///|
pub fn run_cwe704(
  impls : @list.List[@syntax.Impl],
  file : String,
  source : String,
  findings : Array[Finding],
  severity : Severity,
) -> Unit {
  if is_ffi_file(source) {
    return
  }
  let visitor : Cwe704Visitor = { findings, file, source, severity, }
  impls.each(fn(impl_) { @syntax.IterVisitor::visit_Impl(visitor, impl_) })
}

///|
fn is_ffi_file(source : String) -> Bool {
  source.contains("extern \"js\"") ||
  source.contains("extern \"javascript\"") ||
  source.contains("#external")
}

///|
impl @syntax.IterVisitor for Cwe704Visitor with fn visit_Expr_DotApply(
  env,
  self~,
  method_name~,
  args~,
  return_self~,
  loc~,
) {
  if method_name.name == "cast" || method_name.name == "reinterpret_cast" {
    env.findings.push(
      make_finding(
        { cwe: 704, variant: "unsafe-cast", },
        env.severity,
        Medium,
        "Method name suggests a cast. Resolve its declaration and conversion guarantees before treating it as a type-safety issue.",
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
