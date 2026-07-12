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
    id: { cwe: 704, variant: "unsafe-cast" },
    name: "Unchecked Type Cast",
    description: ".cast() bypasses type checking at runtime. Invalid casts can produce corrupted values or undefined behavior.",
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
  let visitor : Cwe704Visitor = { findings, file, source, severity }
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
        { cwe: 704, variant: "unsafe-cast" },
        env.severity,
        Medium,
        "Unchecked .cast() bypasses type safety. The result may be invalid if the underlying value does not match the target type.",
        env.file,
        env.source,
        loc,
      ),
    )
  }
  env.base().visit_Expr_DotApply(self~, method_name~, args~, return_self~, loc~)
}
