// CWE-116: String::replace() used for HTML/security escaping
// MoonBit's replace() only replaces the FIRST occurrence.
// Must use replace_all() for security escaping.

///|
priv struct Cwe116Visitor {
  findings : Array[Finding]
  file : String
  source : String
  severity : Severity
}

///|
pub fn cwe116_info() -> RuleInfo {
  {
    id: { cwe: 116, variant: "replace-escaping" },
    name: "Incomplete HTML Escaping via String::replace",
    description: "String::replace() only replaces the first occurrence in MoonBit. When used with HTML special characters (<, >, &, etc.), subsequent occurrences remain unescaped, enabling XSS bypass.",
    default_severity: Error,
  }
}

///|
pub fn run_cwe116(
  impls : @list.List[@syntax.Impl],
  file : String,
  source : String,
  findings : Array[Finding],
  severity : Severity,
) -> Unit {
  let visitor : Cwe116Visitor = { findings, file, source, severity }
  impls.each(fn(impl_) { @syntax.IterVisitor::visit_Impl(visitor, impl_) })
}

///|
impl @syntax.IterVisitor for Cwe116Visitor with fn visit_Expr_DotApply(
  env,
  self~,
  method_name~,
  args~,
  return_self~,
  loc~,
) {
  if method_name.name == "replace" && is_security_relevant_replace(args) {
    env.findings.push(
      make_finding(
        { cwe: 116, variant: "replace-escaping" },
        env.severity,
        High,
        "String::replace() only replaces the first occurrence. Use replace_all() for HTML escaping to prevent XSS bypass.",
        env.file,
        env.source,
        loc,
      ),
    )
  }
  env.base().visit_Expr_DotApply(self~, method_name~, args~, return_self~, loc~)
}
