// CWE-614: Cookie set without security attributes (HttpOnly, Secure, SameSite).
// Only activated when mocket or crescent is imported.

///|
priv struct Cwe614Visitor {
  findings : Array[Finding]
  file : String
  source : String
  severity : Severity
}

///|
pub fn cwe614_info() -> RuleInfo {
  {
    id: { cwe: 614, variant: "cookie-attrs" },
    name: "Cookie Missing Security Attributes",
    description: "set_cookie() without http_only, secure, or same_site attributes leaves cookies vulnerable to theft and CSRF.",
    default_severity: Warning,
  }
}

///|
pub fn run_cwe614(
  impls : @list.List[@syntax.Impl],
  file : String,
  source : String,
  findings : Array[Finding],
  severity : Severity,
) -> Unit {
  let visitor : Cwe614Visitor = { findings, file, source, severity }
  impls.each(fn(impl_) { @syntax.IterVisitor::visit_Impl(visitor, impl_) })
}

///|
impl @syntax.IterVisitor for Cwe614Visitor with fn visit_Expr_DotApply(
  env,
  self~,
  method_name~,
  args~,
  return_self~,
  loc~,
) {
  if method_name.name == "set_cookie" && !is_cookie_value_empty(args) {
    let missing : Array[String] = []
    if !has_labelled_arg(args, "http_only") {
      missing.push("http_only")
    }
    if !has_labelled_arg(args, "secure") {
      missing.push("secure")
    }
    if !has_labelled_arg(args, "same_site") {
      missing.push("same_site")
    }
    if missing.length() > 0 {
      let attrs = missing.iter().map(fn(s) { s }).collect().join(", ")
      env.findings.push(
        make_finding(
          { cwe: 614, variant: "cookie-attrs" },
          env.severity,
          "set_cookie() missing security attributes: " +
          attrs +
          ". Add these to protect against XSS cookie theft and CSRF.",
          env.file,
          env.source,
          loc,
        ),
      )
    }
  }
  env.base().visit_Expr_DotApply(self~, method_name~, args~, return_self~, loc~)
}
