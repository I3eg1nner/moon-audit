// CWE-79: inner_html() with non-constant argument is an XSS sink.
// Only activated when rabbita package is imported.

///|
priv struct Cwe079InnerHtmlVisitor {
  findings : Array[Finding]
  file : String
  source : String
  severity : Severity
}

///|
pub fn cwe079_inner_html_info() -> RuleInfo {
  {
    id: { cwe: 79, variant: "inner-html" },
    name: "XSS via inner_html with Dynamic Content",
    description: "inner_html() injects raw HTML. Non-constant arguments may contain user-controlled content enabling XSS.",
    default_severity: Error,
  }
}

///|
pub fn run_cwe079_inner_html(
  impls : @list.List[@syntax.Impl],
  file : String,
  source : String,
  findings : Array[Finding],
  severity : Severity,
) -> Unit {
  let visitor : Cwe079InnerHtmlVisitor = { findings, file, source, severity }
  impls.each(fn(impl_) { @syntax.IterVisitor::visit_Impl(visitor, impl_) })
}

///|
impl @syntax.IterVisitor for Cwe079InnerHtmlVisitor with fn visit_Expr_DotApply(
  env,
  self~,
  method_name~,
  args~,
  return_self~,
  loc~,
) {
  if method_name.name == "inner_html" {
    let first_arg_is_constant = match args {
      More({ value: Constant(c=String(_), ..), .. }, ..) => true
      _ => false
    }
    if !first_arg_is_constant {
      env.findings.push(
        make_finding(
          { cwe: 79, variant: "inner-html" },
          env.severity,
          "inner_html() with non-constant argument is an XSS sink. User-controlled content will be injected as raw HTML.",
          env.file,
          env.source,
          loc,
        ),
      )
    }
  }
  env.base().visit_Expr_DotApply(self~, method_name~, args~, return_self~, loc~)
}
