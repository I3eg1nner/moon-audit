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
    id: { cwe: 79, variant: "inner-html", },
    name: "Dynamic inner_html Call Review",
    description: "Method named inner_html receives an expression. Confirm it is a raw HTML API and inspect where its input originates.",
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
  let visitor : Cwe079InnerHtmlVisitor = { findings, file, source, severity, }
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
    let first_arg_is_safe = match args {
      More({ value: Constant(c=String(_), ..), .. }, ..) => true
      More({ value: Ident(id~, ..), .. }, ..) => is_constant_ident(id.name)
      _ => false
    }
    if !first_arg_is_safe {
      env.findings.push(
        make_finding(
          { cwe: 79, variant: "inner-html", },
          env.severity,
          Medium,
          "Method named inner_html receives an expression. Confirm it is a raw HTML API and inspect where its input originates.",
          env.file,
          env.source,
          loc,
        ),
      )
    }
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
