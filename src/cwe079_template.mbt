// CWE-79: Template injection via string interpolation in HTML context.
// Detects route handlers that return HTML with string interpolation
// containing route parameters or user input without encoding.

///|
priv struct Cwe079TemplateVisitor {
  findings : Array[Finding]
  file : String
  source : String
  severity : Severity
}

///|
pub fn cwe079_template_info() -> RuleInfo {
  {
    id: { cwe: 79, variant: "template-injection", },
    name: "HTML Interpolation Review",
    description: "HTML-shaped call contains string interpolation. Review API identity, input origin, output context and whether this response is returned.",
    default_severity: Error,
  }
}

///|
pub fn run_cwe079_template(
  impls : @list.List[@syntax.Impl],
  file : String,
  source : String,
  findings : Array[Finding],
  severity : Severity,
) -> Unit {
  if !source.contains("text/html") && !source.contains("html(") {
    return
  }
  let visitor : Cwe079TemplateVisitor = { findings, file, source, severity, }
  impls.each(fn(impl_) { @syntax.IterVisitor::visit_Impl(visitor, impl_) })
}

///|
fn is_html_response_func(func : @syntax.Expr) -> Bool {
  match func {
    Ident(id~, ..) =>
      match id.name {
        Ident(name="html") => true
        Dot(id="html", ..) => true
        _ => false
      }
    _ => false
  }
}

///|
fn has_interpolation(expr : @syntax.Expr) -> Bool {
  match expr {
    Interp(..) => true
    _ => false
  }
}

///|
impl @syntax.IterVisitor for Cwe079TemplateVisitor with fn visit_Expr_Apply(
  env,
  func~,
  args~,
  loc~,
) {
  if is_html_response_func(func) {
    let has_dynamic = args.any(fn(arg) { has_interpolation(arg.value) })
    if has_dynamic {
      env.findings.push(
        make_finding(
          { cwe: 79, variant: "template-injection", },
          env.severity,
          Medium,
          "HTML-shaped call contains string interpolation. Review API identity, input origin, output context and whether this response is returned.",
          env.file,
          env.source,
          loc,
        ),
      )
    }
  }
  @syntax.IterVisitor::visit_Expr_Apply(
    @syntax.IterVisitor::base(env),
    func~,
    args~,
    loc~,
  )
}

///|
impl @syntax.IterVisitor for Cwe079TemplateVisitor with fn visit_Expr_DotApply(
  env,
  self~,
  method_name~,
  args~,
  return_self~,
  loc~,
) {
  if method_name.name == "html" {
    let has_dynamic = args.any(fn(arg) { has_interpolation(arg.value) })
    if has_dynamic {
      env.findings.push(
        make_finding(
          { cwe: 79, variant: "template-injection", },
          env.severity,
          Medium,
          "HTML-shaped call contains string interpolation. Review API identity, input origin, output context and whether this response is returned.",
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
