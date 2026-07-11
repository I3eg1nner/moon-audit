// CWE-79: cmark render() defaults to safe=false, allowing raw HTML/script injection.
// Only activated when cmark package is imported.

///|
priv struct Cwe079CmarkVisitor {
  findings : Array[Finding]
  file : String
  source : String
  severity : Severity
}

///|
pub fn cwe079_cmark_info() -> RuleInfo {
  {
    id: { cwe: 79, variant: "cmark-unsafe" },
    name: "Unsafe Default in cmark HTML Rendering",
    description: "cmark's render()/from_doc() defaults to safe=false, passing raw HTML and javascript: URLs through to output.",
    default_severity: Error,
  }
}

///|
pub fn run_cwe079_cmark(
  impls : @list.List[@syntax.Impl],
  file : String,
  source : String,
  findings : Array[Finding],
  severity : Severity,
) -> Unit {
  let visitor : Cwe079CmarkVisitor = { findings, file, source, severity }
  impls.each(fn(impl_) { @syntax.IterVisitor::visit_Impl(visitor, impl_) })
}

///|
fn is_cmark_render_func(func : @syntax.Expr) -> Bool {
  match func {
    Ident(id~, ..) =>
      match id.name {
        Ident(name="render") | Ident(name="from_doc") => true
        Dot(id="render", ..) | Dot(id="from_doc", ..) => true
        _ => false
      }
    _ => false
  }
}

///|
impl @syntax.IterVisitor for Cwe079CmarkVisitor with fn visit_Expr_Apply(
  env,
  func~,
  args~,
  loc~,
) {
  if is_cmark_render_func(func) {
    let has_safe_true = has_labelled_bool_arg(args, "safe", true)
    if !has_safe_true {
      env.findings.push(
        make_finding(
          { cwe: 79, variant: "cmark-unsafe" },
          env.severity,
          "cmark render()/from_doc() defaults to safe=false. Raw HTML and javascript: URLs pass through. Add safe=true explicitly.",
          env.file,
          env.source,
          loc,
        ),
      )
    }
  }
  env.base().visit_Expr_Apply(func~, args~, loc~)
}
