// CWE-79: cmark render()/from_doc()/renderer() with explicit safe=false allows raw HTML/script injection.
// render() defaults to safe=true since cmark update; only explicit safe=false is unsafe.
// from_doc()/renderer()/xhtml_renderer() require safe~ explicitly.

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
    name: "Explicit Unsafe HTML Rendering in cmark",
    description: "cmark render()/from_doc()/renderer() called with safe=false, allowing raw HTML and javascript: URLs in output.",
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
        Ident(name="render")
        | Ident(name="from_doc")
        | Ident(name="renderer")
        | Ident(name="xhtml_renderer") => true
        Dot(id="render", ..)
        | Dot(id="from_doc", ..)
        | Dot(id="renderer", ..)
        | Dot(id="xhtml_renderer", ..) => true
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
    let has_safe_false = has_labelled_bool_arg(args, "safe", false)
    if has_safe_false {
      env.findings.push(
        make_finding(
          { cwe: 79, variant: "cmark-unsafe" },
          env.severity,
          High,
          "cmark called with safe=false. Raw HTML and javascript: URLs pass through to output. Remove safe=false or set safe=true.",
          env.file,
          env.source,
          loc,
        ),
      )
    }
  }
  env.base().visit_Expr_Apply(func~, args~, loc~)
}
