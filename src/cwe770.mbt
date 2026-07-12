// CWE-770: Server started without body size limit.
// Only activated when mocket or crescent is imported.

///|
priv struct Cwe770Visitor {
  findings : Array[Finding]
  file : String
  source : String
  severity : Severity
}

///|
pub fn cwe770_info() -> RuleInfo {
  {
    id: { cwe: 770, variant: "no-body-limit" },
    name: "Missing Request Body Size Limit",
    description: "Server listen()/serve() without max body size limit is vulnerable to memory exhaustion via large request bodies.",
    default_severity: Warning,
  }
}

///|
pub fn run_cwe770(
  impls : @list.List[@syntax.Impl],
  file : String,
  source : String,
  findings : Array[Finding],
  severity : Severity,
) -> Unit {
  if !source.contains(".post(") &&
    !source.contains(".put(") &&
    !source.contains(".patch(") {
    return
  }
  let visitor : Cwe770Visitor = { findings, file, source, severity }
  impls.each(fn(impl_) { @syntax.IterVisitor::visit_Impl(visitor, impl_) })
}

///|
fn is_server_start_method(name : String) -> Bool {
  name == "serve" || name == "listen" || name == "serve_async"
}

///|
impl @syntax.IterVisitor for Cwe770Visitor with fn visit_Expr_DotApply(
  env,
  self~,
  method_name~,
  args~,
  return_self~,
  loc~,
) {
  if is_server_start_method(method_name.name) {
    if !has_labelled_arg(args, "max_request_body_bytes") &&
      !has_labelled_arg(args, "max_body_size") &&
      !has_labelled_arg(args, "body_limit") {
      env.findings.push(
        make_finding(
          { cwe: 770, variant: "no-body-limit" },
          env.severity,
          Medium,
          "Server started without request body size limit. Large payloads can exhaust memory. Set a max body size.",
          env.file,
          env.source,
          loc,
        ),
      )
    }
  }
  env.base().visit_Expr_DotApply(self~, method_name~, args~, return_self~, loc~)
}
