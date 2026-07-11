// CWE-942: CORS credentials=true without explicit origin allows credential theft.
// Only activated when mocket or crescent is imported.

///|
priv struct Cwe942Visitor {
  findings : Array[Finding]
  file : String
  source : String
  severity : Severity
}

///|
pub fn cwe942_info() -> RuleInfo {
  {
    id: { cwe: 942, variant: "cors-credentials" },
    name: "CORS Credentials with Wildcard Origin",
    description: "handle_cors(credentials=true) without explicit origin reflects any Origin header, enabling credential theft from any website.",
    default_severity: Error,
  }
}

///|
pub fn run_cwe942(
  impls : @list.List[@syntax.Impl],
  file : String,
  source : String,
  findings : Array[Finding],
  severity : Severity,
) -> Unit {
  let visitor : Cwe942Visitor = { findings, file, source, severity }
  impls.each(fn(impl_) { @syntax.IterVisitor::visit_Impl(visitor, impl_) })
}

///|
fn is_cors_func(func : @syntax.Expr) -> Bool {
  match func {
    Ident(id~, ..) =>
      match id.name {
        Ident(name="handle_cors")
        | Ident(name="append_cors_preflight_headers") => true
        Dot(id="handle_cors", ..)
        | Dot(id="append_cors_preflight_headers", ..) => true
        _ => false
      }
    _ => false
  }
}

///|
impl @syntax.IterVisitor for Cwe942Visitor with fn visit_Expr_Apply(
  env,
  func~,
  args~,
  loc~,
) {
  if is_cors_func(func) {
    let has_credentials_true = has_labelled_bool_arg(args, "credentials", true)
    if has_credentials_true {
      let has_explicit_origin = match
        get_labelled_string_value(args, "origin") {
        Some(v) => v != "*"
        None => false
      }
      if !has_explicit_origin {
        env.findings.push(
          make_finding(
            { cwe: 942, variant: "cors-credentials" },
            env.severity,
            "CORS with credentials=true and default/wildcard origin reflects any Origin header. Specify an explicit origin to prevent credential theft.",
            env.file,
            env.source,
            loc,
          ),
        )
      }
    }
  }
  env.base().visit_Expr_Apply(func~, args~, loc~)
}
