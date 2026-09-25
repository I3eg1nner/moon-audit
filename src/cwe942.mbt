// CWE-942: CORS misconfiguration — wildcard origin or credentials without origin restriction.
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
    id: { cwe: 942, variant: "cors-credentials", },
    name: "Permissive CORS Configuration",
    description: "CORS-shaped call combines credentials=true with wildcard or unresolved origin. Browsers reject credentialed wildcard response sharing; review intended origin policy, reflected origins and availability.",
    default_severity: Warning,
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
  let visitor : Cwe942Visitor = { findings, file, source, severity, }
  impls.each(fn(impl_) { @syntax.IterVisitor::visit_Impl(visitor, impl_) })
}

///|
fn is_cors_func(func : @syntax.Expr) -> Bool {
  match func {
    Ident(id~, ..) =>
      match id.name {
        Ident(name="handle_cors")
        | Ident(name="append_cors_preflight_headers")
        | Ident(name="append_cors_headers") => true
        Dot(id="handle_cors", ..)
        | Dot(id="append_cors_preflight_headers", ..)
        | Dot(id="append_cors_headers", ..) => true
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
    let has_explicit_origin = match get_labelled_string_value(args, "origin") {
      Some(v) => v != "*"
      None => false
    }
    if !has_explicit_origin {
      let has_credentials_true = has_labelled_bool_arg(
        args, "credentials", true,
      )
      // This combination warrants configuration review; it does not prove disclosure.
      // Wildcard without credentials is standard for public APIs.
      if has_credentials_true {
        env.findings.push(
          make_finding(
            { cwe: 942, variant: "cors-credentials", },
            env.severity,
            High,
            "CORS-shaped call combines credentials=true with wildcard or unresolved origin. Browsers reject credentialed wildcard response sharing; review intended origin policy, reflected origins and availability.",
            env.file,
            env.source,
            loc,
          ),
        )
      }
    }
  }
  @syntax.IterVisitor::visit_Expr_Apply(
    @syntax.IterVisitor::base(env),
    func~,
    args~,
    loc~,
  )
}
