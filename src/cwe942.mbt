// CWE-942: CORS misconfiguration — wildcard origin or credentials without origin restriction.
// Only activated when mocket or crescent is imported.

///|
priv struct Cwe942Visitor {
  findings : Array[Finding]
  file : String
  source : String
}

///|
pub fn cwe942_info() -> RuleInfo {
  {
    id: { cwe: 942, variant: "cors-credentials" },
    name: "Permissive CORS Configuration",
    description: "handle_cors() without explicit origin defaults to '*', allowing any website to read responses. With credentials=true this enables credential theft.",
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
  let _ = severity
  let visitor : Cwe942Visitor = { findings, file, source }
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
      // Only flag when credentials=true with wildcard — that's the real attack vector.
      // Wildcard without credentials is standard for public APIs.
      if has_credentials_true {
        env.findings.push(
          make_finding(
            { cwe: 942, variant: "cors-credentials" },
            Error,
            High,
            "CORS with credentials=true and wildcard origin allows any website to make authenticated requests and read responses. Specify an explicit origin.",
            env.file,
            env.source,
            loc,
          ),
        )
      }
    }
  }
  @syntax.IterVisitor::base(env).visit_Expr_Apply(func~, args~, loc~)
}
