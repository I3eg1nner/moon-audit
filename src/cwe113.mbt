// CWE-113: HTTP Response Splitting via CRLF Injection.
// Detects when user-controlled input is passed to response header setters
// without CRLF sanitization.

///|
pub fn cwe113_info() -> RuleInfo {
  {
    id: { cwe: 113, variant: "crlf-injection" },
    name: "HTTP Response Splitting via CRLF Injection",
    description: "Response header values set from user input without CRLF (\\r\\n) sanitization allow HTTP response splitting, enabling session fixation, XSS, and cache poisoning.",
    default_severity: Error,
  }
}

///|
pub fn run_cwe113(
  impls : @list.List[@syntax.Impl],
  file : String,
  source : String,
  findings : Array[Finding],
  severity : Severity,
) -> Unit {
  // M2: flow-sensitive engine replaces the IterVisitor heuristic walk.
  // Taint state is threaded through control flow with branch merging and
  // guard refinement (see taint_flow.mbt); the old textual safe-vars
  // heuristic is retained below only for the legacy summary path.
  for item in impls {
    match item {
      TopFuncDef(fun_decl~, decl_body~, ..) =>
        match decl_body {
          DeclBody(expr=Function(func~, ..)) =>
            run_flow_taint_func(
              Some(func.parameters),
              func.body,
              file,
              source,
              severity,
              findings,
            )
          DeclBody(expr=body) =>
            run_flow_taint_func(
              fun_decl.decl_params,
              body,
              file,
              source,
              severity,
              findings,
            )
          _ => ()
        }
      TopImpl(params~, body~, ..) =>
        match body {
          DeclBody(expr=Function(func~, ..)) =>
            run_flow_taint_func(
              Some(func.parameters),
              func.body,
              file,
              source,
              severity,
              findings,
            )
          DeclBody(expr=body) =>
            run_flow_taint_func(
              Some(params),
              body,
              file,
              source,
              severity,
              findings,
            )
          _ => ()
        }
      TopExpr(expr~, ..) =>
        run_flow_taint_func_top(expr, file, source, severity, findings)
      _ => ()
    }
  }
}

///|
fn is_header_setter(method_name : String) -> Bool {
  method_name == "set_header" ||
  method_name == "add_header" ||
  method_name == "append_header" ||
  method_name == "set_response_header"
}

///|
fn extract_pattern_name(pat : @syntax.Pattern) -> String? {
  match pat {
    Var(binder) => Some(binder.name)
    Constraint(pat~, ..) => extract_pattern_name(pat)
    _ => None
  }
}
