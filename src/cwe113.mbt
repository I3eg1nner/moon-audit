// CWE-113: HTTP Response Splitting via CRLF Injection.
// Detects when user-controlled input is passed to response header setters
// without CRLF sanitization.

///|
pub fn cwe113_info() -> RuleInfo {
  {
    id: { cwe: 113, variant: "crlf-injection", },
    name: "HTTP Response Splitting via CRLF Injection",
    description: "Response header values set from user input without CRLF (\\r\\n) sanitization allow HTTP response splitting, enabling session fixation, XSS, and cache poisoning.",
    default_severity: Error,
  }
}

///|
fn call_flow(
  params : @list.List[@syntax.Parameter]?,
  body : @syntax.Expr,
  file : String,
  source : String,
  severity : Severity,
  findings : Array[Finding],
  ictx : InterProceduralContext?,
  rules : TaintRuleset,
  output_sinks : Bool,
) -> Unit {
  match ictx {
    Some(i) =>
      run_flow_taint_func(
        params,
        body,
        file,
        source,
        severity,
        findings,
        ictx=i,
        rules~,
        output_sinks_enabled=output_sinks,
      )
    None =>
      run_flow_taint_func(
        params,
        body,
        file,
        source,
        severity,
        findings,
        rules~,
        output_sinks_enabled=output_sinks,
      )
  }
}

///|
pub fn run_cwe113(
  impls : @list.List[@syntax.Impl],
  file : String,
  source : String,
  findings : Array[Finding],
  severity : Severity,
  ictx? : InterProceduralContext,
  rules? : TaintRuleset,
  output_sinks_enabled? : Bool,
) -> Unit {
  // M2: flow-sensitive engine replaces the IterVisitor heuristic walk.
  // Taint state is threaded through control flow with branch merging and
  // guard refinement (see taint_flow.mbt); the old textual safe-vars
  // heuristic is retained below only for the legacy summary path.
  // P3: ictx enables field-write summary consumption at call sites.
  // DSL: project taint ruleset ADD to built-ins (empty = built-ins only)
  let rules = match rules {
    Some(r) => r
    None => TaintRuleset::empty()
  }
  let output_sinks = match output_sinks_enabled {
    Some(b) => b
    None => true
  }
  for item in impls {
    match item {
      TopFuncDef(fun_decl~, decl_body~, ..) =>
        match decl_body {
          DeclBody(expr=Function(func~, ..)) =>
            call_flow(
              Some(func.parameters),
              func.body,
              file,
              source,
              severity,
              findings,
              ictx,
              rules,
              output_sinks,
            )
          DeclBody(expr=body) =>
            call_flow(
              fun_decl.decl_params,
              body,
              file,
              source,
              severity,
              findings,
              ictx,
              rules,
              output_sinks,
            )
          _ => ()
        }
      TopImpl(params~, body~, ..) =>
        match body {
          DeclBody(expr=Function(func~, ..)) =>
            call_flow(
              Some(func.parameters),
              func.body,
              file,
              source,
              severity,
              findings,
              ictx,
              rules,
              output_sinks,
            )
          DeclBody(expr=body) =>
            call_flow(
              Some(params),
              body,
              file,
              source,
              severity,
              findings,
              ictx,
              rules,
              output_sinks,
            )
          _ => ()
        }
      TopExpr(expr~, ..) =>
        run_flow_taint_func_top(
          expr,
          file,
          source,
          severity,
          findings,
          rules~,
          output_sinks_enabled=output_sinks,
        )
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
