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
  // F2 (T7.2): optional per-function result cache
  cache? : FnCache,
  symbols_fp? : String,
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
  let c = match cache {
    Some(c) => c
    None => FnCache::new() // no cache: each lookup misses → normal path
  }
  let fp = match symbols_fp {
    Some(f) => f
    None => "-"
  }
  for item in impls {
    match item {
      TopFuncDef(fun_decl~, decl_body~, ..) => {
        let fn_key = fun_decl.name.name
        let (params, body) = match decl_body {
          DeclBody(expr=Function(func~, ..)) =>
            (Some(func.parameters), func.body)
          DeclBody(expr=b) => (fun_decl.decl_params, b)
          _ => (None, b_dummy())
        }
        match decl_body {
          DeclBody(..) => {
            let bh = fn_body_hash(fn_key, body_loc_repr(body))
            match c.lookup(file, fn_key, bh, fp) {
              Some(cached) =>
                for f in cached {
                  findings.push(f)
                }
              None => {
                let base = findings.length()
                call_flow(
                  params, body, file, source, severity, findings, ictx, rules, output_sinks,
                )
                let contrib : Array[Finding] = []
                let mut i = base
                while i < findings.length() {
                  contrib.push(findings[i])
                  i += 1
                }
                c.store(file, fn_key, bh, fp, contrib, 0)
              }
            }
          }
          _ => ()
        }
      }
      TopImpl(method_name~, params~, body~, ..) => {
        let fn_key = method_name.name
        let (params2, body2) = match body {
          DeclBody(expr=Function(func~, ..)) =>
            (Some(func.parameters), func.body)
          DeclBody(expr=b) => (Some(params), b)
          _ => (None, b_dummy())
        }
        match body {
          DeclBody(..) => {
            let bh = fn_body_hash(fn_key, body_loc_repr(body2))
            match c.lookup(file, fn_key, bh, fp) {
              Some(cached) =>
                for f in cached {
                  findings.push(f)
                }
              None => {
                let base = findings.length()
                call_flow(
                  params2, body2, file, source, severity, findings, ictx, rules,
                  output_sinks,
                )
                let contrib : Array[Finding] = []
                let mut i = base
                while i < findings.length() {
                  contrib.push(findings[i])
                  i += 1
                }
                c.store(file, fn_key, bh, fp, contrib, 0)
              }
            }
          }
          _ => ()
        }
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

///|
fn b_dummy() -> @syntax.Expr {
  Unit(loc=unit_dummy_loc(), faked=false)
}

///|
fn unit_dummy_loc() -> @basic.Location {
  {
    start: { fname: "", lnum: 0, bol: 0, cnum: 0, },
    end: { fname: "", lnum: 0, bol: 0, cnum: 0, },
  }
}

// lightweight body repr: loc + structural discriminant (no Show on Expr)

///|
fn body_loc_repr(body : @syntax.Expr) -> String {
  let loc = body.loc()
  loc.start.lnum.to_string() +
  "-" +
  loc.end.lnum.to_string() +
  ":" +
  body_variant_tag(body)
}

///|
fn body_variant_tag(e : @syntax.Expr) -> String {
  match e {
    If(..) => "If"
    Match(..) => "Match"
    Let(..) => "Let"
    Sequence(..) => "Seq"
    Guard(..) => "Guard"
    Try(..) => "Try"
    While(..) => "While"
    _ => "E"
  }
}
