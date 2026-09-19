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
  pkg_root : String,
  cfg_engine : Bool, // PROD-1: true = exec_independent primary, AST fallback
) -> Unit {
  if cfg_engine {
    // PROD-1: build BlockIr from the AST, run exec_independent, and use
    // its findings directly; fall back to AST flow on validation failure
    let fn_name = "fn"
    let ir = build_block_ir(fn_name, body, rules~)
    let errs = validate_cfg(ir)
    if errs.length() == 0 {
      // entry taints: all params conservatively tainted (callback semantics)
      let param_taints : Array[(String, Taint)] = []
      match params {
        Some(ps) =>
          for p in ps {
            match p {
              Positional(binder~, ..)
              | Labelled(binder~, ..)
              | Optional(binder~, ..)
              | QuestionOptional(binder~, ..) =>
                param_taints.push((binder.name, Tainted))
              DiscardPositional(..) => ()
            }
          }
        None => ()
      }
      let ictx_opt = match ictx {
        Some(i) => Some(i)
        None => None
      }
      let cfg_findings = exec_independent(ir, param_taints, rules, ictx_opt)
      for f in cfg_findings {
        findings.push(f)
      }
      return // success: no AST fallback needed
    }
    // validation failure: fall through to AST flow below (disclosed as fallback)
  }
  match ictx {
    Some(i) =>
      run_flow_taint_func(
        params,
        body,
        file,
        source,
        severity,
        findings,
        pkg_root~,
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
        pkg_root~,
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
  pkg_root? : String = "",
  // PROD-1: cfg_engine flag — use exec_independent as primary producer
  cfg_engine? : Bool = false,
  // F2 (T7.2): optional per-function result cache
  cache? : FnCache,
  symbols_fp? : String,
) -> Unit {
  let pr = pkg_root
  let cfg_engine_on = cfg_engine
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
  // Strict CFG verification needs fresh execution diagnostics, which a
  // findings-only cache cannot replay. Keep its results out of a shared
  // cache as well, because normal mode can filter unreachable findings.
  let reusable_cache = if cfg_verify_mode() { None } else { cache }
  let c = match reusable_cache {
    Some(c) => c
    None => FnCache::new() // no cache: each lookup misses → normal path
  }
  let fp = match reusable_cache {
    None => "" // ephemeral cache cannot replay results from an earlier scan
    Some(_) =>
      taint_analysis_fingerprint(
        match symbols_fp {
          Some(f) => f
          None => "-"
        },
        severity,
        rules,
        output_sinks,
        ictx,
      )
  }
  let source_lines : Array[String] = []
  for line in source.split("\n") {
    source_lines.push(line.to_owned())
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
            let bh = fn_body_hash(
              fn_key,
              fn_source_repr(item.loc(), source_lines),
            )
            match c.lookup(file, fn_key, bh, fp) {
              Some(cached) =>
                for f in cached {
                  findings.push(f)
                }
              None => {
                let base = findings.length()
                call_flow(
                  params, body, file, source, severity, findings, ictx, rules, output_sinks,
                  pr, cfg_engine_on,
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
        // Distinguish same-named methods on different receiver/trait impls.
        // Positions already enter validity because findings retain locations.
        let fn_key = cache_parts_repr([
          method_name.name,
          item.loc().start.lnum.to_string(),
          item.loc().start.column().to_string(),
        ])
        let (params2, body2) = match body {
          DeclBody(expr=Function(func~, ..)) =>
            (Some(func.parameters), func.body)
          DeclBody(expr=b) => (Some(params), b)
          _ => (None, b_dummy())
        }
        match body {
          DeclBody(..) => {
            let bh = fn_body_hash(
              fn_key,
              fn_source_repr(item.loc(), source_lines),
            )
            match c.lookup(file, fn_key, bh, fp) {
              Some(cached) =>
                for f in cached {
                  findings.push(f)
                }
              None => {
                let base = findings.length()
                call_flow(
                  params2, body2, file, source, severity, findings, ictx, rules,
                  output_sinks, pr, cfg_engine_on,
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
