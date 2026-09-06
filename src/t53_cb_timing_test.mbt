// T5.3 callback timing: immediate executes at the call site (current
// behavior, now MODEL-gated), deferred records a fact and does NOT
// execute at creation (create != execute for stored callbacks).

///|
fn t53_rules(json : String) -> TaintRuleset {
  let warnings : Array[String] = []
  let j = @json.parse(json) catch { _ => return TaintRuleset::empty() }
  parse_ruleset_json(j, "t53", warnings)
}

///|
fn t53_run(
  source : String,
  rules? : TaintRuleset,
  findings : Array[Finding],
  facts : Array[String],
) -> Unit {
  let (impls, _) = @parser.parse_string(source, name="t.mbt")
  let rs = match rules {
    Some(r) => r
    None => TaintRuleset::empty()
  }
  for item in impls {
    match item {
      TopFuncDef(fun_decl~, decl_body~, ..) =>
        match decl_body {
          DeclBody(expr=Function(func~, ..)) =>
            run_flow_taint_func(
              Some(func.parameters),
              func.body,
              "t.mbt",
              source,
              Error,
              findings,
              rules=rs,
              deferred_facts=facts,
            )
          DeclBody(expr=body) =>
            run_flow_taint_func(
              fun_decl.decl_params,
              body,
              "t.mbt",
              source,
              Error,
              findings,
              rules=rs,
              deferred_facts=facts,
            )
          _ => ()
        }
      _ => ()
    }
  }
}

///|
test "t53_immediate_model_executes_at_call_site" {
  let json =
    #|{
    #|  "callbacks": { "Array::map": { "slots": ["T"], "timing": "immediate" } }
    #|}
  let findings : Array[Finding] = []
  t53_run(
    "fn go(resp : Response, xs : Array[String]) -> Unit { ignore(xs.map(fn(x) { resp.set_header(\"X\", x) })) }",
    rules=t53_rules(json),
    findings,
    [],
  )
  inspect(findings.length() > 0, content="true") // callback body ran here
}

///|
test "t53_deferred_not_executed_and_fact_recorded" {
  let json =
    #|{
    #|  "callbacks": { "Iter::map": { "slots": ["T"], "timing": "deferred" } }
    #|}
  let findings : Array[Finding] = []
  let facts : Array[String] = []
  t53_run(
    "fn go(resp : Response, it : Iter[String]) -> Unit { ignore(it.map(fn(x) { resp.set_header(\"X\", x) })) }",
    rules=t53_rules(json),
    findings,
    facts,
  )
  inspect(findings.length(), content="0") // NOT executed at creation
  inspect(facts.length(), content="1") // fact recorded for the solver
  inspect(facts[0].has_prefix("Iter::map@L"), content="true")
}

///|
test "t53_no_model_defaults_immediate_unchanged" {
  let findings : Array[Finding] = []
  t53_run(
    "fn go(resp : Response, xs : Array[String]) -> Unit { ignore(xs.map(fn(x) { resp.set_header(\"X\", x) })) }",
    findings,
    [],
  )
  inspect(findings.length() > 0, content="true") // behavior unchanged
}
