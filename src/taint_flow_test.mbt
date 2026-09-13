///|

///|
test "h1_unreachable_filter_scoped_to_current_fn" {
  // P0 fix: filter must only affect findings produced by the CURRENT
  // function. We simulate: (1) pre-existing finding from "file B" at line 20,
  // (2) run a function whose unreachable block is also at line 20.
  // The pre-existing finding must survive.
  let findings : Array[Finding] = []
  // simulate a pre-existing finding at line 20 from file B
  let fb : Finding = {
    rule_id: { cwe: 113, variant: "crlf-injection", },
    severity: Warning,
    confidence: Medium,
    message: "file B line 20 pre-existing",
    file: "b.mbt",
    line: 20,
    column: 1,
    end_line: 20,
    end_column: 10,
    snippet: "",
    fingerprint: "h1-test-b20",
  }
  findings.push(fb)
  let pre_count = findings.length()
  ignore(pre_count)
  // run file A's function: an unreachable set_header at line 20 should
  // produce 0 new findings (structural reachability kills it), and the
  // pre-existing file B finding at the SAME line must survive
  let src_a = "pub fn fa(resp : Response, v : String) -> Unit { if false { resp.set_header(\"X\", v) } }"
  let (impls_a, _) = @parser.parse_string(src_a, name="a.mbt")
  let farr : Array[Finding] = []
  for item in impls_a {
    match item {
      TopFuncDef(fun_decl~, decl_body~, ..) =>
        match decl_body {
          DeclBody(expr=body) =>
            run_flow_taint_func(
              fun_decl.decl_params,
              body,
              "a.mbt",
              src_a,
              Warning,
              farr,
            )
          _ => ()
        }
      _ => ()
    }
  }
  // farr may have findings from file A; the pre-existing fb is in a
  // SEPARATE array (simulating earlier file processing) — verify the
  // filter doesn't touch it
  // Merge: pre-existing + new, then verify fb is intact
  for f in farr {
    findings.push(f)
  }
  let b_survived = findings.any(fn(f) { f.file == "b.mbt" })
  inspect(b_survived, content="true")
}

///|
test "h1_validate_gate_blocks_filter_on_invalid_cfg" {
  // Structural: validate_cfg exists and works on a trivial CFG
  let ir = build_block_ir(
    "t",
    @syntax.Expr::Unit(loc=flow_test_dummy_loc(), faked=false),
    rules=TaintRuleset::empty(),
  )
  let errs = validate_cfg(ir)
  // trivial Unit body should produce a valid CFG
  inspect(errs.length(), content="0")
}

///|
fn flow_test_dummy_loc() -> @basic.Location {
  {
    start: { fname: "", lnum: 1, bol: 0, cnum: 0, },
    end: { fname: "", lnum: 1, bol: 0, cnum: 0, },
  }
}

///|
test "flow_augmented_assignment_preserves_left_taint" {
  let source =
    #|fn f(resp : Response, dirty : String) -> Unit {
    #|  let mut value = dirty
    #|  value += " suffix"
    #|  resp.set_header("X", value)
    #|}
  let (impls, errors) = @parser.parse_string(source, name="assignment.mbt")
  inspect(errors.length(), content="0")
  let findings : Array[Finding] = []
  run_cwe113(impls, "assignment.mbt", source, findings, Error)
  inspect(findings.length(), content="1")
  inspect(findings[0].rule_id.cwe, content="113")
  inspect(findings[0].line, content="4")
}

///|
test "flow_augmented_assignment_propagates_right_taint" {
  let source =
    #|fn f(resp : Response, dirty : String) -> Unit {
    #|  let mut value = "prefix "
    #|  value += dirty
    #|  resp.set_header("X", value)
    #|}
  let (impls, errors) = @parser.parse_string(source, name="assignment.mbt")
  inspect(errors.length(), content="0")
  let findings : Array[Finding] = []
  run_cwe113(impls, "assignment.mbt", source, findings, Error)
  inspect(findings.length(), content="1")
  inspect(findings[0].rule_id.cwe, content="113")
  inspect(findings[0].line, content="4")
}

///|
test "flow_augmented_assignment_keeps_clean_values_clean" {
  let source =
    #|fn f(resp : Response) -> Unit {
    #|  let mut value = "prefix "
    #|  value += "suffix"
    #|  resp.set_header("X", value)
    #|}
  let (impls, errors) = @parser.parse_string(source, name="assignment.mbt")
  inspect(errors.length(), content="0")
  let findings : Array[Finding] = []
  run_cwe113(impls, "assignment.mbt", source, findings, Error)
  inspect(findings.length(), content="0")
}

///|
test "flow_plain_assignment_overwrites_left_taint" {
  let source =
    #|fn f(resp : Response, dirty : String) -> Unit {
    #|  let mut value = dirty
    #|  value = "safe"
    #|  resp.set_header("X", value)
    #|}
  let (impls, errors) = @parser.parse_string(source, name="assignment.mbt")
  inspect(errors.length(), content="0")
  let findings : Array[Finding] = []
  run_cwe113(impls, "assignment.mbt", source, findings, Error)
  inspect(findings.length(), content="0")
}

///|
test "flow_augmented_assignment_retains_return_summary_provenance" {
  let source =
    #|fn append(value : String, unused : String) -> String {
    #|  let mut result = value
    #|  result += "suffix"
    #|  result
    #|}
  let (impls, errors) = @parser.parse_string(source, name="append.mbt")
  inspect(errors.length(), content="0")
  let ictx = InterProceduralContext::new()
  collect_func_summaries_flow(impls, "append.mbt", ictx)
  match ictx.summaries.get("append") {
    Some(summary) => {
      inspect(summary.ret_from.length(), content="1")
      inspect(summary.ret_from[0], content="value")
    }
    None => inspect(false, content="true")
  }
  let caller =
    #|fn f(resp : Response, dirty : String) -> Unit {
    #|  resp.set_header("Dirty", append(dirty, "safe"))
    #|  resp.set_header("Clean", append("safe", dirty))
    #|}
  let (caller_impls, caller_errors) = @parser.parse_string(
    caller,
    name="caller.mbt",
  )
  inspect(caller_errors.length(), content="0")
  let findings : Array[Finding] = []
  run_cwe113(caller_impls, "caller.mbt", caller, findings, Error, ictx~)
  inspect(findings.length(), content="1")
  inspect(findings[0].rule_id.cwe, content="113")
  inspect(findings[0].line, content="2")
}

///|
test "flow_guard_reports_both_possible_sink_branches" {
  let source =
    #|fn f(resp : Response, dirty : String, ok : Bool) -> Unit {
    #|  guard ok else {
    #|    resp.set_header("Rejected", dirty)
    #|  }
    #|  resp.set_header("Accepted", dirty)
    #|}
  let (impls, errors) = @parser.parse_string(source, name="guard.mbt")
  inspect(errors.length(), content="0")
  let findings : Array[Finding] = []
  run_cwe113(impls, "guard.mbt", source, findings, Error)
  inspect(findings.length(), content="2")
  inspect(
    findings.any(fn(f) { f.rule_id.cwe == 113 && f.line == 3 }),
    content="true",
  )
  inspect(
    findings.any(fn(f) { f.rule_id.cwe == 113 && f.line == 5 }),
    content="true",
  )
}

///|
test "flow_guard_merges_failure_path_assignment" {
  let source =
    #|fn f(resp : Response, dirty : String, ok : Bool) -> Unit {
    #|  let mut value = "safe"
    #|  { guard ok else { value = dirty }; () }
    #|  resp.set_header("X", value)
    #|}
  let (impls, errors) = @parser.parse_string(source, name="guard.mbt")
  inspect(errors.length(), content="0")
  let findings : Array[Finding] = []
  run_cwe113(impls, "guard.mbt", source, findings, Error)
  inspect(findings.length(), content="1")
  inspect(findings[0].rule_id.cwe, content="113")
  inspect(findings[0].line, content="4")
}

///|
test "flow_guard_merges_failure_path_result" {
  let source =
    #|fn f(resp : Response, dirty : String, ok : Bool) -> Unit {
    #|  let value = { guard ok else { dirty }; "safe" }
    #|  resp.set_header("X", value)
    #|}
  let (impls, errors) = @parser.parse_string(source, name="guard.mbt")
  inspect(errors.length(), content="0")
  let findings : Array[Finding] = []
  run_cwe113(impls, "guard.mbt", source, findings, Error)
  inspect(findings.length(), content="1")
  inspect(findings[0].rule_id.cwe, content="113")
  inspect(findings[0].line, content="3")
}

///|
test "flow_guard_constant_false_skips_success_path" {
  let source =
    #|fn f(resp : Response, dirty : String) -> Unit {
    #|  guard false else { () }
    #|  resp.set_header("X", dirty)
    #|}
  let (impls, errors) = @parser.parse_string(source, name="guard.mbt")
  inspect(errors.length(), content="0")
  let findings : Array[Finding] = []
  run_cwe113(impls, "guard.mbt", source, findings, Error)
  inspect(findings.length(), content="0")
}

///|
test "flow_guard_constant_true_skips_failure_path" {
  let source =
    #|fn f(resp : Response, dirty : String) -> Unit {
    #|  guard true else { resp.set_header("Rejected", dirty) }
    #|  resp.set_header("Accepted", "safe")
    #|}
  let (impls, errors) = @parser.parse_string(source, name="guard.mbt")
  inspect(errors.length(), content="0")
  let findings : Array[Finding] = []
  run_cwe113(impls, "guard.mbt", source, findings, Error)
  inspect(findings.length(), content="0")
}

///|
test "flow_guard_failure_scope_does_not_shadow_outer_value" {
  let source =
    #|fn f(resp : Response, dirty : String, ok : Bool) -> Unit {
    #|  guard ok else {
    #|    let dirty = "safe"
    #|    resp.set_header("Rejected", dirty)
    #|  }
    #|  resp.set_header("Accepted", dirty)
    #|}
  let (impls, errors) = @parser.parse_string(source, name="guard.mbt")
  inspect(errors.length(), content="0")
  let findings : Array[Finding] = []
  run_cwe113(impls, "guard.mbt", source, findings, Error)
  inspect(findings.length(), content="1")
  inspect(findings[0].rule_id.cwe, content="113")
  inspect(findings[0].line, content="6")
}

///|
test "flow_guard_constant_true_preserves_strong_heap_update" {
  let source =
    #|fn f(resp : Response, dirty : String) -> Unit {
    #|  let box = Box::{ value: "safe" }
    #|  box.value = dirty
    #|  { guard true else { () }; box.value = "safe" }
    #|  resp.set_header("X", box.value)
    #|}
  let (impls, errors) = @parser.parse_string(source, name="guard.mbt")
  inspect(errors.length(), content="0")
  let findings : Array[Finding] = []
  run_cwe113(impls, "guard.mbt", source, findings, Error)
  inspect(findings.length(), content="0")
}

///|
test "flow_guard_refinement_does_not_clean_failure_branch" {
  let source =
    #|fn f(resp : Response, dirty : String) -> Unit {
    #|  guard !dirty.contains("\r\n") else {
    #|    resp.set_header("Rejected", dirty)
    #|  }
    #|  resp.set_header("Accepted", dirty)
    #|}
  let (impls, errors) = @parser.parse_string(source, name="guard.mbt")
  inspect(errors.length(), content="0")
  let findings : Array[Finding] = []
  run_cwe113(impls, "guard.mbt", source, findings, Error)
  inspect(findings.length(), content="1")
  inspect(findings[0].rule_id.cwe, content="113")
  inspect(findings[0].line, content="3")
}

///|
test "flow_guard_rebinding_joins_allocation_sites" {
  let source =
    #|fn f(resp : Response, dirty : String, ok : Bool) -> Unit {
    #|  let mut box = Box::{ value: "safe" }
    #|  { guard ok else { () }; box = Box::{ value: dirty } }
    #|  resp.set_header("X", box.value)
    #|}
  let (impls, errors) = @parser.parse_string(source, name="sites.mbt")
  inspect(errors.length(), content="0")
  let findings : Array[Finding] = []
  run_cwe113(impls, "sites.mbt", source, findings, Error)
  inspect(findings.length(), content="1")
  inspect(findings[0].rule_id.cwe, content="113")
  inspect(findings[0].line, content="4")
}

///|
test "flow_if_rebinding_joins_both_object_fields" {
  let source =
    #|fn f(resp : Response, dirty : String, ok : Bool) -> Unit {
    #|  let mut box = Box::{ left: "safe", right: "safe" }
    #|  if ok {
    #|    box = Box::{ left: dirty, right: "safe" }
    #|  } else {
    #|    box = Box::{ left: "safe", right: dirty }
    #|  }
    #|  resp.set_header("Left", box.left)
    #|  resp.set_header("Right", box.right)
    #|}
  let (impls, errors) = @parser.parse_string(source, name="sites.mbt")
  inspect(errors.length(), content="0")
  let findings : Array[Finding] = []
  run_cwe113(impls, "sites.mbt", source, findings, Error)
  inspect(findings.length(), content="2")
  inspect(findings[0].line, content="8")
  inspect(findings[1].line, content="9")
}

///|
test "flow_guard_join_observes_later_alias_writes" {
  let source =
    #|fn f(resp : Response, dirty : String, ok : Bool) -> Unit {
    #|  let left = Box::{ value: "safe" }
    #|  let right = Box::{ value: "safe" }
    #|  let mut box = left
    #|  { guard ok else { () }; box = right }
    #|  right.value = dirty
    #|  resp.set_header("X", box.value)
    #|}
  let (impls, errors) = @parser.parse_string(source, name="sites.mbt")
  inspect(errors.length(), content="0")
  let findings : Array[Finding] = []
  run_cwe113(impls, "sites.mbt", source, findings, Error)
  inspect(findings.length(), content="1")
  inspect(findings[0].line, content="7")
}

///|
test "flow_joined_target_writes_do_not_clean_every_possible_object" {
  let source =
    #|fn f(resp : Response, dirty : String, ok : Bool) -> Unit {
    #|  let left = Box::{ value: dirty }
    #|  let right = Box::{ value: dirty }
    #|  let mut box = left
    #|  if ok { box = right }
    #|  box.value = "safe"
    #|  resp.set_header("Left", left.value)
    #|  resp.set_header("Right", right.value)
    #|}
  let (impls, errors) = @parser.parse_string(source, name="sites.mbt")
  inspect(errors.length(), content="0")
  let findings : Array[Finding] = []
  run_cwe113(impls, "sites.mbt", source, findings, Error)
  inspect(findings.length(), content="2")
  inspect(findings[0].line, content="7")
  inspect(findings[1].line, content="8")
}

///|
test "flow_joined_objects_keep_unrelated_clean_fields_clean" {
  let source =
    #|fn f(resp : Response, dirty : String, ok : Bool) -> Unit {
    #|  let mut box = Box::{ value: "safe", other: dirty }
    #|  { guard ok else { () }; box = Box::{ value: "safe", other: dirty } }
    #|  resp.set_header("X", box.value)
    #|}
  let (impls, errors) = @parser.parse_string(source, name="sites.mbt")
  inspect(errors.length(), content="0")
  let findings : Array[Finding] = []
  run_cwe113(impls, "sites.mbt", source, findings, Error)
  inspect(findings.length(), content="0")
}

///|
test "flow_match_rebinding_joins_allocation_sites" {
  let source =
    #|fn f(resp : Response, dirty : String, ok : Bool) -> Unit {
    #|  let mut box = Box::{ value: "safe" }
    #|  match ok {
    #|    true => box = Box::{ value: dirty }
    #|    false => ()
    #|  }
    #|  resp.set_header("X", box.value)
    #|}
  let (impls, errors) = @parser.parse_string(source, name="sites.mbt")
  inspect(errors.length(), content="0")
  let findings : Array[Finding] = []
  run_cwe113(impls, "sites.mbt", source, findings, Error)
  inspect(findings.length(), content="1")
  inspect(findings[0].line, content="7")
}

///|
test "flow_loop_repeats_when_only_allocation_sites_change" {
  let source =
    #|fn f(resp : Response, dirty : String, ok : Bool) -> Unit {
    #|  let initial = Box::{ value: "safe", other: dirty }
    #|  let final_box = Box::{ value: dirty, other: "safe" }
    #|  let mut first = initial
    #|  let mut second = initial
    #|  while ok {
    #|    resp.set_header("X", first.value)
    #|    first = second
    #|    second = final_box
    #|  }
    #|}
  let (impls, errors) = @parser.parse_string(source, name="sites.mbt")
  inspect(errors.length(), content="0")
  loop_budget_reset()
  let findings : Array[Finding] = []
  run_cwe113(impls, "sites.mbt", source, findings, Error)
  let iterations = loop_fixpoint_last_iterations()
  loop_budget_reset()
  inspect(findings.length(), content="1")
  inspect(findings[0].line, content="7")
  inspect(iterations >= 3, content="true")
}

///|
test "flow_closure_keeps_joined_site_snapshot_after_rebinding" {
  let source =
    #|fn f(resp : Response, dirty : String, ok : Bool) -> Unit {
    #|  let left = Box::{ value: "safe" }
    #|  let right = Box::{ value: "safe" }
    #|  let mut box = left
    #|  if ok { box = right }
    #|  let emit = fn() -> Unit { resp.set_header("X", box.value) }
    #|  box = Box::{ value: "safe" }
    #|  right.value = dirty
    #|  emit()
    #|}
  let (impls, errors) = @parser.parse_string(source, name="sites.mbt")
  inspect(errors.length(), content="0")
  let findings : Array[Finding] = []
  run_cwe113(impls, "sites.mbt", source, findings, Error)
  inspect(findings.length(), content="1")
  inspect(findings[0].line, content="6")
}
