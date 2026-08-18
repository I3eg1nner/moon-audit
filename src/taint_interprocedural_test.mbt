// Tests for inter-procedural taint analysis (via public API).

// ---------------------------------------------------------------------------
// Phase 1: Function summary collection
// ---------------------------------------------------------------------------

///|
test "InterProc: summary detects header sink" {
  let source = "fn set_val(resp : Response, val : String) -> Unit {\n  resp.set_header(\"X-Custom\", val)\n}"
  let ctx = InterProceduralContext::new()
  collect_func_summaries(source, "test.mbt", ctx)
  assert_true(ctx.summaries.contains("set_val"))
  match ctx.summaries.get("set_val") {
    Some(summary) => assert_true(summary.param_sinks.contains("val"))
    None => assert_true(false)
  }
}

///|
test "InterProc: summary detects html sink" {
  let source = "fn render(content : String) -> String {\n  html(content)\n}"
  let ctx = InterProceduralContext::new()
  collect_func_summaries(source, "test.mbt", ctx)
  assert_true(ctx.summaries.contains("render"))
  match ctx.summaries.get("render") {
    Some(summary) => assert_true(summary.param_sinks.contains("content"))
    None => assert_true(false)
  }
}

///|
test "InterProc: summary detects redirect sink" {
  let source = "fn go_to(url : String) -> Unit {\n  redirect(url)\n}"
  let ctx = InterProceduralContext::new()
  collect_func_summaries(source, "test.mbt", ctx)
  assert_true(ctx.summaries.contains("go_to"))
  match ctx.summaries.get("go_to") {
    Some(summary) => assert_true(summary.param_sinks.contains("url"))
    None => assert_true(false)
  }
}

///|
test "InterProc: summary with alias propagation" {
  let source = "fn helper(val : String) -> Unit {\n  let v = val\n  resp.set_header(\"X\", v)\n}"
  let ctx = InterProceduralContext::new()
  collect_func_summaries(source, "test.mbt", ctx)
  assert_true(ctx.summaries.contains("helper"))
  match ctx.summaries.get("helper") {
    Some(summary) => assert_true(summary.param_sinks.contains("val"))
    None => assert_true(false)
  }
}

///|
test "InterProc: no summary when param not in sink" {
  let source = "fn safe_fn(val : String) -> String {\n  val + \" suffix\"\n}"
  let ctx = InterProceduralContext::new()
  collect_func_summaries(source, "test.mbt", ctx)
  assert_true(!ctx.summaries.contains("safe_fn"))
}

///|
test "InterProc: summary from file path sink" {
  let source = "fn load(path : String) -> String {\n  read_file(path)\n}"
  let ctx = InterProceduralContext::new()
  collect_func_summaries(source, "test.mbt", ctx)
  assert_true(ctx.summaries.contains("load"))
  match ctx.summaries.get("load") {
    Some(summary) => assert_true(summary.param_sinks.contains("path"))
    None => assert_true(false)
  }
}

///|
test "InterProc: multiple params only dangerous one gets summary" {
  let source = "fn set_val(resp : Response, name : String, val : String) -> Unit {\n  resp.set_header(name, val)\n}"
  let ctx = InterProceduralContext::new()
  collect_func_summaries(source, "test.mbt", ctx)
  assert_true(ctx.summaries.contains("set_val"))
  match ctx.summaries.get("set_val") {
    Some(summary) => {
      assert_true(summary.param_sinks.contains("val"))
      assert_true(summary.param_sinks.contains("name"))
    }
    None => assert_true(false)
  }
}

// ---------------------------------------------------------------------------
// Phase 2: Cross-function taint detection
// ---------------------------------------------------------------------------

///|
test "InterProc: tainted param through function call" {
  let helper_source = "fn set_val(resp : Response, val : String) -> Unit {\n  resp.set_header(\"X-Custom\", val)\n}"
  let ctx = InterProceduralContext::new()
  collect_func_summaries(helper_source, "helper.mbt", ctx)
  let caller_source = "fn handler(req : Request, resp : Response) -> Unit {\n  let input = req.param(\"id\")\n  set_val(resp, input)\n}"
  let (impls, _) = @parser.parse_string(caller_source, name="handler.mbt")
  let findings : Array[Finding] = []
  run_cross_func_taint(
    impls,
    "handler.mbt",
    caller_source,
    findings,
    ctx,
    ImportContext::empty(),
  )
  assert_true(findings.length() > 0)
  assert_true(findings[0].message.contains("Taint"))
}

///|
test "InterProc: constant arg should not trigger" {
  let helper_source = "fn set_val(resp : Response, val : String) -> Unit {\n  resp.set_header(\"X-Custom\", val)\n}"
  let ctx = InterProceduralContext::new()
  collect_func_summaries(helper_source, "helper.mbt", ctx)
  let caller_source = "fn handler(resp : Response) -> Unit {\n  set_val(resp, \"fixed-value\")\n}"
  let (impls, _) = @parser.parse_string(caller_source, name="handler.mbt")
  let findings : Array[Finding] = []
  run_cross_func_taint(
    impls,
    "handler.mbt",
    caller_source,
    findings,
    ctx,
    ImportContext::empty(),
  )
  assert_true(findings.length() == 0)
}

///|
test "InterProc: taint propagation through let binding" {
  let helper_source = "fn render_page(title : String) -> String {\n  html(title)\n}"
  let ctx = InterProceduralContext::new()
  collect_func_summaries(helper_source, "helper.mbt", ctx)
  let caller_source = "fn handler(req : Request) -> Response {\n  let name = req.query(\"name\")\n  let display = name\n  render_page(display)\n}"
  let (impls, _) = @parser.parse_string(caller_source, name="handler.mbt")
  let findings : Array[Finding] = []
  run_cross_func_taint(
    impls,
    "handler.mbt",
    caller_source,
    findings,
    ctx,
    ImportContext::empty(),
  )
  assert_true(findings.length() > 0)
}

///|
test "InterProc: untainted variable should not trigger" {
  let helper_source = "fn set_val(resp : Response, val : String) -> Unit {\n  resp.set_header(\"X-Custom\", val)\n}"
  let ctx = InterProceduralContext::new()
  collect_func_summaries(helper_source, "helper.mbt", ctx)
  let caller_source = "fn handler(resp : Response) -> Unit {\n  let safe = \"computed\"\n  set_val(resp, safe)\n}"
  let (impls, _) = @parser.parse_string(caller_source, name="handler.mbt")
  let findings : Array[Finding] = []
  run_cross_func_taint(
    impls,
    "handler.mbt",
    caller_source,
    findings,
    ctx,
    ImportContext::empty(),
  )
  assert_true(findings.length() == 0)
}

///|
test "InterProc: no finding when callee has no summary" {
  let ctx = InterProceduralContext::new()
  let caller_source = "fn handler(req : Request) -> Unit {\n  let input = req.param(\"id\")\n  unknown_func(input)\n}"
  let (impls, _) = @parser.parse_string(caller_source, name="handler.mbt")
  let findings : Array[Finding] = []
  run_cross_func_taint(
    impls,
    "handler.mbt",
    caller_source,
    findings,
    ctx,
    ImportContext::empty(),
  )
  assert_true(findings.length() == 0)
}

///|
test "InterProc: multiple summaries across files" {
  let ctx = InterProceduralContext::new()
  let source1 = "fn set_val(resp : Response, val : String) -> Unit {\n  resp.set_header(\"X\", val)\n}"
  let source2 = "fn render(content : String) -> String {\n  html(content)\n}"
  collect_func_summaries(source1, "a.mbt", ctx)
  collect_func_summaries(source2, "b.mbt", ctx)
  assert_true(ctx.summaries.contains("set_val"))
  assert_true(ctx.summaries.contains("render"))
}

///|
test "InterProc: direct taint source in call arg" {
  let helper_source = "fn set_val(resp : Response, val : String) -> Unit {\n  resp.set_header(\"X-Custom\", val)\n}"
  let ctx = InterProceduralContext::new()
  collect_func_summaries(helper_source, "helper.mbt", ctx)
  let caller_source = "fn handler(req : Request, resp : Response) -> Unit {\n  set_val(resp, req.param(\"id\"))\n}"
  let (impls, _) = @parser.parse_string(caller_source, name="handler.mbt")
  let findings : Array[Finding] = []
  run_cross_func_taint(
    impls,
    "handler.mbt",
    caller_source,
    findings,
    ctx,
    ImportContext::empty(),
  )
  assert_true(findings.length() > 0)
}
