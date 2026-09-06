// Tests for extended modules: CWE-113, CWE-79/template, LLM prompt, PoC gen, remediation.

// ---------------------------------------------------------------------------
// CWE-113: CRLF injection via dynamic header values
// ---------------------------------------------------------------------------

///|
test "CWE-113: set_header with dynamic value should trigger" {
  let source = "fn foo(resp : Response, val : String) -> Unit { resp.set_header(\"X-Custom\", val) }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() > 0)
}

///|
test "CWE-113: set_header with constant value should not trigger" {
  let source = "fn foo(resp : Response) -> Unit { resp.set_header(\"X-Custom\", \"fixed-value\") }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() == 0)
}

///|
test "CWE-113: add_header with dynamic value should trigger" {
  let source = "fn foo(resp : Response, lang : String) -> Unit { resp.add_header(\"X-Language\", lang) }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() > 0)
}

///|
test "CWE-113: sanitize_header_value wrapping should not trigger" {
  let source = "fn foo(resp : Response, val : String) -> Unit { resp.set_header(\"X-Custom\", sanitize_header_value(val)) }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() == 0)
}

///|
test "CWE-113: replace_all CRLF stripping should not trigger" {
  let source = "fn foo(resp : Response, val : String) -> Unit { resp.set_header(\"X-Custom\", val.replace_all(old=\"\\r\", new=\"\").replace_all(old=\"\\n\", new=\"\")) }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() == 0)
}

///|
test "CWE-113: config field access should not trigger" {
  let source = "fn foo(ctx : Context, config : Config) -> Unit { ctx.set_header(\"Cache-Control\", config.cache_control) }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() == 0)
}

///|
test "CWE-113: CamelCase identifier should not trigger" {
  let source = "fn foo(resp : Response) -> Unit { resp.set_header(\"Content-Type\", ContentType) }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() == 0)
}

///|
test "CWE-113: interpolation with constant identifier should not trigger" {
  let source =
    #|fn foo(ctx : Context) -> Unit { ctx.set_header("Cache-Control", "s-maxage=\{MaxAge}") }
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() == 0)
}

///|
test "CWE-113: let-bound sanitized value should not trigger" {
  let source =
    #|fn foo(resp : Response, val : String) -> Unit { let safe = sanitize_header_value(val); resp.set_header("X-Custom", safe) }
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() == 0)
}

///|
test "CWE-113: let-bound replace_all chain should not trigger" {
  let source =
    #|fn foo(resp : Response, val : String) -> Unit { let clean = val.replace_all(old="\r", new="").replace_all(old="\n", new=""); resp.set_header("X-Custom", clean) }
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() == 0)
}

///|
test "CWE-113: string interpolation with dynamic value should trigger" {
  let source =
    #|fn foo(ctx : Context, user_input : String) -> Unit { ctx.set_header("X-Data", "value=\{user_input}") }
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() > 0)
}

// ---------------------------------------------------------------------------
// CWE-79/template: HTML response with string interpolation
// ---------------------------------------------------------------------------

///|
test "CWE-079/template: html() with interpolation should trigger" {
  let source =
    #|fn handler(name : String) -> Response { html("<h1>Hello, \{name}!</h1>") }
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe079_template(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() > 0)
}

///|
test "CWE-079/template: html() with constant string should not trigger" {
  let source = "fn handler() -> Response { html(\"<h1>Hello World</h1>\") }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe079_template(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() == 0)
}

// ---------------------------------------------------------------------------
// LLM prompt generation
// ---------------------------------------------------------------------------

///|
test "LLM: generate_analysis_prompt produces non-empty prompt" {
  let finding : Finding = {
    rule_id: { cwe: 942, variant: "cors-credentials", },
    severity: Error,
    confidence: Medium,
    message: "CORS credential theft",
    file: "server.mbt",
    line: 10,
    column: 5,
    end_line: 10,
    end_column: 50,
    snippet: "handle_cors(credentials=true)",
    fingerprint: "",
  }
  let source = "fn main() {\n  handle_cors(credentials=true)\n}\n"
  let imports = ImportContext::empty()
  let req = generate_analysis_prompt(finding, source, imports)
  assert_true(req.prompt.length() > 100)
  assert_true(req.system_prompt.length() > 100)
  assert_true(req.prompt.contains("CWE-942"))
  assert_true(req.system_prompt.contains("MoonBit"))
}

///|
test "LLM: parse_llm_response parses valid JSON" {
  let finding : Finding = {
    rule_id: { cwe: 79, variant: "cmark-unsafe", },
    severity: Error,
    confidence: High,
    message: "test",
    file: "test.mbt",
    line: 1,
    column: 1,
    end_line: 1,
    end_column: 10,
    snippet: "",
    fingerprint: "",
  }
  let json = "{\"is_true_positive\": true, \"confidence\": 0.95, \"explanation\": \"Real vulnerability\", \"remediation\": \"Add safe=true\"}"
  let result = parse_llm_response(finding, json)
  assert_true(result is Some(_))
  match result {
    Some(r) => {
      assert_true(r.is_true_positive)
      assert_true(r.confidence > 0.9)
      assert_true(r.explanation.contains("Real"))
    }
    None => assert_true(false)
  }
}

///|
test "LLM: format_prompt_as_json produces valid structure" {
  let finding : Finding = {
    rule_id: { cwe: 116, variant: "replace-escaping", },
    severity: Error,
    confidence: High,
    message: "test",
    file: "test.mbt",
    line: 1,
    column: 1,
    end_line: 1,
    end_column: 10,
    snippet: "",
    fingerprint: "",
  }
  let req = generate_analysis_prompt(
    finding,
    "fn foo() {}",
    ImportContext::empty(),
  )
  let json_str = format_prompt_as_json(req)
  assert_true(json_str.contains("claude"))
  assert_true(json_str.contains("messages"))
}

// ---------------------------------------------------------------------------
// PoC generation
// ---------------------------------------------------------------------------

///|
test "PoC: generate_poc creates CORS PoC" {
  let finding : Finding = {
    rule_id: { cwe: 942, variant: "cors-credentials", },
    severity: Error,
    confidence: Medium,
    message: "CORS credential theft",
    file: "server.mbt",
    line: 10,
    column: 5,
    end_line: 10,
    end_column: 50,
    snippet: "",
    fingerprint: "",
  }
  let poc = generate_poc(finding, ImportContext::empty())
  assert_true(poc is Some(_))
  match poc {
    Some(p) => {
      assert_true(p.title.contains("CORS"))
      assert_true(p.script.contains("python3"))
      assert_true(p.script.contains("evil.com"))
      assert_true(p.attack_steps.length() > 0)
    }
    None => assert_true(false)
  }
}

///|
test "PoC: generate_poc creates cookie PoC" {
  let finding : Finding = {
    rule_id: { cwe: 614, variant: "cookie-attrs", },
    severity: Warning,
    confidence: Medium,
    message: "Missing cookie attrs",
    file: "server.mbt",
    line: 20,
    column: 5,
    end_line: 20,
    end_column: 50,
    snippet: "",
    fingerprint: "",
  }
  let poc = generate_poc(finding, ImportContext::empty())
  assert_true(poc is Some(_))
  match poc {
    Some(p) => {
      assert_true(p.title.contains("Cookie"))
      assert_true(p.script.contains("httponly"))
    }
    None => assert_true(false)
  }
}

///|
test "PoC: generate_all_pocs handles multiple findings" {
  let findings : Array[Finding] = [
    {
      rule_id: { cwe: 942, variant: "cors-credentials", },
      severity: Error,
      confidence: Medium,
      message: "CORS",
      file: "a.mbt",
      line: 1,
      column: 1,
      end_line: 1,
      end_column: 10,
      snippet: "",
      fingerprint: "",
    },
    {
      rule_id: { cwe: 770, variant: "no-body-limit", },
      severity: Warning,
      confidence: Medium,
      message: "DoS",
      file: "b.mbt",
      line: 2,
      column: 1,
      end_line: 2,
      end_column: 10,
      snippet: "",
      fingerprint: "",
    },
  ]
  let pocs = generate_all_pocs(findings, ImportContext::empty())
  assert_true(pocs.length() == 2)
}

// ---------------------------------------------------------------------------
// Remediation
// ---------------------------------------------------------------------------

///|
test "Remediation: get_remediation returns correct fix for CWE-116" {
  let finding : Finding = {
    rule_id: { cwe: 116, variant: "replace-escaping", },
    severity: Error,
    confidence: High,
    message: "test",
    file: "test.mbt",
    line: 1,
    column: 1,
    end_line: 1,
    end_column: 10,
    snippet: "",
    fingerprint: "",
  }
  let rem = get_remediation(finding)
  assert_true(rem.title.contains("replace_all"))
  assert_true(rem.code_before.contains("replace"))
  assert_true(rem.code_after.contains("replace_all"))
  assert_true(rem.owasp_category.contains("Injection"))
}

///|
test "Remediation: get_all_remediations deduplicates" {
  let findings : Array[Finding] = [
    {
      rule_id: { cwe: 614, variant: "cookie-attrs", },
      severity: Warning,
      confidence: Medium,
      message: "a",
      file: "a.mbt",
      line: 1,
      column: 1,
      end_line: 1,
      end_column: 5,
      snippet: "",
      fingerprint: "",
    },
    {
      rule_id: { cwe: 614, variant: "cookie-attrs", },
      severity: Warning,
      confidence: Medium,
      message: "b",
      file: "b.mbt",
      line: 2,
      column: 1,
      end_line: 2,
      end_column: 5,
      snippet: "",
      fingerprint: "",
    },
  ]
  let rems = get_all_remediations(findings)
  assert_true(rems.length() == 1)
}

///|
test "Remediation: format_remediation_report produces markdown" {
  let finding : Finding = {
    rule_id: { cwe: 942, variant: "cors-credentials", },
    severity: Error,
    confidence: Medium,
    message: "test",
    file: "test.mbt",
    line: 1,
    column: 1,
    end_line: 1,
    end_column: 10,
    snippet: "",
    fingerprint: "",
  }
  let rems = [get_remediation(finding)]
  let report = format_remediation_report(rems)
  assert_true(report.contains("# Security Remediation Guide"))
  assert_true(report.contains("CORS"))
  assert_true(report.contains("OWASP"))
}

// ---------------------------------------------------------------------------
// Integration: helpers and types
// ---------------------------------------------------------------------------

///|
test "Types: rule_id_str formats correctly" {
  let id : RuleId = { cwe: 942, variant: "cors-credentials", }
  assert_true(rule_id_str(id) == "CWE-942/cors-credentials")
}

///|
test "Types: severity roundtrip" {
  assert_true(severity_from_str("error") == Error)
  assert_true(severity_from_str("warning") == Warning)
  assert_true(severity_from_str("info") == Info)
  assert_true(severity_str(Error) == "error")
}

///|
test "Config: default config disables high-FP rules" {
  let config = Config::default()
  assert_true(!config.is_enabled("CWE-94/eval-extern"))
  assert_true(!config.is_enabled("CWE-79/inner-html"))
  assert_true(config.is_enabled("CWE-942/cors-credentials"))
}

///|
test "Helpers: get_source_line extracts correct line" {
  let source = "line1\nline2\nline3\n"
  assert_true(get_source_line(source, 2) == "line2")
}

// ---------------------------------------------------------------------------
// M2.5 adversarial: sanitizer strictness + guard polarity
// ---------------------------------------------------------------------------

///|
test "M2.5: positive contains(danger) must still trigger" {
  let source = "fn foo(resp : Response, x : String) -> Unit { if x.contains(\"\\r\\n\") { resp.set_header(\"X\", x) } }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() > 0)
}

///|
test "M2.5: negated contains(danger) cleans then-branch" {
  let source = "fn foo(resp : Response, x : String) -> Unit { if !x.contains(\"\\r\\n\") { resp.set_header(\"X\", x) } else { abort(\"\") } }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() == 0)
}

///|
test "M2.5: negated whitelist is NOT clean" {
  let source = "fn foo(resp : Response, x : String) -> Unit { if !x.is_ascii() { abort(\"\") } else { resp.set_header(\"X\", x) } }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() > 0)
}

///|
test "M2.5: single replace (not replace_all) is not a sanitizer" {
  let source = "fn foo(resp : Response, val : String) -> Unit { resp.set_header(\"X-Custom\", val.replace(old=\"\\r\\n\", new=\"\")) }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() > 0)
}

///|
test "M2.5: replace_all of only \\r alone is not a sanitizer" {
  let source = "fn foo(resp : Response, val : String) -> Unit { resp.set_header(\"X-Custom\", val.replace_all(old=\"\\r\", new=\"\")) }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() > 0)
}

///|
test "M2.5: if-expression taint joins to let" {
  let source = "fn foo(resp : Response, cond : Bool, dirty : String) -> Unit { let v = if cond { dirty } else { \"safe\" }; resp.set_header(\"X\", v) }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() > 0)
}

///|
test "M2.5: match-expression taint joins to let" {
  let source = "fn foo(resp : Response, n : Int, dirty : String) -> Unit { let v = match n { 0 => \"safe\"; _ => dirty }; resp.set_header(\"X\", v) }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() > 0)
}

///|
test "M2.6: replace_all INTRODUCING CRLF via new= must trigger" {
  let source = "fn foo(resp : Response, val : String) -> Unit { resp.set_header(\"X\", val.replace_all(old=\"a\", new=\"\\r\\n\")) }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() > 0)
}

///|
test "M2.6: old-slot CRLF strip chain still sanitizes" {
  let source = "fn foo(resp : Response, val : String) -> Unit { resp.set_header(\"X\", val.replace_all(old=\"\\r\", new=\"\").replace_all(old=\"\\n\", new=\"\")) }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() == 0)
}

// ---------------------------------------------------------------------------
// Phase-3 semantics: review counterexamples (field / loop / defer)
// ---------------------------------------------------------------------------

///|
test "P3: field of source-derived struct must trigger" {
  let source = "pub struct Box { v : String } fn h(resp : Response, req : Request) -> Unit { let b = Box::{ v: req.query(\"q\") }; resp.set_header(\"X\", b.v) }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() > 0)
}

///|
test "P3: config-like param field stays silent" {
  let source = "pub struct Cfg { cc : String } fn h(resp : Response, config : Cfg) -> Unit { resp.set_header(\"Cache-Control\", config.cc) }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() == 0)
}

///|
test "P3: two-pass loop propagation must trigger" {
  let source = "fn h(resp : Response, req : Request) -> Unit { let mut acc = \"\"; let mut i = 0; while i < 2 { if i > 0 { resp.set_header(\"X\", acc) } else { () }; acc = req.query(\"q\"); i = i + 1 } }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() > 0)
}

///|
test "P3: defer expression observes body writes (exit-path order)" {
  let source = "fn h(resp : Response, req : Request) -> Unit { let mut acc2 = \"s\"; defer { resp.set_header(\"X\", acc2) }; acc2 = req.query(\"q\") }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() > 0)
}

// ---------------------------------------------------------------------------
// V1: error-flow & value-structure contracts (third review)
// ---------------------------------------------------------------------------

///|
fn v1_may_fail() -> String {
  "fn may_fail(x : String, flag : Bool) -> String raise Bad { if flag { raise Bad(x) } x }"
}

///|
test "v1_control_param_direct_header_reports" {
  let source = "fn foo(resp : Response, x : String) -> Unit { resp.set_header(\"X\", x) }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() > 0)
}

///|
test "v1_try_normal_branch_taint_reports" {
  let source = v1_may_fail() +
    " pub fn foo(resp : Response, x : String, flag : Bool) -> Unit { let value = try may_fail(x, flag) catch { _ => \"safe\" }; resp.set_header(\"X\", value) }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() > 0)
}

///|
test "v1_error_payload_taint_reports" {
  let source = v1_may_fail() +
    " pub fn foo(resp : Response, x : String, flag : Bool) -> Unit { try { ignore(may_fail(x, flag)) } catch { Bad(value) => resp.set_header(\"X\", value) } }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() > 0)
}

///|
test "v1_noraise_success_arm_reports" {
  let source = v1_may_fail() +
    " pub fn foo(resp : Response, x : String, flag : Bool) -> Unit { try may_fail(x, flag) catch { _ => () } noraise { value => resp.set_header(\"X\", value) } }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() > 0)
}

///|
test "v1_catch_only_cleanup_still_reports" {
  let source = v1_may_fail() +
    " pub fn foo(resp : Response, x : String, flag : Bool) -> Unit { let mut value = x; try { ignore(may_fail(x, flag)) } catch { _ => value = \"safe\" }; resp.set_header(\"X\", value) }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() > 0)
}

///|
test "v1_tuple_component_clean_no_report" {
  let source = "pub fn foo(resp : Response, x : String) -> Unit { let (_dirty, clean) = (x, \"safe\"); resp.set_header(\"X\", clean) }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() == 0)
}

// ---------------------------------------------------------------------------
// T2 first batch: scope ids / single-evaluation / direct raise payload
// ---------------------------------------------------------------------------

///|
test "t2_scope_closure_param_no_longer_clobbers_outer_var" {
  // G2 same-name: the closure param `v` lives in its OWN scope; the outer
  // tainted `v` survives the closure body (flat-env engines restored the
  // outer binding to Clean after the closure — a known miss)
  let source = "pub fn go(resp : Response, req : Request) -> Unit { let v = req.query(\"q\"); let f = fn(v : String) -> Unit { ignore(v) }; f(\"x\"); resp.set_header(\"X\", v) }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() > 0)
}

///|
test "t2_scope_branch_binding_does_not_leak" {
  // a branch-local binding stays branch-local: after the if, the outer
  // `h` (constant) is still clean even though the then-branch bound a
  // same-name tainted value in its own scope
  let source = "pub fn go(resp : Response, c : Bool, req : Request) -> Unit { let h = \"safe\"; if c { let h = req.query(\"q\"); ignore(h) } else { () }; resp.set_header(\"X\", h) }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() == 0)
}

///|
test "t2_single_eval_sink_arg_reported_exactly_once" {
  // G2 double evaluation: the value-slot argument contains a nested sink
  // call; single-evaluation contract => exactly ONE finding (the inner
  // report). Re-flowing args would report it twice.
  let source = "pub fn go(resp : Response, req : Request) -> Unit { resp.set_header(\"X\", resp.set_header(\"Y\", req.query(\"q\"))) }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "test.mbt", source, findings, Error)
  inspect(findings.length(), content="1")
}

///|
test "t2_raise_direct_payload_alerts_in_catch" {
  // G3: raise Bad(query()) — the payload taint flows directly to the
  // catch binding (no temp variable needed)
  let source = "pub fn go(resp : Response, req : Request) -> Unit { try { raise Bad(req.query(\"q\")) } catch { Bad(v) => resp.set_header(\"X\", v) } }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() > 0)
}

///|
test "t2_raise_temp_var_version_behaves_identically" {
  // equivalence rewrite: storing the payload in a temp variable first
  // must produce the SAME alert (review: equivalent rewrites may not
  // change analysis facts)
  let source = "pub fn go(resp : Response, req : Request) -> Unit { let t = req.query(\"q\"); try { raise Bad(t) } catch { Bad(v) => resp.set_header(\"X\", v) } }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() > 0)
}

///|
test "t2_tuple_component_projection_via_field" {
  // C1 (G2): let pair = (tainted, "safe"); sink(pair.1) must stay SILENT —
  // the Index projection reads the exact recorded component
  let source = "pub fn go(resp : Response, req : Request) -> Unit { let pair = (req.query(\"q\"), \"safe\"); resp.set_header(\"X\", pair.1) }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() == 0)
}

///|
test "t2_tuple_component_zero_still_tainted" {
  // negative control: the FIRST component stays tainted (projection is
  // positional, not blanket)
  let source = "pub fn go(resp : Response, req : Request) -> Unit { let pair = (req.query(\"q\"), \"safe\"); resp.set_header(\"X\", pair.0) }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() > 0)
}

// ---------------------------------------------------------------------------
// R3/R4/R5 (round-5): declaration ids, eval-then-bind, value identity
// ---------------------------------------------------------------------------

///|
test "r3r4_orig_same_name_destructure_reports" {
  // review c9 ORIGINAL: RHS evaluated fully before pattern binding, so the
  // second component reads the OUTER tainted x
  let source = "fn foo(resp : Response, x : String) -> Unit { let (x, value) = (\"safe\", x); resp.set_header(\"H\", value) }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() == 1)
}

///|
test "r4_match_pattern_shadow_scoped" {
  // review c10: `match "safe" { x => ... }` must not silence outer x
  let source = "fn foo(resp : Response, x : String) -> Unit { match \"safe\" { x => ignore(x) }; resp.set_header(\"H\", x) }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() == 1)
}

///|
test "r4_block_let_does_not_leak" {
  // review c11: the block-scoped x must not shadow the outer param
  let source = "fn foo(resp : Response, x : String) -> Unit { let _v = { let x = \"safe\"; x }; resp.set_header(\"H\", x) }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() == 1)
}

///|
test "r5_tuple_rebind_invalidates_stale_components" {
  // review c12: rebinding `pair` must not reuse the old clean components
  let source = "fn mk(x : String) -> (String, String) { (x, x) } fn foo(resp : Response, x : String) -> Unit { let pair = (\"safe\", \"safe\"); ignore(pair); let pair = mk(x); resp.set_header(\"H\", pair.0) }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() == 1)
}

///|
test "r5_tuple_literal_components_still_project" {
  // negative control: clean components of a tuple literal stay clean
  let source = "fn foo(resp : Response, x : String) -> Unit { let pair = (x, \"safe\"); ignore(pair.0); resp.set_header(\"H\", pair.1) }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() == 0)
}

///|
test "r3_same_scope_scalar_rebind_chains" {
  // same-scope rebind: the RHS reads the PREVIOUS declaration
  let source = "fn foo(resp : Response, x : String) -> Unit { let y = \"safe\"; let y = x; resp.set_header(\"H\", y) }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() == 1)
}

///|
test "r6_nested_try_error_exit_isolation" {
  // round-5 P0: an inner (fully-handled) try must not wipe the outer
  // raise facts — Bad carries input()'s taint to the OUTER catch binding
  let src = "fn go() -> Unit { let resp = Response::{}; try { if flip() { raise Bad(query()) }; try { raise Fine } catch { _ => () } } catch { Bad(value) => resp.set_header(\"X-Nested\", value) } }"
  let (impls, _) = @parser.parse_string(src, name="t.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "t.mbt", src, findings, Error)
  inspect(findings.length(), content="1")
}

///|
test "r6_inner_constr_only_catch_propagates_unmatched" {
  // constructor-only catch leaves unmatched raise types free to escape:
  // the tainted Bad raised inside the inner try is NOT consumed by the
  // Fine-only handler and reaches the outer generic catch (sound direction)
  let src = "fn go() -> Unit { let resp = Response::{}; try { try { raise Bad(query()) } catch { Fine => () } } catch { e => resp.set_header(\"X-Escape\", Show::to_string(e)) } }"
  let (impls, _) = @parser.parse_string(src, name="t.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "t.mbt", src, findings, Error)
  inspect(findings.length() > 0, content="true")
}

// ---------------------------------------------------------------------------
// T2.2 thin: defer exit paths + short-circuit + valued break/continue
// ---------------------------------------------------------------------------

///|
test "t2b_defer_lifo_order" {
  // LIFO: the LAST-registered defer (x = v) runs FIRST, so the sink in the
  // first defer sees the taint -> 1 finding. FIFO order would report 0.
  let source = "fn f(r : Response, v : String) -> Unit { let mut x = \"safe\"; defer { r.set_header(\"X\", x) }; defer { x = v }; () }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "test.mbt", source, findings, Error)
  inspect(findings.length(), content="1")
}

///|
test "t2b_defer_runs_at_block_exit_not_inline" {
  // the sink BEFORE the block tail sees pre-defer state: defer { x = v }
  // has not executed at the sink point -> 0 findings
  let source = "fn f(r : Response, v : String) -> Unit { let mut x = \"safe\"; defer { x = v }; r.set_header(\"X\", x) }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "test.mbt", source, findings, Error)
  inspect(findings.length(), content="0")
}

///|
test "t2b_defer_executes_and_can_reach_sink_after_state" {
  // two defers, sink in the LAST registered one runs FIRST (clean), then
  // the earlier-registered taint write runs; nothing observes it -> 0.
  // (paired with lifo test above which observes the opposite order)
  let source = "fn f(r : Response, v : String) -> Unit { let mut x = \"safe\"; defer { x = v }; defer { r.set_header(\"X\", x) }; () }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "test.mbt", source, findings, Error)
  inspect(findings.length(), content="0")
}

///|
test "t2b_short_circuit_const_false_skips_rhs_sink" {
  // `false && sink(...)`: rhs never executes -> no finding
  let source = "fn f(r : Response, v : String) -> Unit { ignore(false && r.set_header(\"X\", v)) }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "test.mbt", source, findings, Error)
  inspect(findings.length(), content="0")
}

///|
test "t2b_short_circuit_const_true_skips_rhs_sink" {
  // `true || sink(...)`: rhs never executes -> no finding
  let source = "fn f(r : Response, v : String) -> Unit { ignore(true || r.set_header(\"X\", v)) }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "test.mbt", source, findings, Error)
  inspect(findings.length(), content="0")
}

///|
test "t2b_short_circuit_join_is_sound" {
  // `c && v`: result may carry rhs taint on the deciding path -> report
  let source = "fn f(r : Response, c : Bool, v : String) -> Unit { let t = c && v; r.set_header(\"X\", t) }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "test.mbt", source, findings, Error)
  inspect(findings.length(), content="1")
}

///|
test "t2b_break_evaluates_its_value_expression" {
  // break(expr): the value expression's effects happen before the exit
  let source = "fn f(r : Response, v : String) -> Unit { while true { break r.set_header(\"X\", v) } }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "test.mbt", source, findings, Error)
  inspect(findings.length(), content="1")
}
