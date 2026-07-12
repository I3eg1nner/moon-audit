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
    rule_id: { cwe: 942, variant: "cors-credentials" },
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
    rule_id: { cwe: 79, variant: "cmark-unsafe" },
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
    rule_id: { cwe: 116, variant: "replace-escaping" },
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
    rule_id: { cwe: 942, variant: "cors-credentials" },
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
    rule_id: { cwe: 614, variant: "cookie-attrs" },
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
      rule_id: { cwe: 942, variant: "cors-credentials" },
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
      rule_id: { cwe: 770, variant: "no-body-limit" },
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
    rule_id: { cwe: 116, variant: "replace-escaping" },
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
      rule_id: { cwe: 614, variant: "cookie-attrs" },
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
      rule_id: { cwe: 614, variant: "cookie-attrs" },
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
    rule_id: { cwe: 942, variant: "cors-credentials" },
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
  let id : RuleId = { cwe: 942, variant: "cors-credentials" }
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
