// Scanner rule tests: each rule gets at least one positive and one negative test.

// ---------------------------------------------------------------------------
// CWE-116: String::replace used for HTML escaping (should use replace_all)
// ---------------------------------------------------------------------------

///|
test "CWE-116: replace with HTML metachar should trigger" {
  let source = "fn foo(s : String) -> String { s.replace(old=\"<\", new=\"&lt;\") }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe116(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() > 0)
}

///|
test "CWE-116: replace_all should not trigger" {
  let source = "fn foo(s : String) -> String { s.replace_all(old=\"<\", new=\"&lt;\") }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe116(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() == 0)
}

// ---------------------------------------------------------------------------
// CWE-79/cmark: render()/from_doc() without safe=true
// ---------------------------------------------------------------------------

///|
test "CWE-079/cmark: render without safe=true should trigger" {
  let source = "fn foo(md : String) -> String { render(md) }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe079_cmark(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() > 0)
}

///|
test "CWE-079/cmark: render with safe=true should not trigger" {
  let source = "fn foo(md : String) -> String { render(md, safe=true) }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe079_cmark(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() == 0)
}

// ---------------------------------------------------------------------------
// CWE-79/inner-html: inner_html() with non-constant argument
// ---------------------------------------------------------------------------

///|
test "CWE-079/inner-html: non-constant arg should trigger" {
  let source = "fn foo(el : Element, content : String) -> Unit { el.inner_html(content) }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe079_inner_html(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() > 0)
}

///|
test "CWE-079/inner-html: constant string arg should not trigger" {
  let source = "fn foo(el : Element) -> Unit { el.inner_html(\"<b>bold</b>\") }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe079_inner_html(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() == 0)
}

// ---------------------------------------------------------------------------
// CWE-94: eval() or new Function() in extern JS blocks
// ---------------------------------------------------------------------------

///|
test "CWE-094: eval in extern JS should trigger" {
  let source = "extern \"js\" fn dangerous() -> String =\n  #| eval(user_input)\n"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe094(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() > 0)
}

///|
test "CWE-094: new Function in extern JS should trigger" {
  let source = "extern \"js\" fn build() -> String =\n  #| new Function(code)\n"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe094(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() > 0)
}

///|
test "CWE-094: safe extern JS should not trigger" {
  let source = "extern \"js\" fn safe_fn() -> Int =\n  #| return 42\n"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe094(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() == 0)
}

// ---------------------------------------------------------------------------
// CWE-942: CORS credentials=true without explicit origin
// ---------------------------------------------------------------------------

///|
test "CWE-942: handle_cors with credentials=true without origin should trigger" {
  let source = "fn setup() -> Unit { handle_cors(credentials=true) }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe942(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() > 0)
}

///|
test "CWE-942: handle_cors with credentials=true and explicit origin should not trigger" {
  let source = "fn setup() -> Unit { handle_cors(credentials=true, origin=\"https://example.com\") }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe942(impls, "test.mbt", source, findings, Error)
  assert_true(findings.length() == 0)
}

// ---------------------------------------------------------------------------
// CWE-614: set_cookie without http_only / secure / same_site
// ---------------------------------------------------------------------------

///|
test "CWE-614: set_cookie without security attrs should trigger" {
  let source = "fn foo(resp : Response) -> Unit { resp.set_cookie(\"session\", \"abc123\") }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe614(impls, "test.mbt", source, findings, Warning)
  assert_true(findings.length() > 0)
}

///|
test "CWE-614: set_cookie with all security attrs should not trigger" {
  let source = "fn foo(resp : Response) -> Unit { resp.set_cookie(\"session\", \"abc123\", http_only=true, secure=true, same_site=\"Strict\") }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe614(impls, "test.mbt", source, findings, Warning)
  assert_true(findings.length() == 0)
}

// ---------------------------------------------------------------------------
// CWE-770: serve/listen without max body size (requires POST/PUT/PATCH route)
// ---------------------------------------------------------------------------

///|
test "CWE-770: serve without body limit with POST route should trigger" {
  let source = "fn start(app : App) -> Unit {\n  app.post(\"/upload\", handler)\n  app.serve(port=4000)\n}"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe770(impls, "test.mbt", source, findings, Warning)
  assert_true(findings.length() > 0)
}

///|
test "CWE-770: serve with body limit should not trigger" {
  let source = "fn start(app : App) -> Unit {\n  app.post(\"/upload\", handler)\n  app.serve(port=4000, max_request_body_bytes=1048576)\n}"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe770(impls, "test.mbt", source, findings, Warning)
  assert_true(findings.length() == 0)
}

///|
test "CWE-770: serve without POST route should not trigger" {
  let source = "fn start(app : App) -> Unit {\n  app.get(\"/\", handler)\n  app.serve(port=4000)\n}"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe770(impls, "test.mbt", source, findings, Warning)
  assert_true(findings.length() == 0)
}

// ---------------------------------------------------------------------------
// CWE-346: WebSocket upgrade without origin validation
// ---------------------------------------------------------------------------

///|
test "CWE-346: upgrade_websocket without origin should trigger" {
  let source = "fn handle(req : Request) -> Unit { req.upgrade_websocket(handler) }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe346(impls, "test.mbt", source, findings, Warning)
  assert_true(findings.length() > 0)
}

///|
test "CWE-346: upgrade_websocket with allowed_origins should not trigger" {
  let source = "fn handle(req : Request) -> Unit { req.upgrade_websocket(handler, allowed_origins=origins) }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe346(impls, "test.mbt", source, findings, Warning)
  assert_true(findings.length() == 0)
}

// ---------------------------------------------------------------------------
// CWE-22: Path concatenation with user-controlled input
// ---------------------------------------------------------------------------

///|
test "CWE-022: path + user_input concat should trigger" {
  let source = "fn foo(path : String, user_input : String) -> String { path + user_input }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe022(impls, "test.mbt", source, findings, Warning)
  assert_true(findings.length() > 0)
}

///|
test "CWE-022: path + constant string should not trigger" {
  let source = "fn foo(path : String) -> String { path + \"/static\" }"
  let (impls, _) = @parser.parse_string(source, name="test.mbt")
  let findings : Array[Finding] = []
  run_cwe022(impls, "test.mbt", source, findings, Warning)
  assert_true(findings.length() == 0)
}
