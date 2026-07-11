// Remediation advice engine.
// Provides fix suggestions, code patches, and security best practices
// for each detected vulnerability type.

///|
pub(all) struct Remediation {
  rule_id : String
  title : String
  risk_summary : String
  fix_description : String
  code_before : String
  code_after : String
  references : Array[String]
  owasp_category : String
}

///|
pub fn get_remediation(finding : Finding) -> Remediation {
  let rule_id = rule_id_str(finding.rule_id)
  if rule_id == "CWE-116/replace-escaping" {
    remediation_cwe116()
  } else if rule_id == "CWE-79/cmark-unsafe" {
    remediation_cwe079_cmark()
  } else if rule_id == "CWE-79/inner-html" {
    remediation_cwe079_inner_html()
  } else if rule_id == "CWE-94/eval-extern" {
    remediation_cwe094()
  } else if rule_id == "CWE-942/cors-credentials" {
    remediation_cwe942()
  } else if rule_id == "CWE-614/cookie-attrs" {
    remediation_cwe614()
  } else if rule_id == "CWE-770/no-body-limit" {
    remediation_cwe770()
  } else if rule_id == "CWE-346/ws-origin" {
    remediation_cwe346()
  } else if rule_id == "CWE-22/path-concat" {
    remediation_cwe022()
  } else {
    remediation_generic(rule_id)
  }
}

///|
pub fn get_all_remediations(findings : Array[Finding]) -> Array[Remediation] {
  let seen : Map[String, Bool] = {}
  let result : Array[Remediation] = []
  for f in findings {
    let id = rule_id_str(f.rule_id)
    if !seen.contains(id) {
      seen[id] = true
      result.push(get_remediation(f))
    }
  }
  result
}

///|
fn remediation_cwe116() -> Remediation {
  {
    rule_id: "CWE-116/replace-escaping",
    title: "Use replace_all() Instead of replace() for HTML Escaping",
    risk_summary: "MoonBit's String::replace() only replaces the first occurrence. Attackers can bypass HTML escaping by including multiple special characters.",
    fix_description: "Replace all calls to .replace() with .replace_all() when escaping HTML metacharacters. Better yet, use a dedicated HTML escaping function that handles all characters in one pass.",
    code_before: "fn escape_html(s : String) -> String {\n  s.replace(old=\"<\", new=\"&lt;\")\n   .replace(old=\">\", new=\"&gt;\")\n   .replace(old=\"&\", new=\"&amp;\")\n}",
    code_after: "fn escape_html(s : String) -> String {\n  s.replace_all(old=\"&\", new=\"&amp;\")  // & first!\n   .replace_all(old=\"<\", new=\"&lt;\")\n   .replace_all(old=\">\", new=\"&gt;\")\n   .replace_all(old=\"\\\"\", new=\"&quot;\")\n   .replace_all(old=\"'\", new=\"&#x27;\")\n}",
    references: [
      "https://cwe.mitre.org/data/definitions/116.html", "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
    ],
    owasp_category: "A03:2021 - Injection",
  }
}

///|
fn remediation_cwe079_cmark() -> Remediation {
  {
    rule_id: "CWE-79/cmark-unsafe",
    title: "Enable Safe Mode for cmark HTML Rendering",
    risk_summary: "cmark's render() defaults to safe=false, allowing raw HTML tags (<script>, <iframe>) and dangerous URL schemes (javascript:, vbscript:) to pass through. This enables stored XSS when rendering user-provided Markdown.",
    fix_description: "Always pass safe=true when rendering user-provided Markdown content. This replaces raw HTML with a safe comment marker and strips dangerous URL schemes.",
    code_before: "let html = @cmark_html.render(user_markdown)",
    code_after: "let html = @cmark_html.render(user_markdown, safe=true)",
    references: [
      "https://cwe.mitre.org/data/definitions/79.html", "https://github.github.com/gfm/#raw-html",
    ],
    owasp_category: "A03:2021 - Injection",
  }
}

///|
fn remediation_cwe079_inner_html() -> Remediation {
  {
    rule_id: "CWE-79/inner-html",
    title: "Sanitize Content Before inner_html()",
    risk_summary: "inner_html() sets raw HTML content on DOM elements. When the argument contains user-controlled data, attackers can inject arbitrary HTML and JavaScript.",
    fix_description: "Use text_content() instead of inner_html() for plain text. If HTML is needed, sanitize the input through an allowlist-based HTML sanitizer before passing to inner_html().",
    code_before: "element.inner_html(user_input)",
    code_after: "// Option 1: Use text_content for plain text\nelement.text_content(user_input)\n\n// Option 2: Sanitize HTML before injection\nlet safe_html = sanitize_html(user_input)\nelement.inner_html(safe_html)",
    references: [
      "https://cwe.mitre.org/data/definitions/79.html", "https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html",
    ],
    owasp_category: "A03:2021 - Injection",
  }
}

///|
fn remediation_cwe094() -> Remediation {
  {
    rule_id: "CWE-94/eval-extern",
    title: "Remove eval() and new Function() from Extern JS",
    risk_summary: "eval() and new Function() in extern JavaScript blocks execute arbitrary code strings. If any part of the input is user-controlled, this enables remote code execution.",
    fix_description: "Replace eval() with structured alternatives: JSON.parse() for data parsing, direct property access for dynamic lookups, or pre-compiled functions for template evaluation.",
    code_before: "extern \"js\" fn process(code : String) -> String =\n  #| eval(code)",
    code_after: "extern \"js\" fn process(data : String) -> String =\n  #| JSON.parse(data)",
    references: [
      "https://cwe.mitre.org/data/definitions/94.html", "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval#never_use_eval!",
    ],
    owasp_category: "A03:2021 - Injection",
  }
}

///|
fn remediation_cwe942() -> Remediation {
  {
    rule_id: "CWE-942/cors-credentials",
    title: "Restrict CORS Origin When Using Credentials",
    risk_summary: "When credentials=true, the server reflects any Origin header in Access-Control-Allow-Origin. This allows any website to make authenticated cross-origin requests and steal user data.",
    fix_description: "Specify an explicit list of allowed origins instead of reflecting the request Origin. Never use wildcard (*) with credentials.",
    code_before: "app.use_middleware(@cors.handle_cors(credentials=true))",
    code_after: "app.use_middleware(@cors.handle_cors(\n  credentials=true,\n  origin=\"https://your-app.example.com\"\n))",
    references: [
      "https://cwe.mitre.org/data/definitions/942.html", "https://portswigger.net/web-security/cors",
    ],
    owasp_category: "A01:2021 - Broken Access Control",
  }
}

///|
fn remediation_cwe614() -> Remediation {
  {
    rule_id: "CWE-614/cookie-attrs",
    title: "Add Security Attributes to Cookies",
    risk_summary: "Cookies without HttpOnly, Secure, and SameSite attributes are vulnerable to theft via XSS (document.cookie), network interception (no HTTPS enforcement), and CSRF attacks.",
    fix_description: "Always set HttpOnly (prevents JS access), Secure (requires HTTPS), and SameSite=Strict or Lax (prevents CSRF) on session and authentication cookies.",
    code_before: "event.res.set_cookie(\"session\", token, path=\"/\")",
    code_after: "event.res.set_cookie(\"session\", token,\n  path=\"/\",\n  http_only=true,\n  secure=true,\n  same_site=Strict\n)",
    references: [
      "https://cwe.mitre.org/data/definitions/614.html", "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#cookie-attributes",
    ],
    owasp_category: "A01:2021 - Broken Access Control",
  }
}

///|
fn remediation_cwe770() -> Remediation {
  {
    rule_id: "CWE-770/no-body-limit",
    title: "Set Maximum Request Body Size",
    risk_summary: "Without a body size limit, attackers can send arbitrarily large POST requests to exhaust server memory, causing denial of service.",
    fix_description: "Configure a maximum request body size appropriate for your application. Typical limits: 1MB for JSON APIs, 10MB for file uploads.",
    code_before: "app.serve(port=4000)",
    code_after: "app.serve(port=4000, max_request_body_bytes=1048576)  // 1MB",
    references: [
      "https://cwe.mitre.org/data/definitions/770.html", "https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html",
    ],
    owasp_category: "A05:2021 - Security Misconfiguration",
  }
}

///|
fn remediation_cwe346() -> Remediation {
  {
    rule_id: "CWE-346/ws-origin",
    title: "Validate WebSocket Origin Header",
    risk_summary: "Without Origin validation, any website can establish WebSocket connections to your server, enabling cross-site WebSocket hijacking to steal data or perform actions as the victim.",
    fix_description: "Check the Origin header during WebSocket upgrade and reject connections from unauthorized origins.",
    code_before: "req.upgrade_websocket(handler)",
    code_after: "req.upgrade_websocket(handler,\n  allowed_origins=[\"https://your-app.example.com\"]\n)",
    references: [
      "https://cwe.mitre.org/data/definitions/346.html", "https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking",
    ],
    owasp_category: "A01:2021 - Broken Access Control",
  }
}

///|
fn remediation_cwe022() -> Remediation {
  {
    rule_id: "CWE-22/path-concat",
    title: "Sanitize Path Components to Prevent Traversal",
    risk_summary: "String concatenation to build file paths allows attackers to inject ../ sequences and access files outside the intended directory.",
    fix_description: "Use path canonicalization and verify the resolved path starts with the intended root directory. Reject any path containing .. segments.",
    code_before: "let file_path = base_dir + \"/\" + user_filename",
    code_after: "let file_path = @path.Path(base_dir).join(@path.Path(user_filename)).0\n// Verify the resolved path is within the allowed root\nlet canon = canonicalize(file_path)\nif !canon.has_prefix(base_dir) {\n  abort(\"Path traversal detected\")\n}",
    references: [
      "https://cwe.mitre.org/data/definitions/22.html", "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
    ],
    owasp_category: "A01:2021 - Broken Access Control",
  }
}

///|
fn remediation_generic(rule_id : String) -> Remediation {
  {
    rule_id,
    title: "Security Finding",
    risk_summary: "A potential security issue was detected by static analysis.",
    fix_description: "Review the flagged code and apply appropriate security controls.",
    code_before: "",
    code_after: "",
    references: ["https://cwe.mitre.org/"],
    owasp_category: "General",
  }
}

///|
pub fn format_remediation_report(remediations : Array[Remediation]) -> String {
  let buf = StringBuilder::new()
  buf.write_string("# Security Remediation Guide\n\n")
  for i, r in remediations {
    buf.write_string("## ")
    buf.write_string((i + 1).to_string())
    buf.write_string(". ")
    buf.write_string(r.title)
    buf.write_string(" (")
    buf.write_string(r.rule_id)
    buf.write_string(")\n\n")
    buf.write_string("**OWASP**: ")
    buf.write_string(r.owasp_category)
    buf.write_string("\n\n")
    buf.write_string("### Risk\n\n")
    buf.write_string(r.risk_summary)
    buf.write_string("\n\n")
    buf.write_string("### Fix\n\n")
    buf.write_string(r.fix_description)
    buf.write_string("\n\n")
    if r.code_before.length() > 0 {
      buf.write_string("**Before:**\n```moonbit\n")
      buf.write_string(r.code_before)
      buf.write_string("\n```\n\n")
      buf.write_string("**After:**\n```moonbit\n")
      buf.write_string(r.code_after)
      buf.write_string("\n```\n\n")
    }
    buf.write_string("### References\n\n")
    for item in r.references {
      buf.write_string("- ")
      buf.write_string(item)
      buf.write_char('\n')
    }
    buf.write_string("\n---\n\n")
  }
  buf.to_string()
}
