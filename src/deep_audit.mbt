// Deep audit: combines static analysis with LLM-powered code review.
// Generates a self-contained Python script that:
// 1. Verifies static analysis findings with LLM
// 2. Sends prioritized source files to LLM for deep security review
// 3. Merges and deduplicates results
//
// Context management strategy:
// - Files scored by security relevance (HTTP handlers > utilities)
// - Static findings included as context so LLM doesn't repeat them
// - Focused prompts targeting exploitable HIGH/CRITICAL issues only
// - Smart batching groups related files together

///|
pub fn collect_audit_files(
  root : String,
  config : Config,
) -> Array[(String, String)] {
  let files : Array[(String, String)] = []
  collect_audit_walk(root, config, files)
  // Sort by security relevance — high-priority files first
  files.sort_by(fn(a, b) {
    let sa = file_security_score(a.0, a.1)
    let sb = file_security_score(b.0, b.1)
    sb - sa
  })
  files
}

///|
fn collect_audit_walk(
  dir : String,
  config : Config,
  files : Array[(String, String)],
) -> Unit {
  let entries = @fs.read_dir(dir) catch { _ => return }
  let subdirs : Array[String] = []
  for entry in entries {
    let full = @path.Path(dir).join(@path.Path(entry)).0
    if entry.has_prefix(".") ||
      entry == "_build" ||
      entry == ".mooncakes" ||
      entry == "node_modules" {
      continue
    }
    let mut excluded = false
    for pat in config.exclude {
      if entry == pat {
        excluded = true
        break
      }
    }
    if excluded {
      continue
    }
    // Skip test directories
    if entry == "test" || entry == "tests" || entry == "__test__" {
      continue
    }
    let is_dir = @fs.is_dir(full) catch { _ => false }
    if is_dir {
      subdirs.push(full)
    } else if entry.has_suffix(".mbt") &&
      !entry.has_suffix("_test.mbt") &&
      !entry.has_suffix("_wbtest.mbt") {
      let content = @fs.read_file_to_string(full) catch { _ => continue }
      if content.length() > 0 && content.length() < 20000 {
        files.push((full, content))
      }
    }
  }
  for subdir in subdirs {
    collect_audit_walk(subdir, config, files)
  }
}

///|
fn file_security_score(path : String, content : String) -> Int {
  let mut score = 0
  // HTTP/routing files — highest priority
  if has_keyword(content, "fn handle") ||
    has_keyword(content, "fn serve") ||
    has_keyword(content, "Request") ||
    has_keyword(content, "Response") {
    score += 40
  }
  // Path-based hints
  if has_keyword(path, "route") ||
    has_keyword(path, "handler") ||
    has_keyword(path, "middleware") ||
    has_keyword(path, "server") ||
    has_keyword(path, "api") {
    score += 30
  }
  // Security-sensitive patterns in content
  if has_keyword(content, "cookie") ||
    has_keyword(content, "Cookie") ||
    has_keyword(content, "session") ||
    has_keyword(content, "Session") {
    score += 25
  }
  if has_keyword(content, "auth") ||
    has_keyword(content, "Auth") ||
    has_keyword(content, "password") ||
    has_keyword(content, "token") {
    score += 25
  }
  if has_keyword(content, "header") ||
    has_keyword(content, "Header") ||
    has_keyword(content, "cors") ||
    has_keyword(content, "CORS") {
    score += 20
  }
  // Input handling
  if has_keyword(content, "parse") ||
    has_keyword(content, "decode") ||
    has_keyword(content, "query") ||
    has_keyword(content, "body") {
    score += 15
  }
  // FFI/extern — potential unsafe boundary
  if has_keyword(content, "extern") || has_keyword(content, "ffi") {
    score += 15
  }
  // HTML/template rendering
  if has_keyword(content, "html") ||
    has_keyword(content, "HTML") ||
    has_keyword(content, "render") ||
    has_keyword(content, "template") {
    score += 15
  }
  // File/path operations
  if has_keyword(content, "read_file") ||
    has_keyword(content, "write_file") ||
    has_keyword(content, "path") {
    score += 10
  }
  // Utility/helper files get lower priority
  if has_keyword(path, "util") || has_keyword(path, "helper") {
    score -= 10
  }
  score
}

///|
fn has_keyword(s : String, keyword : String) -> Bool {
  s.contains(keyword)
}

///|
pub fn generate_deep_audit_script(
  llm_config : LLMConfig,
  findings : Array[Finding],
  source_files : Array[(String, String)],
) -> String {
  let buf = StringBuilder::new()
  write_deep_header(buf)
  write_deep_env_loader(buf)
  write_deep_config(buf, llm_config)
  write_deep_call_llm(buf)
  write_deep_static_findings(buf, findings)
  write_deep_source_files(buf, source_files)
  write_deep_audit_prompt(buf, findings)
  write_deep_main(buf)
  buf.to_string()
}

///|
fn write_deep_header(buf : StringBuilder) -> Unit {
  buf.write_string("#!/usr/bin/env python3\n")
  buf.write_string("\"\"\"moon-audit Deep Security Audit\n")
  buf.write_string(
    "Combines static analysis findings with LLM-powered code review.\n",
  )
  buf.write_string("Auto-generated script. Usage: python3 deep_audit.py\n")
  buf.write_string("\"\"\"\n\n")
  buf.write_string("import json, os, sys, time\n")
  buf.write_string("from pathlib import Path\n\n")
}

///|
fn write_deep_env_loader(buf : StringBuilder) -> Unit {
  buf.write_string("# ── Load .env file ──\n")
  buf.write_string("def load_dotenv():\n")
  buf.write_string("    env = {}\n")
  buf.write_string(
    "    for p in [Path('.env'), Path(__file__).parent / '.env']:\n",
  )
  buf.write_string("        if p.is_file():\n")
  buf.write_string("            for line in p.read_text().splitlines():\n")
  buf.write_string("                line = line.strip()\n")
  buf.write_string(
    "                if not line or line.startswith('#') or '=' not in line:\n",
  )
  buf.write_string("                    continue\n")
  buf.write_string("                k, v = line.split('=', 1)\n")
  buf.write_string("                v = v.strip().strip('\"').strip(\"'\")\n")
  buf.write_string("                env[k.strip()] = v\n")
  buf.write_string("            break\n")
  buf.write_string("    return env\n\n")
  buf.write_string("_dotenv = load_dotenv()\n")
  buf.write_string("def _cfg(key, default=''):\n")
  buf.write_string(
    "    return os.environ.get(key) or _dotenv.get(key) or default\n\n",
  )
}

///|
fn write_deep_config(buf : StringBuilder, llm_config : LLMConfig) -> Unit {
  buf.write_string("# ── Configuration ──\n")
  buf.write_string(
    "BASE_URL = _cfg('LLM_BASE_URL') or _cfg('Base_URL') or _cfg('BASE_URL', '",
  )
  buf.write_string(escape_py_str(llm_config.base_url))
  buf.write_string("')\n")
  buf.write_string(
    "MODEL    = _cfg('LLM_MODEL') or _cfg('Model') or _cfg('MODEL', '",
  )
  buf.write_string(escape_py_str(llm_config.model))
  buf.write_string("')\n")
  buf.write_string(
    "API_KEY  = _cfg('LLM_API_KEY') or _cfg('API_KEY') or _cfg('ANTHROPIC_API_KEY')\n\n",
  )
  buf.write_string("if not API_KEY:\n")
  buf.write_string("    print('ERROR: No API key. Set LLM_API_KEY in .env')\n")
  buf.write_string("    sys.exit(1)\n\n")
  buf.write_string("IS_ANTHROPIC = 'anthropic' in BASE_URL\n\n")
}

///|
fn write_deep_call_llm(buf : StringBuilder) -> Unit {
  buf.write_string("# ── HTTP client ──\n")
  buf.write_string("try:\n")
  buf.write_string("    import httpx\n")
  buf.write_string("    _client = httpx.Client(timeout=120)\n")
  buf.write_string("    def _post(url, headers, body):\n")
  buf.write_string(
    "        r = _client.post(url, headers=headers, json=body)\n",
  )
  buf.write_string("        return r.status_code, r.json()\n")
  buf.write_string("except ImportError:\n")
  buf.write_string("    from urllib.request import Request, urlopen\n")
  buf.write_string("    def _post(url, headers, body):\n")
  buf.write_string(
    "        req = Request(url, data=json.dumps(body).encode(), headers=headers, method='POST')\n",
  )
  buf.write_string("        resp = urlopen(req, timeout=120)\n")
  buf.write_string("        return resp.status, json.loads(resp.read())\n\n")
  buf.write_string(
    "def call_llm(system_prompt, user_prompt, max_tokens=4096):\n",
  )
  buf.write_string("    if IS_ANTHROPIC:\n")
  buf.write_string("        headers = {\n")
  buf.write_string("            'x-api-key': API_KEY,\n")
  buf.write_string("            'content-type': 'application/json',\n")
  buf.write_string("            'anthropic-version': '2023-06-01',\n")
  buf.write_string("        }\n")
  buf.write_string("        body = {\n")
  buf.write_string("            'model': MODEL,\n")
  buf.write_string("            'max_tokens': max_tokens,\n")
  buf.write_string("            'system': system_prompt,\n")
  buf.write_string(
    "            'messages': [{'role': 'user', 'content': user_prompt}],\n",
  )
  buf.write_string("        }\n")
  buf.write_string("    else:\n")
  buf.write_string("        url = BASE_URL\n")
  buf.write_string("        if not url.endswith('/chat/completions'):\n")
  buf.write_string("            url = url.rstrip('/') + '/chat/completions'\n")
  buf.write_string("        headers = {\n")
  buf.write_string("            'Authorization': f'Bearer {API_KEY}',\n")
  buf.write_string("            'Content-Type': 'application/json',\n")
  buf.write_string("        }\n")
  buf.write_string("        body = {\n")
  buf.write_string("            'model': MODEL,\n")
  buf.write_string("            'max_tokens': max_tokens,\n")
  buf.write_string("            'messages': [\n")
  buf.write_string(
    "                {'role': 'system', 'content': system_prompt},\n",
  )
  buf.write_string(
    "                {'role': 'user', 'content': user_prompt},\n",
  )
  buf.write_string("            ],\n")
  buf.write_string("        }\n\n")
  buf.write_string("    try:\n")
  buf.write_string(
    "        status, resp = _post(BASE_URL if IS_ANTHROPIC else url, headers, body)\n",
  )
  buf.write_string("    except Exception as e:\n")
  buf.write_string("        print(f'  API call failed: {e}')\n")
  buf.write_string("        return None\n")
  buf.write_string("    if status != 200:\n")
  buf.write_string("        print(f'  API error: {status}')\n")
  buf.write_string("        return None\n")
  buf.write_string("    if IS_ANTHROPIC:\n")
  buf.write_string("        return resp['content'][0]['text']\n")
  buf.write_string("    else:\n")
  buf.write_string(
    "        return resp['choices'][0]['message']['content']\n\n",
  )
}

///|
fn write_deep_static_findings(
  buf : StringBuilder,
  findings : Array[Finding],
) -> Unit {
  buf.write_string("# ── Static analysis findings ──\n")
  buf.write_string("STATIC_FINDINGS = [\n")
  for f in findings {
    buf.write_string("    {'rule': '")
    buf.write_string(escape_py_str(rule_id_str(f.rule_id)))
    buf.write_string("', 'sev': '")
    buf.write_string(escape_py_str(severity_str(f.severity)))
    buf.write_string("', 'file': '")
    buf.write_string(escape_py_str(f.file))
    buf.write_string("', 'line': ")
    buf.write_string(f.line.to_string())
    buf.write_string(", 'msg': '")
    buf.write_string(escape_py_str(f.message))
    buf.write_string("'},\n")
  }
  buf.write_string("]\n\n")
}

///|
fn write_deep_source_files(
  buf : StringBuilder,
  files : Array[(String, String)],
) -> Unit {
  buf.write_string(
    "# ── Source files for deep audit (sorted by security relevance) ──\n",
  )
  buf.write_string("SOURCE_FILES = {\n")
  for pair in files {
    buf.write_string("    '")
    buf.write_string(escape_py_str(pair.0))
    buf.write_string("': ")
    write_py_triple_quoted(buf, pair.1)
    buf.write_string(",\n")
  }
  buf.write_string("}\n\n")
}

///|
fn build_static_findings_context(findings : Array[Finding]) -> String {
  if findings.length() == 0 {
    return ""
  }
  let buf = StringBuilder::new()
  buf.write_string(
    "The following issues were ALREADY found by static analysis. Do NOT repeat these — focus on NEW vulnerabilities that static analysis missed:\\n",
  )
  for f in findings {
    buf.write_string("- ")
    buf.write_string(rule_id_str(f.rule_id))
    buf.write_string(" @ ")
    buf.write_string(f.file)
    buf.write_string(":")
    buf.write_string(f.line.to_string())
    buf.write_string(" — ")
    buf.write_string(f.message)
    buf.write_string("\\n")
  }
  buf.to_string()
}

///|
fn write_deep_audit_prompt(
  buf : StringBuilder,
  findings : Array[Finding],
) -> Unit {
  let findings_ctx = build_static_findings_context(findings)
  buf.write_string("STATIC_CONTEXT = '")
  buf.write_string(escape_py_str(findings_ctx))
  buf.write_string("'\n\n")
  buf.write_string("DEEP_AUDIT_SYSTEM = ")
  write_py_triple_quoted(
    buf, "You are a senior security auditor performing a focused vulnerability assessment on MoonBit source code.\n\nIMPORTANT GUIDELINES:\n- Report ONLY exploitable vulnerabilities with real security impact\n- Severity must be HIGH or CRITICAL — skip informational/low findings\n- Each finding must describe a concrete attack scenario\n- Do NOT report: code style, best practices, theoretical risks without exploit path\n- Do NOT repeat issues already identified by static analysis (listed in context)\n\nFocus areas:\n1. Injection: XSS, CRLF, command injection, header injection\n2. Path traversal / directory escape\n3. Authentication/authorization bypass\n4. Insecure deserialization or parsing that enables code execution\n5. Resource exhaustion with attacker-controlled input (not just large data)\n6. Unsafe FFI boundaries that break memory safety guarantees\n7. Credential/secret exposure in responses\n\nFor each vulnerability, respond with a JSON array:\n[\n  {\n    \"file\": \"path/to/file.mbt\",\n    \"line\": 42,\n    \"category\": \"CWE-79/XSS\",\n    \"severity\": \"high\",\n    \"title\": \"Short title\",\n    \"description\": \"What the vulnerability is\",\n    \"attack_scenario\": \"Step-by-step how an attacker exploits this\",\n    \"impact\": \"What damage results\",\n    \"remediation\": \"How to fix it\"\n  }\n]\n\nIf no exploitable vulnerabilities are found, respond with: []\nRespond ONLY with the JSON array.",
  )
  buf.write_string("\n\n")
}

///|
fn write_deep_main(buf : StringBuilder) -> Unit {
  buf.write_string("def verify_findings():\n")
  buf.write_string(
    "    \"\"\"Phase 1: Verify static analysis findings.\"\"\"\n",
  )
  buf.write_string("    if not STATIC_FINDINGS:\n")
  buf.write_string("        return []\n")
  buf.write_string(
    "    print(f'Phase 1: Verifying {len(STATIC_FINDINGS)} static findings...')\n",
  )
  buf.write_string("    verified = []\n")
  buf.write_string("    for i, f in enumerate(STATIC_FINDINGS):\n")
  buf.write_string(
    "        print(f\"  [{i+1}/{len(STATIC_FINDINGS)}] {f['rule']} @ {f['file']}:{f['line']}\")\n",
  )
  buf.write_string("        ctx = SOURCE_FILES.get(f['file'], '')\n")
  buf.write_string("        if not ctx:\n")
  buf.write_string(
    "            verified.append({**f, 'verdict': 'unverified'})\n",
  )
  buf.write_string("            continue\n")
  buf.write_string("        lines = ctx.splitlines()\n")
  buf.write_string("        start = max(0, f['line'] - 11)\n")
  buf.write_string("        end = min(len(lines), f['line'] + 10)\n")
  buf.write_string(
    "        snippet = '\\n'.join(f'{j+1:4d} | {lines[j]}' for j in range(start, end))\n",
  )
  buf.write_string(
    "        prompt = f\"\"\"Verify this static analysis finding:\n",
  )
  buf.write_string("Rule: {f['rule']}\n")
  buf.write_string("File: {f['file']}:{f['line']}\n")
  buf.write_string("Message: {f['msg']}\n\n")
  buf.write_string("Source context:\n```moonbit\n{snippet}\n```\n\n")
  buf.write_string("Analyze whether this is exploitable. Consider:\n")
  buf.write_string("- Can an attacker actually reach this code path?\n")
  buf.write_string("- Is the input attacker-controlled?\n")
  buf.write_string("- What is the concrete impact if exploited?\n\n")
  buf.write_string("Respond with JSON:\n")
  buf.write_string(
    "{{\"is_true_positive\": true/false, \"confidence\": 0.0-1.0, \"exploitable\": true/false, \"explanation\": \"...\", \"remediation\": \"...\"}}\"\"\"\n",
  )
  buf.write_string(
    "        resp = call_llm('You are a MoonBit security expert. Assess exploitability, not just theoretical risk. Respond ONLY with JSON.', prompt, max_tokens=1024)\n",
  )
  buf.write_string("        if resp:\n")
  buf.write_string("            try:\n")
  buf.write_string("                start_j = resp.index('{')\n")
  buf.write_string("                end_j = resp.rindex('}') + 1\n")
  buf.write_string("                result = json.loads(resp[start_j:end_j])\n")
  buf.write_string(
    "                tp = result.get('is_true_positive', False)\n",
  )
  buf.write_string("                conf = result.get('confidence', 0)\n")
  buf.write_string(
    "                exploitable = result.get('exploitable', False)\n",
  )
  buf.write_string("                if tp and exploitable:\n")
  buf.write_string("                    v = 'EXPLOITABLE'\n")
  buf.write_string("                elif tp:\n")
  buf.write_string(
    "                    v = 'TRUE POSITIVE (not easily exploitable)'\n",
  )
  buf.write_string("                else:\n")
  buf.write_string("                    v = 'FALSE POSITIVE'\n")
  buf.write_string(
    "                print(f'    => {v} (confidence: {conf})')\n",
  )
  buf.write_string(
    "                verified.append({**f, 'verdict': v.lower(), **result})\n",
  )
  buf.write_string("            except (ValueError, json.JSONDecodeError):\n")
  buf.write_string(
    "                verified.append({**f, 'verdict': 'unverified'})\n",
  )
  buf.write_string("        else:\n")
  buf.write_string(
    "            verified.append({**f, 'verdict': 'unverified'})\n",
  )
  buf.write_string("        time.sleep(1)\n")
  buf.write_string("    return verified\n\n")
  buf.write_string("def deep_audit_files():\n")
  buf.write_string(
    "    \"\"\"Phase 2: LLM reads source code to find new vulnerabilities.\"\"\"\n",
  )
  buf.write_string("    if not SOURCE_FILES:\n")
  buf.write_string("        return []\n")
  buf.write_string("    # Group files into batches by security relevance\n")
  buf.write_string("    batches = []\n")
  buf.write_string("    current_batch = []\n")
  buf.write_string("    current_size = 0\n")
  buf.write_string("    MAX_BATCH = 15000  # chars per batch\n")
  buf.write_string("    for path, content in SOURCE_FILES.items():\n")
  buf.write_string(
    "        if current_size + len(content) > MAX_BATCH and current_batch:\n",
  )
  buf.write_string("            batches.append(current_batch)\n")
  buf.write_string("            current_batch = []\n")
  buf.write_string("            current_size = 0\n")
  buf.write_string("        current_batch.append((path, content))\n")
  buf.write_string("        current_size += len(content)\n")
  buf.write_string("    if current_batch:\n")
  buf.write_string("        batches.append(current_batch)\n\n")
  buf.write_string(
    "    print(f'Phase 2: Deep audit of {len(SOURCE_FILES)} files in {len(batches)} batch(es)...')\n",
  )
  buf.write_string("    all_findings = []\n")
  buf.write_string("    for i, batch in enumerate(batches):\n")
  buf.write_string("        files_str = ', '.join(p for p, _ in batch)\n")
  buf.write_string(
    "        print(f'  Batch {i+1}/{len(batches)}: {files_str[:80]}...')\n",
  )
  // Build per-batch prompt with static findings context for dedup
  buf.write_string("        prompt = ''\n")
  buf.write_string("        if STATIC_CONTEXT:\n")
  buf.write_string("            prompt += STATIC_CONTEXT + '\\n\\n'\n")
  buf.write_string(
    "        prompt += 'Review the following MoonBit source files for exploitable security vulnerabilities:\\n\\n'\n",
  )
  buf.write_string("        for path, content in batch:\n")
  buf.write_string(
    "            prompt += f'## {path}\\n```moonbit\\n{content}\\n```\\n\\n'\n",
  )
  buf.write_string("        resp = call_llm(DEEP_AUDIT_SYSTEM, prompt)\n")
  buf.write_string("        if resp:\n")
  buf.write_string("            try:\n")
  buf.write_string("                start_j = resp.index('[')\n")
  buf.write_string("                end_j = resp.rindex(']') + 1\n")
  buf.write_string(
    "                findings = json.loads(resp[start_j:end_j])\n",
  )
  buf.write_string("                # Filter out low-severity findings\n")
  buf.write_string(
    "                findings = [f for f in findings if f.get('severity', '').lower() in ('high', 'critical')]\n",
  )
  buf.write_string(
    "                print(f'    Found {len(findings)} high/critical issue(s)')\n",
  )
  buf.write_string("                all_findings.extend(findings)\n")
  buf.write_string("            except (ValueError, json.JSONDecodeError):\n")
  buf.write_string(
    "                print('    Failed to parse LLM response')\n",
  )
  buf.write_string("        time.sleep(2)\n")
  buf.write_string("    return all_findings\n\n")
  buf.write_string("def main():\n")
  buf.write_string("    print('=' * 60)\n")
  buf.write_string("    print('moon-audit Deep Security Audit')\n")
  buf.write_string("    print(f'API: {BASE_URL}')\n")
  buf.write_string("    print(f'Model: {MODEL}')\n")
  buf.write_string("    print(f'Static findings: {len(STATIC_FINDINGS)}')\n")
  buf.write_string("    print(f'Source files: {len(SOURCE_FILES)}')\n")
  buf.write_string("    print('=' * 60)\n")
  buf.write_string("    print()\n\n")
  buf.write_string("    # Phase 1: Verify static findings\n")
  buf.write_string("    verified = verify_findings()\n")
  buf.write_string(
    "    exploitable = [v for v in verified if 'exploitable' in v.get('verdict', '')]\n",
  )
  buf.write_string(
    "    tp = [v for v in verified if v.get('is_true_positive') is True]\n",
  )
  buf.write_string(
    "    fp = [v for v in verified if v.get('verdict') == 'false positive']\n",
  )
  buf.write_string("    print()\n\n")
  buf.write_string("    # Phase 2: Deep audit\n")
  buf.write_string("    deep_findings = deep_audit_files()\n")
  buf.write_string("    print()\n\n")
  buf.write_string("    # Summary\n")
  buf.write_string("    print('=' * 60)\n")
  buf.write_string("    print('AUDIT SUMMARY')\n")
  buf.write_string("    print('=' * 60)\n")
  buf.write_string(
    "    print(f'Static analysis: {len(STATIC_FINDINGS)} findings')\n",
  )
  buf.write_string("    print(f'  Exploitable:     {len(exploitable)}')\n")
  buf.write_string("    print(f'  True positives:  {len(tp)}')\n")
  buf.write_string("    print(f'  False positives: {len(fp)}')\n")
  buf.write_string(
    "    print(f'  Unverified:      {len(verified) - len(tp) - len(fp)}')\n",
  )
  buf.write_string(
    "    print(f'Deep audit:        {len(deep_findings)} new high/critical finding(s)')\n",
  )
  buf.write_string("    print()\n\n")
  buf.write_string("    if exploitable:\n")
  buf.write_string("        print('EXPLOITABLE Findings (action required):')\n")
  buf.write_string("        for v in exploitable:\n")
  buf.write_string(
    "            print(f\"  [{v['sev'].upper()}] {v['rule']} @ {v['file']}:{v['line']}\")\n",
  )
  buf.write_string("            print(f\"    {v['msg']}\")\n")
  buf.write_string("            if v.get('explanation'):\n")
  buf.write_string(
    "                print(f\"    Analysis: {v['explanation'][:200]}\")\n",
  )
  buf.write_string("            if v.get('remediation'):\n")
  buf.write_string(
    "                print(f\"    Fix: {v['remediation'][:120]}\")\n",
  )
  buf.write_string("            print()\n\n")
  buf.write_string("    if deep_findings:\n")
  buf.write_string("        print('NEW Findings from Deep Audit:')\n")
  buf.write_string("        for d in deep_findings:\n")
  buf.write_string("            sev = d.get('severity', 'high').upper()\n")
  buf.write_string(
    "            print(f\"  [{sev}] {d.get('category', 'unknown')} @ {d.get('file', '?')}:{d.get('line', '?')}\")\n",
  )
  buf.write_string("            print(f\"    {d.get('title', '')}\")\n")
  buf.write_string("            if d.get('attack_scenario'):\n")
  buf.write_string(
    "                print(f\"    Attack: {d['attack_scenario'][:200]}\")\n",
  )
  buf.write_string("            if d.get('remediation'):\n")
  buf.write_string(
    "                print(f\"    Fix: {d['remediation'][:120]}\")\n",
  )
  buf.write_string("            print()\n\n")
  buf.write_string("    if not exploitable and not deep_findings:\n")
  buf.write_string("        print('No exploitable vulnerabilities found.')\n")
  buf.write_string(
    "        print('All static findings were either false positives or not easily exploitable.')\n",
  )
  buf.write_string("        print()\n\n")
  buf.write_string("    # Save results\n")
  buf.write_string("    report = {\n")
  buf.write_string("        'static_verified': verified,\n")
  buf.write_string("        'deep_findings': deep_findings,\n")
  buf.write_string("        'summary': {\n")
  buf.write_string("            'total_static': len(STATIC_FINDINGS),\n")
  buf.write_string("            'exploitable': len(exploitable),\n")
  buf.write_string("            'true_positives': len(tp),\n")
  buf.write_string("            'false_positives': len(fp),\n")
  buf.write_string("            'deep_new': len(deep_findings),\n")
  buf.write_string("        },\n")
  buf.write_string("    }\n")
  buf.write_string("    out = 'deep_audit_report.json'\n")
  buf.write_string("    with open(out, 'w') as f:\n")
  buf.write_string(
    "        json.dump(report, f, indent=2, ensure_ascii=False)\n",
  )
  buf.write_string("    print(f'Full report saved to: {out}')\n\n")
  buf.write_string("if __name__ == '__main__':\n")
  buf.write_string("    main()\n")
}
