// .env file parser for LLM API configuration.

///|
pub(all) struct LLMConfig {
  base_url : String
  model : String
  api_key : String
}

///|
pub fn LLMConfig::default() -> LLMConfig {
  {
    base_url: "https://api.anthropic.com/v1/messages",
    model: "claude-sonnet-4-20250514",
    api_key: "",
  }
}

///|
pub fn load_env(dir : String) -> Map[String, String] {
  let env : Map[String, String] = {}
  let env_path = @path.Path(dir).join(@path.Path(".env")).0
  let content = @fs.read_file_to_string(env_path) catch { _ => return env }
  parse_env_content(content, env)
  env
}

///|
fn parse_env_content(content : String, env : Map[String, String]) -> Unit {
  let lines : Array[String] = []
  for part in content.split("\n") {
    lines.push(part.to_owned())
  }
  for line in lines {
    let trimmed = line.trim().to_owned()
    if trimmed.length() == 0 || trimmed.has_prefix("#") {
      continue
    }
    let eq_pos = find_char_in_str(trimmed, '=')
    if eq_pos < 0 {
      continue
    }
    let key = trimmed[0:eq_pos].to_owned().trim().to_owned()
    let raw_val = trimmed[eq_pos + 1:].to_owned().trim().to_owned()
    let val = strip_quotes(raw_val)
    env[key] = val
  }
}

///|
fn char16(c : Char) -> UInt16 {
  c.to_uint().to_uint16()
}

///|
fn find_char_in_str(s : String, c : Char) -> Int {
  let target = char16(c)
  for i = 0; i < s.length(); i = i + 1 {
    if s[i] == target {
      return i
    }
  }
  -1
}

///|
fn strip_quotes(s : String) -> String {
  if s.length() >= 2 {
    let dq = char16('"')
    let sq = char16('\'')
    let first = s[0]
    let last = s[s.length() - 1]
    if (first == dq && last == dq) || (first == sq && last == sq) {
      return s[1:s.length() - 1].to_owned()
    }
  }
  s
}

///|
pub fn load_llm_config(dir : String) -> LLMConfig {
  let env = load_env(".")
  if env.length() == 0 {
    let env2 = load_env(dir)
    return build_llm_config(env2)
  }
  build_llm_config(env)
}

///|
fn build_llm_config(env : Map[String, String]) -> LLMConfig {
  let base = LLMConfig::default()
  let base_url = match env.get("LLM_BASE_URL") {
    Some(v) => if v.length() > 0 { v } else { base.base_url }
    None => base.base_url
  }
  let model = match env.get("LLM_MODEL") {
    Some(v) => if v.length() > 0 { v } else { base.model }
    None => base.model
  }
  let api_key = match env.get("LLM_API_KEY") {
    Some(v) => v
    None =>
      match env.get("ANTHROPIC_API_KEY") {
        Some(v) => v
        None => base.api_key
      }
  }
  { base_url, model, api_key }
}

///|
pub fn load_env_merged(dir : String) -> Map[String, String] {
  let env = load_env(".")
  let env2 = load_env(dir)
  for k, v in env2 {
    if !env.contains(k) {
      env[k] = v
    }
  }
  env
}

///|
pub fn generate_llm_script(
  llm_config : LLMConfig,
  requests : Array[LLMAnalysisRequest],
) -> String {
  let buf = StringBuilder::new()
  buf.write_string("#!/usr/bin/env python3\n")
  buf.write_string("\"\"\"moon-audit LLM Analysis Runner\n")
  buf.write_string(
    "Auto-generated script. Calls LLM API to verify static analysis findings.\n",
  )
  buf.write_string("Usage: python3 llm_analyze.py\n")
  buf.write_string("\"\"\"\n\n")
  buf.write_string("import json, sys, time\n\n")
  buf.write_string("try:\n")
  buf.write_string("    import httpx\n")
  buf.write_string("    CLIENT = httpx.Client(timeout=60)\n")
  buf.write_string("    def post(url, headers, body):\n")
  buf.write_string("        r = CLIENT.post(url, headers=headers, json=body)\n")
  buf.write_string("        return r.status_code, r.json()\n")
  buf.write_string("except ImportError:\n")
  buf.write_string("    from urllib.request import Request, urlopen\n")
  buf.write_string("    def post(url, headers, body):\n")
  buf.write_string(
    "        req = Request(url, data=json.dumps(body).encode(), headers=headers, method='POST')\n",
  )
  buf.write_string("        resp = urlopen(req)\n")
  buf.write_string("        return resp.status, json.loads(resp.read())\n\n")
  buf.write_string("# ── Configuration (from .env) ──\n")
  buf.write_string("BASE_URL = \"")
  buf.write_string(escape_py_str(llm_config.base_url))
  buf.write_string("\"\n")
  buf.write_string("MODEL    = \"")
  buf.write_string(escape_py_str(llm_config.model))
  buf.write_string("\"\n")
  buf.write_string("API_KEY  = \"")
  buf.write_string(escape_py_str(llm_config.api_key))
  buf.write_string("\"\n\n")
  buf.write_string("if not API_KEY:\n")
  buf.write_string("    print(\"ERROR: No API key configured.\")\n")
  buf.write_string(
    "    print(\"Set LLM_API_KEY or ANTHROPIC_API_KEY in .env file:\")\n",
  )
  buf.write_string("    print(\"  LLM_API_KEY=sk-...\")\n")
  buf.write_string(
    "    print(\"  LLM_BASE_URL=https://api.anthropic.com/v1/messages  # optional\")\n",
  )
  buf.write_string(
    "    print(\"  LLM_MODEL=claude-sonnet-4-20250514                   # optional\")\n",
  )
  buf.write_string("    sys.exit(1)\n\n")
  write_py_is_anthropic(buf)
  write_py_call_function(buf)
  write_py_findings(buf, requests)
  write_py_main(buf)
  buf.to_string()
}

///|
fn write_py_is_anthropic(buf : StringBuilder) -> Unit {
  buf.write_string("IS_ANTHROPIC = \"anthropic\" in BASE_URL\n\n")
  buf.write_string("# Auto-append endpoint path if BASE_URL is just the base\n")
  buf.write_string(
    "if not IS_ANTHROPIC and not BASE_URL.endswith(\"/chat/completions\"):\n",
  )
  buf.write_string(
    "    BASE_URL = BASE_URL.rstrip(\"/\") + \"/chat/completions\"\n\n",
  )
}

///|
fn write_py_call_function(buf : StringBuilder) -> Unit {
  buf.write_string("def call_llm(system_prompt, user_prompt):\n")
  buf.write_string("    if IS_ANTHROPIC:\n")
  buf.write_string("        headers = {\n")
  buf.write_string("            \"x-api-key\": API_KEY,\n")
  buf.write_string("            \"content-type\": \"application/json\",\n")
  buf.write_string("            \"anthropic-version\": \"2023-06-01\",\n")
  buf.write_string("        }\n")
  buf.write_string("        body = {\n")
  buf.write_string("            \"model\": MODEL,\n")
  buf.write_string("            \"max_tokens\": 2048,\n")
  buf.write_string("            \"system\": system_prompt,\n")
  buf.write_string(
    "            \"messages\": [{\"role\": \"user\", \"content\": user_prompt}],\n",
  )
  buf.write_string("        }\n")
  buf.write_string("    else:\n")
  buf.write_string("        # OpenAI-compatible API\n")
  buf.write_string("        headers = {\n")
  buf.write_string("            \"Authorization\": f\"Bearer {API_KEY}\",\n")
  buf.write_string("            \"Content-Type\": \"application/json\",\n")
  buf.write_string("        }\n")
  buf.write_string("        body = {\n")
  buf.write_string("            \"model\": MODEL,\n")
  buf.write_string("            \"max_tokens\": 2048,\n")
  buf.write_string("            \"messages\": [\n")
  buf.write_string(
    "                {\"role\": \"system\", \"content\": system_prompt},\n",
  )
  buf.write_string(
    "                {\"role\": \"user\", \"content\": user_prompt},\n",
  )
  buf.write_string("            ],\n")
  buf.write_string("        }\n")
  buf.write_string("    status, resp = post(BASE_URL, headers, body)\n")
  buf.write_string("    if status != 200:\n")
  buf.write_string("        print(f\"  API error: {status} - {resp}\")\n")
  buf.write_string("        return None\n")
  buf.write_string("    if IS_ANTHROPIC:\n")
  buf.write_string("        text = resp[\"content\"][0][\"text\"]\n")
  buf.write_string("    else:\n")
  buf.write_string(
    "        text = resp[\"choices\"][0][\"message\"][\"content\"]\n",
  )
  buf.write_string("    # Extract JSON from response\n")
  buf.write_string("    try:\n")
  buf.write_string("        start = text.index(\"{\")\n")
  buf.write_string("        end = text.rindex(\"}\") + 1\n")
  buf.write_string("        return json.loads(text[start:end])\n")
  buf.write_string("    except (ValueError, json.JSONDecodeError):\n")
  buf.write_string(
    "        print(f\"  Failed to parse LLM response as JSON\")\n",
  )
  buf.write_string("        return None\n\n")
}

///|
fn write_py_findings(
  buf : StringBuilder,
  requests : Array[LLMAnalysisRequest],
) -> Unit {
  buf.write_string("FINDINGS = [\n")
  for req in requests {
    buf.write_string("    {\n")
    buf.write_string("        \"rule_id\": \"")
    buf.write_string(escape_py_str(rule_id_str(req.finding.rule_id)))
    buf.write_string("\",\n")
    buf.write_string("        \"file\": \"")
    buf.write_string(escape_py_str(req.finding.file))
    buf.write_string("\",\n")
    buf.write_string("        \"line\": ")
    buf.write_string(req.finding.line.to_string())
    buf.write_string(",\n")
    buf.write_string("        \"message\": \"")
    buf.write_string(escape_py_str(req.finding.message))
    buf.write_string("\",\n")
    buf.write_string("        \"severity\": \"")
    buf.write_string(escape_py_str(severity_str(req.finding.severity)))
    buf.write_string("\",\n")
    buf.write_string("        \"system_prompt\": ")
    write_py_triple_quoted(buf, req.system_prompt)
    buf.write_string(",\n")
    buf.write_string("        \"user_prompt\": ")
    write_py_triple_quoted(buf, req.prompt)
    buf.write_string(",\n")
    buf.write_string("    },\n")
  }
  buf.write_string("]\n\n")
}

///|
fn write_py_main(buf : StringBuilder) -> Unit {
  buf.write_string("def main():\n")
  buf.write_string("    print(f\"moon-audit LLM Analysis\")\n")
  buf.write_string("    print(f\"API: {BASE_URL}\")\n")
  buf.write_string("    print(f\"Model: {MODEL}\")\n")
  buf.write_string("    print(f\"Findings to analyze: {len(FINDINGS)}\")\n")
  buf.write_string("    print(\"=\" * 60)\n")
  buf.write_string("    print()\n\n")
  buf.write_string("    results = []\n")
  buf.write_string("    for i, f in enumerate(FINDINGS):\n")
  buf.write_string(
    "        label = f\"{f['rule_id']} @ {f['file']}:{f['line']}\"\n",
  )
  buf.write_string(
    "        print(f\"[{i+1}/{len(FINDINGS)}] Analyzing: {label}\")\n",
  )
  buf.write_string(
    "        result = call_llm(f[\"system_prompt\"], f[\"user_prompt\"])\n",
  )
  buf.write_string("        if result:\n")
  buf.write_string("            tp = result.get(\"is_true_positive\", False)\n")
  buf.write_string("            conf = result.get(\"confidence\", 0)\n")
  buf.write_string(
    "            verdict = \"TRUE POSITIVE\" if tp else \"FALSE POSITIVE\"\n",
  )
  buf.write_string(
    "            print(f\"  => {verdict} (confidence: {conf})\")\n",
  )
  buf.write_string(
    "            print(f\"  => {result.get('explanation', '')[:120]}\")\n",
  )
  buf.write_string("            results.append({**f, **result})\n")
  buf.write_string("        else:\n")
  buf.write_string("            print(f\"  => SKIPPED (API error)\")\n")
  buf.write_string(
    "            results.append({**f, \"is_true_positive\": None, \"confidence\": 0})\n",
  )
  buf.write_string("        if i < len(FINDINGS) - 1:\n")
  buf.write_string("            time.sleep(1)\n")
  buf.write_string("        print()\n\n")
  buf.write_string("    # Summary\n")
  buf.write_string(
    "    tp = [r for r in results if r.get(\"is_true_positive\") is True]\n",
  )
  buf.write_string(
    "    fp = [r for r in results if r.get(\"is_true_positive\") is False]\n",
  )
  buf.write_string(
    "    skipped = [r for r in results if r.get(\"is_true_positive\") is None]\n",
  )
  buf.write_string("    print(\"=\" * 60)\n")
  buf.write_string("    print(f\"Analysis Complete\")\n")
  buf.write_string("    print(f\"  Total:           {len(results)}\")\n")
  buf.write_string("    print(f\"  True Positives:  {len(tp)}\")\n")
  buf.write_string("    print(f\"  False Positives: {len(fp)}\")\n")
  buf.write_string("    print(f\"  Skipped:         {len(skipped)}\")\n")
  buf.write_string("    print()\n\n")
  buf.write_string("    if tp:\n")
  buf.write_string("        print(\"Confirmed Vulnerabilities:\")\n")
  buf.write_string("        for r in tp:\n")
  buf.write_string(
    "            print(f\"  [{r['severity'].upper()}] {r['rule_id']} @ {r['file']}:{r['line']}\")\n",
  )
  buf.write_string(
    "            print(f\"    {r.get('explanation', '')[:200]}\")\n",
  )
  buf.write_string("            if r.get('remediation'):\n")
  buf.write_string(
    "                print(f\"    Fix: {r['remediation'][:200]}\")\n",
  )
  buf.write_string("            print()\n\n")
  buf.write_string("    # Save JSON results\n")
  buf.write_string("    out_file = \"llm_analysis_results.json\"\n")
  buf.write_string("    with open(out_file, \"w\") as f:\n")
  buf.write_string(
    "        json.dump(results, f, indent=2, ensure_ascii=False)\n",
  )
  buf.write_string("    print(f\"Full results saved to: {out_file}\")\n\n")
  buf.write_string("if __name__ == \"__main__\":\n")
  buf.write_string("    main()\n")
}

///|
fn escape_py_str(s : String) -> String {
  let buf = StringBuilder::new()
  let backslash = char16('\\')
  let dquote = char16('"')
  let newline = char16('\n')
  let cr = char16('\r')
  for i = 0; i < s.length(); i = i + 1 {
    let c = s[i]
    if c == backslash {
      buf.write_string("\\\\")
    } else if c == dquote {
      buf.write_string("\\\"")
    } else if c == newline {
      buf.write_string("\\n")
    } else if c == cr {
      buf.write_string("\\r")
    } else {
      buf.write_string(c.to_int().unsafe_to_char().to_string())
    }
  }
  buf.to_string()
}

///|
fn write_py_triple_quoted(buf : StringBuilder, s : String) -> Unit {
  let backslash = char16('\\')
  let dquote = char16('"')
  buf.write_string("\"\"\"")
  for i = 0; i < s.length(); i = i + 1 {
    let c = s[i]
    if c == backslash {
      buf.write_string("\\\\")
    } else if c == dquote {
      let is_triple = i + 2 < s.length() &&
        s[i + 1] == dquote &&
        s[i + 2] == dquote
      if is_triple {
        buf.write_string("\\\"")
      } else {
        buf.write_char('"')
      }
    } else {
      buf.write_string(c.to_int().unsafe_to_char().to_string())
    }
  }
  buf.write_string("\"\"\"")
}
