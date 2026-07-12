// LLM-assisted vulnerability analysis prompt generation.
// Generates structured prompts from static analysis findings
// for LLM-based deep analysis and false positive reduction.

///|
pub(all) struct LLMAnalysisRequest {
  finding : Finding
  source_context : String
  import_context : ImportContext
  prompt : String
  system_prompt : String
}

///|
pub(all) struct LLMAnalysisResult {
  finding : Finding
  is_true_positive : Bool
  confidence : Double
  explanation : String
  severity_adjustment : Severity?
  remediation : String
}

///|
pub fn generate_analysis_prompt(
  finding : Finding,
  source : String,
  imports : ImportContext,
) -> LLMAnalysisRequest {
  let context = extract_source_context(source, finding.line, 10)
  let system = build_system_prompt()
  let prompt = build_analysis_prompt(finding, context, imports)
  {
    finding,
    source_context: context,
    import_context: imports,
    prompt,
    system_prompt: system,
  }
}

///|
pub fn generate_batch_prompts(
  findings : Array[Finding],
  sources : Map[String, String],
  imports : ImportContext,
) -> Array[LLMAnalysisRequest] {
  let requests : Array[LLMAnalysisRequest] = []
  for f in findings {
    let source = match sources.get(f.file) {
      Some(s) => s
      None => ""
    }
    requests.push(generate_analysis_prompt(f, source, imports))
  }
  requests
}

///|
fn build_system_prompt() -> String {
  let buf = StringBuilder::new()
  buf.write_string(
    "You are a security expert specialized in MoonBit web application security.\n",
  )
  buf.write_string(
    "Your task is to analyze potential vulnerabilities found by static analysis.\n\n",
  )
  buf.write_string("For each finding, determine:\n")
  buf.write_string(
    "1. Whether it is a true positive (real vulnerability) or false positive\n",
  )
  buf.write_string("2. Your confidence level (0.0 to 1.0)\n")
  buf.write_string("3. Detailed explanation of your reasoning\n")
  buf.write_string("4. Whether the severity should be adjusted\n")
  buf.write_string("5. Specific remediation advice\n\n")
  buf.write_string("Consider the following MoonBit-specific characteristics:\n")
  buf.write_string(
    "- MoonBit is statically typed with compile-time safety guarantees\n",
  )
  buf.write_string(
    "- String::replace() only replaces the FIRST occurrence (unlike most languages)\n",
  )
  buf.write_string("- MoonBit compiles to Wasm, JS, C, or native targets\n")
  buf.write_string(
    "- Web frameworks (mocket, crescent) use route parameters via :param syntax\n",
  )
  buf.write_string(
    "- The cmark library defaults to safe=false for HTML rendering\n\n",
  )
  buf.write_string(
    "Respond in JSON format with fields: is_true_positive, confidence, explanation, severity_adjustment, remediation\n",
  )
  buf.to_string()
}

///|
fn build_analysis_prompt(
  finding : Finding,
  context : String,
  imports : ImportContext,
) -> String {
  let buf = StringBuilder::new()
  buf.write_string("## Static Analysis Finding\n\n")
  buf.write_string("**Rule**: ")
  buf.write_string(rule_id_str(finding.rule_id))
  buf.write_char('\n')
  buf.write_string("**Severity**: ")
  buf.write_string(severity_str(finding.severity))
  buf.write_char('\n')
  buf.write_string("**File**: ")
  buf.write_string(finding.file)
  buf.write_char(':')
  buf.write_string(finding.line.to_string())
  buf.write_char('\n')
  buf.write_string("**Message**: ")
  buf.write_string(finding.message)
  buf.write_string("\n\n")
  buf.write_string("### Source Context\n\n```moonbit\n")
  buf.write_string(context)
  buf.write_string("\n```\n\n")
  buf.write_string("### Import Context\n\n")
  write_import_context(buf, imports)
  buf.write_string("\n### Question\n\n")
  buf.write_string(
    "Is this finding a true positive? Analyze the code context, ",
  )
  buf.write_string(
    "data flow, and whether user-controlled input can reach this sink. ",
  )
  buf.write_string(
    "Consider framework-specific behavior and MoonBit language semantics.\n",
  )
  buf.to_string()
}

///|
fn write_import_context(buf : StringBuilder, imports : ImportContext) -> Unit {
  buf.write_string("- cmark: ")
  buf.write_string(imports.has_cmark.to_string())
  buf.write_char('\n')
  buf.write_string("- rabbita: ")
  buf.write_string(imports.has_rabbita.to_string())
  buf.write_char('\n')
  buf.write_string("- mocket: ")
  buf.write_string(imports.has_mocket.to_string())
  buf.write_char('\n')
  buf.write_string("- crescent: ")
  buf.write_string(imports.has_crescent.to_string())
  buf.write_char('\n')
}

///|
fn extract_source_context(
  source : String,
  center_line : Int,
  radius : Int,
) -> String {
  let lines : Array[String] = []
  for part in source.split("\n") {
    lines.push(part.to_owned())
  }
  let start = if center_line - radius - 1 > 0 {
    center_line - radius - 1
  } else {
    0
  }
  let end = if center_line + radius < lines.length() {
    center_line + radius
  } else {
    lines.length()
  }
  let buf = StringBuilder::new()
  for i = start; i < end; i = i + 1 {
    let line_num = i + 1
    let marker = if line_num == center_line { ">>> " } else { "    " }
    buf.write_string(marker)
    buf.write_string(line_num.to_string())
    buf.write_string(" | ")
    buf.write_string(lines[i])
    buf.write_char('\n')
  }
  buf.to_string()
}

///|
pub fn format_prompt_as_json(
  req : LLMAnalysisRequest,
  model? : String,
) -> String {
  let model_name = model.unwrap_or("claude-sonnet-4-20250514")
  let obj : Json = {
    "model": Json::string(model_name),
    "system": Json::string(req.system_prompt),
    "messages": Json::array([
      { "role": Json::string("user"), "content": Json::string(req.prompt) },
    ]),
  }
  obj.stringify(indent=2)
}

///|
pub fn parse_llm_response(
  finding : Finding,
  response_json : String,
) -> LLMAnalysisResult? {
  let json = @json.parse(response_json) catch { _ => return None }
  match json {
    Object(obj) => {
      let is_tp = match obj.get("is_true_positive") {
        Some(True) => true
        _ => false
      }
      let confidence = match obj.get("confidence") {
        Some(Number(n, ..)) => n
        _ => 0.5
      }
      let explanation = match obj.get("explanation") {
        Some(String(s)) => s
        _ => ""
      }
      let sev_adj : Severity? = match obj.get("severity_adjustment") {
        Some(String(s)) => Some(severity_from_str(s))
        _ => None
      }
      let remediation = match obj.get("remediation") {
        Some(String(s)) => s
        _ => ""
      }
      Some({
        finding,
        is_true_positive: is_tp,
        confidence,
        explanation,
        severity_adjustment: sev_adj,
        remediation,
      })
    }
    _ => None
  }
}

///|
pub fn filter_by_llm_results(
  results : Array[LLMAnalysisResult],
  min_confidence : Double,
) -> Array[LLMAnalysisResult] {
  results.filter(fn(r) { r.is_true_positive && r.confidence >= min_confidence })
}

///|
pub fn format_llm_report(results : Array[LLMAnalysisResult]) -> String {
  let buf = StringBuilder::new()
  buf.write_string("# LLM-Assisted Vulnerability Analysis Report\n\n")
  let tp_count = results.iter().filter(fn(r) { r.is_true_positive }).count()
  let fp_count = results.length() - tp_count
  buf.write_string("**Total findings analyzed**: ")
  buf.write_string(results.length().to_string())
  buf.write_char('\n')
  buf.write_string("**True positives**: ")
  buf.write_string(tp_count.to_string())
  buf.write_char('\n')
  buf.write_string("**False positives**: ")
  buf.write_string(fp_count.to_string())
  buf.write_string("\n\n")
  for i, r in results {
    buf.write_string("## Finding ")
    buf.write_string((i + 1).to_string())
    buf.write_string(": ")
    buf.write_string(rule_id_str(r.finding.rule_id))
    buf.write_char('\n')
    buf.write_string("- **File**: ")
    buf.write_string(r.finding.file)
    buf.write_char(':')
    buf.write_string(r.finding.line.to_string())
    buf.write_char('\n')
    buf.write_string("- **Verdict**: ")
    buf.write_string(
      if r.is_true_positive {
        "TRUE POSITIVE"
      } else {
        "FALSE POSITIVE"
      },
    )
    buf.write_char('\n')
    buf.write_string("- **Confidence**: ")
    buf.write_string(r.confidence.to_string())
    buf.write_char('\n')
    buf.write_string("- **Explanation**: ")
    buf.write_string(r.explanation)
    buf.write_char('\n')
    if r.remediation.length() > 0 {
      buf.write_string("- **Remediation**: ")
      buf.write_string(r.remediation)
      buf.write_char('\n')
    }
    buf.write_char('\n')
  }
  buf.to_string()
}
