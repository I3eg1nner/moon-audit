///|
pub fn format_text(result : ScanResult, verbose : Bool) -> String {
  let buf = StringBuilder::new()
  for f in result.findings {
    buf.write_string(f.file)
    buf.write_char(':')
    buf.write_string(f.line.to_string())
    buf.write_char(':')
    buf.write_string(f.column.to_string())
    buf.write_string(": ")
    buf.write_string(severity_str(f.severity))
    buf.write_char('[')
    buf.write_string(rule_id_str(f.rule_id))
    buf.write_string("] ")
    buf.write_string(f.message)
    buf.write_char('\n')
    if f.snippet.length() > 0 {
      buf.write_string("  |\n")
      buf.write_string("  ")
      buf.write_string(f.line.to_string())
      buf.write_string(" | ")
      buf.write_string(f.snippet)
      buf.write_string("\n  |\n")
    }
  }
  if !verbose && result.findings.length() == 0 {
    buf.write_string("No issues found.\n")
  }
  if verbose || result.findings.length() > 0 {
    buf.write_char('\n')
    buf.write_string(result.files_scanned.to_string())
    buf.write_string(" files scanned, ")
    buf.write_string(result.findings.length().to_string())
    buf.write_string(" issues found")
    if result.errors.length() > 0 {
      buf.write_string(", ")
      buf.write_string(result.errors.length().to_string())
      buf.write_string(" errors")
    }
    buf.write_char('\n')
  }
  buf.to_string()
}

///|
pub fn format_json(result : ScanResult) -> String {
  let findings_json : Array[Json] = []
  for f in result.findings {
    findings_json.push(finding_to_json(f))
  }
  let obj : Json = {
    "findings": Json::array(findings_json),
    "files_scanned": Json::number(result.files_scanned.to_double()),
    "errors": Json::array(result.errors.map(fn(e) { Json::string(e) })),
  }
  obj.stringify(indent=2)
}

///|
fn finding_to_json(f : Finding) -> Json {
  {
    "rule_id": Json::string(rule_id_str(f.rule_id)),
    "severity": Json::string(severity_str(f.severity)),
    "message": Json::string(f.message),
    "file": Json::string(f.file),
    "line": Json::number(f.line.to_double()),
    "column": Json::number(f.column.to_double()),
    "end_line": Json::number(f.end_line.to_double()),
    "end_column": Json::number(f.end_column.to_double()),
    "snippet": Json::string(f.snippet),
  }
}
