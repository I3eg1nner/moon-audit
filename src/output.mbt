///|
pub fn format_text(result : ScanResult, verbose : Bool) -> String {
  let buf = StringBuilder()
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
    buf.write_string("] (")
    buf.write_string(confidence_str(f.confidence))
    buf.write_string(") ")
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
  buf.write_string(
    "\n" +
    result.files_selected.to_string() +
    " files selected, " +
    result.files_parsed.to_string() +
    " parsed, " +
    (result.files_selected - result.files_parsed).to_string() +
    " not parsed; " +
    result.findings.length().to_string() +
    " findings.\n",
  )
  if result.files_selected == 0 {
    buf.write_string(
      "No source files selected; no project safety conclusion.\n",
    )
  }
  match result.project_verification {
    Some(value) => {
      match value {
        { "status": String(status), "target": String(target), .. } =>
          buf.write_string(
            "project-verification: " + status + "; target=" + target + "\n",
          )
        _ => ()
      }
      if verbose {
        buf.write_string(value.stringify(indent=2) + "\n")
      }
    }
    None =>
      buf.write_string(
        "Project toolchain and backend selection were not verified.\n",
      )
  }
  if result.semantic_analysis is Some(report) {
    buf.write_string(
      "Semantic scope: mocket GET callback returns; registration and middleware assumptions apply.\n",
    )
    if report is { "status": String(status), .. } {
      buf.write_string("semantic-status: " + status + "\n")
    }
    if verbose {
      buf.write_string(report.stringify(indent=2) + "\n")
    }
  }
  for error in result.errors {
    buf.write_string("error: " + error + "\n")
  }
  // T0.4: scope disclosure is always printed (verbose or not) — what was
  // NOT analyzed is as important as what was
  if result.analysis_scope.length() > 0 {
    buf.write_string("analysis-scope: ")
    buf.write_string(result.analysis_scope)
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
    "project_verification": result.project_verification.unwrap_or(Json::null()),
    "semantic_analysis": result.semantic_analysis.unwrap_or(Json::null()),
    "files_scanned": Json::number(result.files_scanned.to_double()),
    "files_selected": Json::number(result.files_selected.to_double()),
    "files_parsed": Json::number(result.files_parsed.to_double()),
    "errors": Json::array(result.errors.map(fn(e) { Json::string(e) })),
    "analysis_scope": Json::string(result.analysis_scope),
    "analysis_manifest": analysis_manifest_json(result),
  }
  obj.stringify(indent=2)
}

///|
fn finding_to_json(f : Finding) -> Json {
  {
    "rule_id": Json::string(rule_id_str(f.rule_id)),
    "severity": Json::string(severity_str(f.severity)),
    "confidence": Json::string(confidence_str(f.confidence)),
    "message": Json::string(f.message),
    "file": Json::string(f.file),
    "line": Json::number(f.line.to_double()),
    "column": Json::number(f.column.to_double()),
    "end_line": Json::number(f.end_line.to_double()),
    "end_column": Json::number(f.end_column.to_double()),
    "snippet": Json::string(f.snippet),
    "fingerprint": Json::string(f.fingerprint),
    "evidence": Json::string(f.evidence),
    "dataflow": f.dataflow.to_json(),
  }
}

///|
fn analysis_manifest_json(result : ScanResult) -> Json {
  let files : Array[Json] = []
  for file in result.file_coverage {
    let rules : Array[Json] = []
    for rule in file.rules {
      rules.push({
        "id": Json::string(rule.id),
        "status": Json::string(rule.status),
        "reason": Json::string(rule.reason),
      })
    }
    files.push({
      "path": Json::string(file.path),
      "status": Json::string(file.status),
      "reason": Json::string(file.reason),
      "rules": Json::array(rules),
    })
  }
  let verified = match result.project_verification {
    Some({ "status": String("compiler_verified"), .. }) => true
    _ => false
  }
  let incomplete : Array[Json] = if verified {
    []
  } else {
    [
      Json::string("target_toolchain_not_verified"),
      Json::string("backend_file_selection_not_verified"),
    ]
  }
  if result.file_coverage.any(fn(file) { file.status == "unsupported" }) {
    incomplete.push(Json::string("unsupported_source_inputs"))
  }
  if !result.errors.is_empty() {
    incomplete.push(Json::string("scan_errors"))
  }
  {
    "schema": Json::string("moon-audit.analysis-manifest.v1"),
    "verification": Json::string(
      if verified {
        "compiler_verified_syntax"
      } else {
        "syntax_only"
      },
    ),
    "selection": {
      "enumerated_scope": Json::string(
        "eligible_mbt_mbt_md_mbtx_files_after_directory_exclusions",
      ),
      "supported_formats": [".mbt"],
      "unsupported_formats": [".mbt.md", ".mbtx"],
      "implicit_excludes": Json::array([
        Json::string("dot_directories_and_files"),
        Json::string("_build"),
        Json::string("*_test.mbt"),
        Json::string("*_wbtest.mbt"),
      ]),
      "configured_excludes": Json::array(
        result.configured_excludes.map(fn(e) { Json::string(e) }),
      ),
      "incremental": Json::boolean(result.incremental),
    },
    "files": Json::array(files),
    "rule_capabilities": rule_capabilities(),
    "incomplete_reasons": Json::array(incomplete),
  }
}
