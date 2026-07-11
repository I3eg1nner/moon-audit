// Scan result summary and statistics.
// Aggregates findings by severity, rule, file, and CWE category
// for dashboard-style reporting and trend tracking.

///|
pub(all) struct ScanSummary {
  total_findings : Int
  error_count : Int
  warning_count : Int
  info_count : Int
  files_scanned : Int
  files_with_findings : Int
  rules_triggered : Array[RuleStat]
  file_stats : Array[FileStat]
  cwe_categories : Array[CWEStat]
  owasp_mapping : Array[OwaspStat]
  scan_errors : Int
}

///|
pub(all) struct RuleStat {
  rule_id : String
  name : String
  count : Int
  severity : Severity
}

///|
pub(all) struct FileStat {
  file : String
  finding_count : Int
  error_count : Int
  warning_count : Int
}

///|
pub(all) struct CWEStat {
  cwe_id : Int
  name : String
  count : Int
}

///|
pub(all) struct OwaspStat {
  category : String
  count : Int
  cwe_ids : Array[Int]
}

///|
pub fn build_summary(
  result : ScanResult,
  rules : Array[RuleInfo],
) -> ScanSummary {
  let error_count = result.findings
    .iter()
    .filter(fn(f) { f.severity == Error })
    .count()
  let warning_count = result.findings
    .iter()
    .filter(fn(f) { f.severity == Warning })
    .count()
  let info_count = result.findings
    .iter()
    .filter(fn(f) { f.severity == Info })
    .count()
  let file_set : Map[String, Bool] = {}
  for f in result.findings {
    file_set[f.file] = true
  }
  let rule_stats = build_rule_stats(result.findings, rules)
  let file_stats = build_file_stats(result.findings)
  let cwe_stats = build_cwe_stats(result.findings)
  let owasp_stats = build_owasp_stats(result.findings)
  {
    total_findings: result.findings.length(),
    error_count,
    warning_count,
    info_count,
    files_scanned: result.files_scanned,
    files_with_findings: file_set.length(),
    rules_triggered: rule_stats,
    file_stats,
    cwe_categories: cwe_stats,
    owasp_mapping: owasp_stats,
    scan_errors: result.errors.length(),
  }
}

///|
fn build_rule_stats(
  findings : Array[Finding],
  rules : Array[RuleInfo],
) -> Array[RuleStat] {
  let counts : Map[String, Int] = {}
  for f in findings {
    let id = rule_id_str(f.rule_id)
    let cur = match counts.get(id) {
      Some(c) => c
      None => 0
    }
    counts[id] = cur + 1
  }
  let stats : Array[RuleStat] = []
  for rule in rules {
    let id = rule_id_str(rule.id)
    let count = match counts.get(id) {
      Some(c) => c
      None => 0
    }
    if count > 0 {
      stats.push({
        rule_id: id,
        name: rule.name,
        count,
        severity: rule.default_severity,
      })
    }
  }
  stats.sort_by(fn(a, b) { b.count - a.count })
  stats
}

///|
fn build_file_stats(findings : Array[Finding]) -> Array[FileStat] {
  let file_map : Map[String, FileStat] = {}
  for f in findings {
    match file_map.get(f.file) {
      Some(fs) => {
        let new_err = if f.severity == Error {
          fs.error_count + 1
        } else {
          fs.error_count
        }
        let new_warn = if f.severity == Warning {
          fs.warning_count + 1
        } else {
          fs.warning_count
        }
        file_map[f.file] = {
          file: f.file,
          finding_count: fs.finding_count + 1,
          error_count: new_err,
          warning_count: new_warn,
        }
      }
      None => {
        let err = if f.severity == Error { 1 } else { 0 }
        let warn = if f.severity == Warning { 1 } else { 0 }
        file_map[f.file] = {
          file: f.file,
          finding_count: 1,
          error_count: err,
          warning_count: warn,
        }
      }
    }
  }
  let result : Array[FileStat] = []
  file_map.each(fn(_k, v) { result.push(v) })
  result.sort_by(fn(a, b) { b.finding_count - a.finding_count })
  result
}

///|
fn build_cwe_stats(findings : Array[Finding]) -> Array[CWEStat] {
  let cwe_counts : Map[Int, Int] = {}
  for f in findings {
    let cur = match cwe_counts.get(f.rule_id.cwe) {
      Some(c) => c
      None => 0
    }
    cwe_counts[f.rule_id.cwe] = cur + 1
  }
  let stats : Array[CWEStat] = []
  cwe_counts.each(fn(cwe_id, count) {
    stats.push({ cwe_id, name: cwe_name(cwe_id), count })
  })
  stats.sort_by(fn(a, b) { b.count - a.count })
  stats
}

///|
fn cwe_name(cwe_id : Int) -> String {
  if cwe_id == 79 {
    "Cross-site Scripting (XSS)"
  } else if cwe_id == 89 {
    "SQL Injection"
  } else if cwe_id == 94 {
    "Code Injection"
  } else if cwe_id == 113 {
    "HTTP Response Splitting"
  } else if cwe_id == 116 {
    "Improper Encoding or Escaping"
  } else if cwe_id == 22 {
    "Path Traversal"
  } else if cwe_id == 346 {
    "Origin Validation Error"
  } else if cwe_id == 614 {
    "Sensitive Cookie Without Secure Flag"
  } else if cwe_id == 770 {
    "Allocation of Resources Without Limits"
  } else if cwe_id == 942 {
    "Permissive CORS Policy"
  } else if cwe_id == 78 {
    "OS Command Injection"
  } else if cwe_id == 601 {
    "Open Redirect"
  } else {
    "CWE-" + cwe_id.to_string()
  }
}

///|
fn cwe_to_owasp(cwe_id : Int) -> String {
  if cwe_id == 79 ||
    cwe_id == 89 ||
    cwe_id == 94 ||
    cwe_id == 116 ||
    cwe_id == 78 ||
    cwe_id == 113 {
    "A03:2021 - Injection"
  } else if cwe_id == 942 ||
    cwe_id == 614 ||
    cwe_id == 346 ||
    cwe_id == 22 ||
    cwe_id == 601 {
    "A01:2021 - Broken Access Control"
  } else if cwe_id == 770 {
    "A05:2021 - Security Misconfiguration"
  } else {
    "General"
  }
}

///|
fn build_owasp_stats(findings : Array[Finding]) -> Array[OwaspStat] {
  let owasp_map : Map[String, OwaspStat] = {}
  for f in findings {
    let cat = cwe_to_owasp(f.rule_id.cwe)
    match owasp_map.get(cat) {
      Some(os) => {
        let has_cwe = os.cwe_ids.contains(f.rule_id.cwe)
        if !has_cwe {
          os.cwe_ids.push(f.rule_id.cwe)
        }
        owasp_map[cat] = {
          category: cat,
          count: os.count + 1,
          cwe_ids: os.cwe_ids,
        }
      }
      None =>
        owasp_map[cat] = { category: cat, count: 1, cwe_ids: [f.rule_id.cwe] }
    }
  }
  let result : Array[OwaspStat] = []
  owasp_map.each(fn(_k, v) { result.push(v) })
  result.sort_by(fn(a, b) { b.count - a.count })
  result
}

///|
pub fn format_summary_text(summary : ScanSummary) -> String {
  let buf = StringBuilder::new()
  buf.write_string(
    "═══════════════════════════════════════════════\n",
  )
  buf.write_string("  moon-audit Scan Summary\n")
  buf.write_string(
    "═══════════════════════════════════════════════\n\n",
  )
  buf.write_string("  Files scanned:        ")
  buf.write_string(summary.files_scanned.to_string())
  buf.write_char('\n')
  buf.write_string("  Files with findings:  ")
  buf.write_string(summary.files_with_findings.to_string())
  buf.write_char('\n')
  buf.write_string("  Total findings:       ")
  buf.write_string(summary.total_findings.to_string())
  buf.write_char('\n')
  buf.write_string("    Errors:             ")
  buf.write_string(summary.error_count.to_string())
  buf.write_char('\n')
  buf.write_string("    Warnings:           ")
  buf.write_string(summary.warning_count.to_string())
  buf.write_char('\n')
  buf.write_string("    Info:               ")
  buf.write_string(summary.info_count.to_string())
  buf.write_char('\n')
  if summary.scan_errors > 0 {
    buf.write_string("  Scan errors:          ")
    buf.write_string(summary.scan_errors.to_string())
    buf.write_char('\n')
  }
  buf.write_string(
    "\n───────────────────────────────────────────────\n",
  )
  buf.write_string("  Rules Triggered\n")
  buf.write_string(
    "───────────────────────────────────────────────\n\n",
  )
  for stat in summary.rules_triggered {
    buf.write_string("  ")
    buf.write_string(pad_right(stat.rule_id, 30))
    buf.write_string("  ")
    buf.write_string(pad_left(stat.count.to_string(), 4))
    buf.write_string("  (")
    buf.write_string(severity_str(stat.severity))
    buf.write_string(")\n")
  }
  if summary.cwe_categories.length() > 0 {
    buf.write_string(
      "\n───────────────────────────────────────────────\n",
    )
    buf.write_string("  CWE Categories\n")
    buf.write_string(
      "───────────────────────────────────────────────\n\n",
    )
    for stat in summary.cwe_categories {
      buf.write_string("  CWE-")
      buf.write_string(pad_right(stat.cwe_id.to_string(), 5))
      buf.write_string(" ")
      buf.write_string(pad_right(stat.name, 35))
      buf.write_string("  ")
      buf.write_string(pad_left(stat.count.to_string(), 4))
      buf.write_char('\n')
    }
  }
  if summary.owasp_mapping.length() > 0 {
    buf.write_string(
      "\n───────────────────────────────────────────────\n",
    )
    buf.write_string("  OWASP Top 10 Mapping\n")
    buf.write_string(
      "───────────────────────────────────────────────\n\n",
    )
    for stat in summary.owasp_mapping {
      buf.write_string("  ")
      buf.write_string(pad_right(stat.category, 40))
      buf.write_string("  ")
      buf.write_string(pad_left(stat.count.to_string(), 4))
      buf.write_char('\n')
    }
  }
  if summary.file_stats.length() > 0 {
    buf.write_string(
      "\n───────────────────────────────────────────────\n",
    )
    buf.write_string("  Top Files\n")
    buf.write_string(
      "───────────────────────────────────────────────\n\n",
    )
    let max_files = if summary.file_stats.length() > 10 {
      10
    } else {
      summary.file_stats.length()
    }
    for i = 0; i < max_files; i = i + 1 {
      let fs = summary.file_stats[i]
      buf.write_string("  ")
      buf.write_string(pad_right(fs.file, 40))
      buf.write_string("  ")
      buf.write_string(pad_left(fs.finding_count.to_string(), 4))
      buf.write_string(" (")
      buf.write_string(fs.error_count.to_string())
      buf.write_string("E/")
      buf.write_string(fs.warning_count.to_string())
      buf.write_string("W)\n")
    }
  }
  buf.write_string(
    "\n═══════════════════════════════════════════════\n",
  )
  buf.to_string()
}

///|
fn pad_right(s : String, width : Int) -> String {
  if s.length() >= width {
    return s
  }
  let buf = StringBuilder::new()
  buf.write_string(s)
  for _i = s.length(); _i < width; _i = _i + 1 {
    buf.write_char(' ')
  }
  buf.to_string()
}

///|
fn pad_left(s : String, width : Int) -> String {
  if s.length() >= width {
    return s
  }
  let buf = StringBuilder::new()
  for _i = s.length(); _i < width; _i = _i + 1 {
    buf.write_char(' ')
  }
  buf.write_string(s)
  buf.to_string()
}

///|
pub fn format_summary_json(summary : ScanSummary) -> String {
  let rules_json : Array[Json] = summary.rules_triggered.map(fn(r) {
    let obj : Json = {
      "rule_id": Json::string(r.rule_id),
      "name": Json::string(r.name),
      "count": Json::number(r.count.to_double()),
      "severity": Json::string(severity_str(r.severity)),
    }
    obj
  })
  let files_json : Array[Json] = summary.file_stats.map(fn(f) {
    let obj : Json = {
      "file": Json::string(f.file),
      "findings": Json::number(f.finding_count.to_double()),
      "errors": Json::number(f.error_count.to_double()),
      "warnings": Json::number(f.warning_count.to_double()),
    }
    obj
  })
  let cwe_json : Array[Json] = summary.cwe_categories.map(fn(c) {
    let obj : Json = {
      "cwe_id": Json::number(c.cwe_id.to_double()),
      "name": Json::string(c.name),
      "count": Json::number(c.count.to_double()),
    }
    obj
  })
  let owasp_json : Array[Json] = summary.owasp_mapping.map(fn(o) {
    let cwe_ids_json : Array[Json] = o.cwe_ids.map(fn(id) {
      Json::number(id.to_double())
    })
    let obj : Json = {
      "category": Json::string(o.category),
      "count": Json::number(o.count.to_double()),
      "cwe_ids": Json::array(cwe_ids_json),
    }
    obj
  })
  let obj : Json = {
    "files_scanned": Json::number(summary.files_scanned.to_double()),
    "files_with_findings": Json::number(summary.files_with_findings.to_double()),
    "total_findings": Json::number(summary.total_findings.to_double()),
    "errors": Json::number(summary.error_count.to_double()),
    "warnings": Json::number(summary.warning_count.to_double()),
    "info": Json::number(summary.info_count.to_double()),
    "rules": Json::array(rules_json),
    "files": Json::array(files_json),
    "cwe_categories": Json::array(cwe_json),
    "owasp_mapping": Json::array(owasp_json),
  }
  obj.stringify(indent=2)
}

///|
pub fn risk_score(summary : ScanSummary) -> Double {
  let base = summary.error_count.to_double() * 10.0 +
    summary.warning_count.to_double() * 3.0 +
    summary.info_count.to_double() * 1.0
  let file_ratio = if summary.files_scanned > 0 {
    summary.files_with_findings.to_double() / summary.files_scanned.to_double()
  } else {
    0.0
  }
  let diversity = summary.cwe_categories.length().to_double()
  let score = base * (1.0 + file_ratio * 0.5) * (1.0 + diversity * 0.1)
  if score > 100.0 {
    100.0
  } else {
    score
  }
}

///|
pub fn risk_level(score : Double) -> String {
  if score >= 80.0 {
    "CRITICAL"
  } else if score >= 50.0 {
    "HIGH"
  } else if score >= 20.0 {
    "MEDIUM"
  } else if score > 0.0 {
    "LOW"
  } else {
    "NONE"
  }
}
