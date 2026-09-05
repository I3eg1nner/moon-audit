// Acceptance system (review §4): TP/FP/FN baseline comparison, analysis
// cache keys, and the contracts documented in docs/ir/ACCEPTANCE.md.
//
// Baseline diff: compares a current scan against a PREVIOUS scan report
// (the JSON emitted by `scan --format json`). Findings are keyed by the
// stable FNV fingerprint (rule_id + code snippet, line-independent), so
//   new      = present now, absent before  → TP candidates (or regressions)
//   resolved = present before, absent now  → fixes / noise removed
//   unchanged= present in both            → existing inventory

///|
pub(all) struct PrevFinding {
  fingerprint : String
  rule_id : String
  file : String
  line : Int
  message : String
} derive(Debug)

///|
pub(all) struct BaselineDiff {
  new_findings : Array[Finding] // TP candidates
  resolved : Array[PrevFinding] // disappeared vs previous report
  unchanged : Array[Finding] // existing inventory
  prev_total : Int
  current_total : Int
}

///|
/// Parse a previous scan report (output of `--format json`) into the
/// fingerprint-keyed finding list. Returns [] on parse failure.
pub fn parse_report_findings(content : String) -> Array[PrevFinding] {
  let out : Array[PrevFinding] = []
  let json = @json.parse(content) catch { _ => return out }
  match json {
    Object(obj) =>
      match obj.get("findings") {
        Some(Array(arr)) =>
          for item in arr {
            match item {
              Object(f) => {
                let fp = match f.get("fingerprint") {
                  Some(String(s)) => s
                  _ => continue
                }
                let rule = match f.get("rule_id") {
                  Some(String(s)) => s
                  _ => ""
                }
                let file = match f.get("file") {
                  Some(String(s)) => s
                  _ => ""
                }
                let line = match f.get("line") {
                  Some(Number(n, ..)) => n.to_int()
                  _ => 0
                }
                let msg = match f.get("message") {
                  Some(String(s)) => s
                  _ => ""
                }
                out.push({
                  fingerprint: fp,
                  rule_id: rule,
                  file,
                  line,
                  message: msg,
                })
              }
              _ => ()
            }
          }
        _ => ()
      }
    _ => ()
  }
  out
}

///|
/// Classify current findings against a previous report's findings.
pub fn diff_findings(
  current : Array[Finding],
  prev : Array[PrevFinding],
) -> BaselineDiff {
  let prev_map : Map[String, PrevFinding] = Map([])
  for p in prev {
    prev_map[p.fingerprint] = p
  }
  let cur_map : Map[String, Bool] = Map([])
  let diff : BaselineDiff = {
    new_findings: [],
    resolved: [],
    unchanged: [],
    prev_total: prev.length(),
    current_total: current.length(),
  }
  for f in current {
    cur_map[f.fingerprint] = true
    match prev_map.get(f.fingerprint) {
      Some(_) => diff.unchanged.push(f)
      None => diff.new_findings.push(f)
    }
  }
  // resolved: prev entries whose fingerprint is absent from current
  for p in prev {
    if !cur_map.contains(p.fingerprint) {
      diff.resolved.push(p)
    }
  }
  diff
}

///|
fn truncate_str(s : String, max : Int) -> String {
  if s.length() <= max {
    s
  } else {
    Show::to_string(s[0:max])
  }
}

///|
/// Text summary of a baseline diff (TP candidates / resolved / unchanged).
pub fn format_baseline_diff(diff : BaselineDiff) -> String {
  let buf = StringBuilder::new()
  buf.write_string("Baseline comparison (previous report):\n")
  buf.write_string(
    "  previous findings: " +
    diff.prev_total.to_string() +
    "   current findings: " +
    diff.current_total.to_string() +
    "\n",
  )
  buf.write_string(
    "  NEW (TP candidates): " +
    diff.new_findings.length().to_string() +
    "   RESOLVED: " +
    diff.resolved.length().to_string() +
    "   UNCHANGED: " +
    diff.unchanged.length().to_string() +
    "\n",
  )
  if diff.new_findings.length() > 0 {
    buf.write_string("  new findings:\n")
    for f in diff.new_findings {
      buf.write_string(
        "    " +
        f.file +
        ":" +
        f.line.to_string() +
        " [" +
        rule_id_str(f.rule_id) +
        "] " +
        truncate_str(f.message, 60) +
        "...\n",
      )
    }
  }
  if diff.resolved.length() > 0 {
    buf.write_string("  resolved findings:\n")
    for p in diff.resolved {
      buf.write_string(
        "    " +
        p.file +
        ":" +
        p.line.to_string() +
        " [" +
        p.rule_id +
        "]\n",
      )
    }
  }
  buf.to_string()
}

///|
/// JSON output with a comparison section (used when --baseline-report set
/// together with --format json).
pub fn format_json_with_diff(result : ScanResult, diff : BaselineDiff) -> String {
  let findings_json : Array[Json] = []
  for f in result.findings {
    findings_json.push({
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
      "status": Json::string(
        if diff.new_findings.any(
            fn(f2) { f2.fingerprint == f.fingerprint && f2.file == f.file },
        ) {
          "new"
        } else {
          "unchanged"
        },
      ),
    })
  }
  let resolved_json : Array[Json] = []
  for p in diff.resolved {
    resolved_json.push({
      "rule_id": Json::string(p.rule_id),
      "file": Json::string(p.file),
      "line": Json::number(p.line.to_double()),
      "message": Json::string(p.message),
      "fingerprint": Json::string(p.fingerprint),
    })
  }
  let obj : Json = {
    "findings": Json::array(findings_json),
    "files_scanned": Json::number(result.files_scanned.to_double()),
    "errors": Json::array(result.errors.map(fn(e) { Json::string(e) })),
    "comparison": {
      "previous_total": Json::number(diff.prev_total.to_double()),
      "current_total": Json::number(diff.current_total.to_double()),
      "new": Json::number(diff.new_findings.length().to_double()),
      "resolved": Json::number(diff.resolved.length().to_double()),
      "unchanged": Json::number(diff.unchanged.length().to_double()),
      "resolved_findings": Json::array(resolved_json),
    },
  }
  obj.stringify(indent=2)
}

// ── Analysis cache keys ───────────────────────────────────────────────────
// Review §4: a source-file hash alone is NOT a valid cache key for typed
// IR / summaries. Validity also depends on the dependency symbol tables
// (.mbti interfaces, dep sources), the parser version, and (future) the
// summaries of called functions. analysis_cache_key composes all of them.

///|
pub const PARSER_VERSION_KEY : String = "moonbitlang/parser@0.3.18"

///|
fn fnv1a(parts : Array[String]) -> String {
  let mut h : UInt = 2166136261U
  for part in parts {
    for i = 0; i < part.length(); i = i + 1 {
      h = h.lxor(part[i].to_uint())
      h = h * 16777619U
    }
    // separator avoids concatenation ambiguity
    h = h.lxor(0x1fU)
    h = h * 16777619U
  }
  h.to_string()
}

///|
/// Cache key for per-function analysis artifacts (IR / taint summaries):
/// hash(source + dependency-symbol fingerprint + parser version).
/// The symbol fingerprint covers everything the local inference reads:
/// fn signatures, impl methods, struct fields, constructor payloads,
/// trait params, alias arrows — in .mbti and dependency sources.
pub fn analysis_cache_key(
  source : String,
  symbols_fingerprint : String,
) -> String {
  fnv1a([source, symbols_fingerprint, PARSER_VERSION_KEY])
}

///|
/// Fingerprint of a PkgSymbols table (insertion-order independent:
/// sorts key/value strings before hashing).
pub fn symbols_fingerprint(symbols : PkgSymbols) -> String {
  let parts : Array[String] = []
  let keys : Array[String] = []
  symbols.fn_ret.each(fn(k, _) { keys.push("ret:" + k) })
  symbols.impl_methods.each(fn(k, _) { keys.push("impl:" + k) })
  symbols.struct_fields.each(fn(k, _) { keys.push("field:" + k) })
  symbols.constr_params.each(fn(k, _) { keys.push("ctor:" + k) })
  symbols.trait_params.each(fn(k, _) { keys.push("trait:" + k) })
  symbols.fn_param_arrows.each(fn(k, _) { keys.push("arrow:" + k) })
  symbols.alias_arrows.each(fn(k, _) { keys.push("alias:" + k) })
  symbols.fn_exists.each(fn(k, _) { keys.push("fn:" + k) })
  keys.sort()
  for k in keys {
    parts.push(k)
  }
  fnv1a(parts)
}
