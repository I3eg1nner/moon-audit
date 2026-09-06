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
  let buf = StringBuilder()
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
        "    " + p.file + ":" + p.line.to_string() + " [" + p.rule_id + "]\n",
      )
    }
  }
  buf.to_string()
}

///|
/// JSON output with a comparison section (used when --baseline-report set
/// together with --format json).
pub fn format_json_with_diff(
  result : ScanResult,
  diff : BaselineDiff,
) -> String {
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
        if diff.new_findings.any(fn(f2) {
            f2.fingerprint == f.fingerprint && f2.file == f.file
          }) {
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
fn irtype_opt_repr(t : IRType?) -> String {
  match t {
    Some(ty) => ty.display()
    None => "-"
  }
}

///|
/// Fingerprint of a PkgSymbols table. T7.3: VALUE-SENSITIVE — a same-name
/// type change now changes the fingerprint (gate15 known-gap closed).
/// Also stamped with analyzer + parser versions so a toolchain bump
/// invalidates derived caches. Insertion-order independent.
pub fn symbols_fingerprint(symbols : PkgSymbols) -> String {
  let parts : Array[String] = []
  // version stamps (T7.3): toolchain identity enters the key
  parts.push("v:analyzer=" + ANALYZER_VERSION)
  parts.push("v:parser=" + PARSER_SPEC_VERSION)
  let keys : Array[String] = []
  symbols.fn_ret.each(fn(k, ty) { keys.push("ret:" + k + "=" + ty.display()) })
  symbols.impl_methods.each(fn(k, trait_path) {
    keys.push("impl:" + k + "=" + trait_path)
  })
  symbols.struct_fields.each(fn(k, fields) {
    // field map is itself insertion-order dependent: normalize by sorting
    let fpairs : Array[String] = []
    fields.each(fn(fk, fty) { fpairs.push(fk + ":" + fty.display()) })
    fpairs.sort()
    keys.push("field:" + k + "={" + fpairs.join(",") + "}")
  })
  symbols.constr_params.each(fn(k, tys) {
    let reps : Array[String] = []
    for ty in tys {
      reps.push(ty.display())
    }
    keys.push("ctor:" + k + "=[" + reps.join(",") + "]")
  })
  symbols.trait_params.each(fn(k, tys) {
    let reps : Array[String] = []
    for t in tys {
      reps.push(irtype_opt_repr(t))
    }
    keys.push("trait:" + k + "=[" + reps.join(",") + "]")
  })
  symbols.fn_param_arrows.each(fn(k, per_param) {
    // per-param groups: each param's arrow-arg types rendered as a group
    let groups : Array[String] = []
    for grp in per_param {
      let reps : Array[String] = []
      for t in grp {
        reps.push(irtype_opt_repr(t))
      }
      groups.push("(" + reps.join(",") + ")")
    }
    keys.push("arrow:" + k + "=[" + groups.join(",") + "]")
  })
  symbols.alias_arrows.each(fn(k, tys) {
    let reps : Array[String] = []
    for t in tys {
      reps.push(irtype_opt_repr(t))
    }
    keys.push("alias:" + k + "=[" + reps.join(",") + "]")
  })
  // fn_exists values are constant `true` — key names suffice
  symbols.fn_exists.each(fn(k, _) { keys.push("fn:" + k) })
  keys.sort()
  for k in keys {
    parts.push(k)
  }
  fnv1a(parts)
}

// ── T8.4: precision ledger (per-rule four-state triage aggregation) ───────
//
// State semantics (aligned with docs/ir/ACCEPTANCE.md ledger section):
//   tp_candidates : NEW findings not yet triaged (default state for new)
//   confirmed     : findings (new or unchanged) marked "confirmed" in triage
//   fp_suspects   : findings marked "fp" in triage, plus RESOLVED findings
//                   (disappeared vs previous: either fixed upstream or was FP)
//   untriaged     : UNCHANGED findings not in triage (existing inventory)

///|
pub(all) struct RuleLedger {
  rule_id : String
  mut tp_candidates : Int
  mut fp_suspects : Int
  mut confirmed : Int
  mut untriaged : Int
} derive(Debug)

///|
pub fn build_ledger(
  diff : BaselineDiff,
  triage : Map[String, String],
) -> Array[RuleLedger] {
  let per_rule : Map[String, RuleLedger] = Map([])
  fn entry(rule : String) -> RuleLedger {
    match per_rule.get(rule) {
      Some(e) => e
      None => {
        let e : RuleLedger = {
          rule_id: rule,
          tp_candidates: 0,
          fp_suspects: 0,
          confirmed: 0,
          untriaged: 0,
        }
        per_rule[rule] = e
        e
      }
    }
  }
  for f in diff.new_findings {
    let e = entry(rule_id_str(f.rule_id))
    match triage.get(f.fingerprint) {
      Some("confirmed") => e.confirmed += 1
      Some("fp") => e.fp_suspects += 1
      _ => e.tp_candidates += 1
    }
  }
  for f in diff.unchanged {
    let e = entry(rule_id_str(f.rule_id))
    match triage.get(f.fingerprint) {
      Some("confirmed") => e.confirmed += 1
      Some("fp") => e.fp_suspects += 1
      _ => e.untriaged += 1
    }
  }
  for p in diff.resolved {
    // disappeared: fixed upstream or was an FP — both count as FP-suspect
    // until an external fix record says otherwise (thin-slice boundary)
    let e = entry(p.rule_id)
    e.fp_suspects += 1
  }
  let out : Array[RuleLedger] = []
  per_rule.each(fn(_k, v) { out.push(v) })
  out.sort_by(fn(a, b) { a.rule_id.compare(b.rule_id) })
  out
}

///|
pub fn format_ledger(ledgers : Array[RuleLedger]) -> String {
  let buf = StringBuilder()
  buf.write_string("Precision ledger (per rule):\n")
  buf.write_string(
    "  rule                          tp-cand  fp-susp  confirmed  untriaged\n",
  )
  let mut tc = 0
  let mut fs = 0
  let mut cf = 0
  let mut ut = 0
  for l in ledgers {
    buf.write_string(
      "  " +
      Show::to_string(
        (l.rule_id + "                                    ")[0:30],
      ) +
      Show::to_string((l.tp_candidates.to_string() + "            ")[0:10]) +
      Show::to_string((l.fp_suspects.to_string() + "            ")[0:10]) +
      Show::to_string((l.confirmed.to_string() + "                ")[0:14]) +
      l.untriaged.to_string() +
      "\n",
    )
    tc += l.tp_candidates
    fs += l.fp_suspects
    cf += l.confirmed
    ut += l.untriaged
  }
  buf.write_string(
    "  corpus: tp-candidates=" +
    tc.to_string() +
    " fp-suspects=" +
    fs.to_string() +
    " confirmed=" +
    cf.to_string() +
    " untriaged=" +
    ut.to_string() +
    "\n",
  )
  buf.to_string()
}
