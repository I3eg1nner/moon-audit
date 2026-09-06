// Acceptance system tests: baseline diff (TP/FP/FN tracking) + cache keys.

///|
fn mk_finding(fp : String) -> Finding {
  {
    rule_id: { cwe: 113, variant: "crlf-injection", },
    severity: Error,
    confidence: Medium,
    message: "m",
    file: "a.mbt",
    line: 1,
    column: 1,
    end_line: 1,
    end_column: 2,
    snippet: "s",
    fingerprint: fp,
  }
}

///|
test "acceptance: baseline diff classifies new/resolved/unchanged" {
  let prev_report = "{ \"findings\": [ {\"rule_id\": \"CWE-113/crlf-injection\", \"file\": \"a.mbt\", \"line\": 1, \"fingerprint\": \"fp-keep\", \"message\": \"stays\"}, {\"rule_id\": \"CWE-113/crlf-injection\", \"file\": \"b.mbt\", \"line\": 2, \"fingerprint\": \"fp-gone\", \"message\": \"fixed\"} ], \"files_scanned\": 2, \"errors\": [] }"
  let prev = parse_report_findings(prev_report)
  inspect(prev.length(), content="2")
  // current scan: one unchanged (fp-keep), one new (fp-new); fp-gone resolved
  let current = [mk_finding("fp-keep"), mk_finding("fp-new")]
  let diff = diff_findings(current, prev)
  inspect(diff.prev_total, content="2")
  inspect(diff.current_total, content="2")
  inspect(diff.unchanged.length(), content="1")
  inspect(diff.new_findings.length(), content="1")
  inspect(diff.resolved.length(), content="1")
  inspect(diff.unchanged[0].fingerprint, content="fp-keep")
  inspect(diff.new_findings[0].fingerprint, content="fp-new")
  inspect(diff.resolved[0].fingerprint, content="fp-gone")
  let text = format_baseline_diff(diff)
  inspect(text.contains("NEW (TP candidates): 1"), content="true")
  inspect(text.contains("RESOLVED: 1"), content="true")
  inspect(text.contains("UNCHANGED: 1"), content="true")
}

///|
test "acceptance: json diff output marks new status" {
  let prev_report = "{ \"findings\": [ {\"rule_id\": \"CWE-113/crlf-injection\", \"file\": \"a.mbt\", \"line\": 1, \"fingerprint\": \"fp-old\", \"message\": \"stays\"} ], \"files_scanned\": 1, \"errors\": [] }"
  let prev = parse_report_findings(prev_report)
  let result : ScanResult = {
    findings: [mk_finding("fp-old"), mk_finding("fp-fresh")],
    files_scanned: 1,
    errors: [],
    analysis_scope: "",
  }
  let diff = diff_findings(result.findings, prev)
  let json = format_json_with_diff(result, diff)
  inspect(json.contains("\"status\": \"new\""), content="true")
  inspect(json.contains("\"status\": \"unchanged\""), content="true")
  inspect(json.contains("\"resolved\": 0"), content="true")
  inspect(json.contains("\"new\": 1"), content="true")
}

///|
test "acceptance: parse_report_findings empty and malformed" {
  inspect(parse_report_findings("not json").length(), content="0")
  inspect(parse_report_findings("{}").length(), content="0")
  inspect(
    parse_report_findings("{ \"findings\": [], \"files_scanned\": 0 }").length(),
    content="0",
  )
}

///|
test "acceptance: analysis_cache_key composition" {
  // different source -> different key
  let k1 = analysis_cache_key("fn a() {}", "symfp")
  let k2 = analysis_cache_key("fn b() {}", "symfp")
  assert_true(k1 != k2)
  // different symbol fingerprint -> different key (review: source hash alone
  // is invalid; dependency changes must invalidate)
  let k3 = analysis_cache_key("fn a() {}", "symfp2")
  assert_true(k1 != k3)
  // deterministic
  assert_true(k1 == analysis_cache_key("fn a() {}", "symfp"))
}

///|
test "acceptance: symbols_fingerprint is stable across insertion order" {
  let s1 = PkgSymbols::new()
  s1.fn_exists["alpha"] = true
  s1.fn_exists["beta"] = true
  s1.impl_methods["A::f"] = "T"
  let s2 = PkgSymbols::new()
  s2.impl_methods["A::f"] = "T"
  s2.fn_exists["beta"] = true
  s2.fn_exists["alpha"] = true
  assert_true(symbols_fingerprint(s1) == symbols_fingerprint(s2))
  // content change -> different fingerprint
  let s3 = PkgSymbols::new()
  s3.fn_exists["alpha"] = true
  s3.fn_exists["beta"] = true
  s3.impl_methods["A::g"] = "T"
  assert_true(symbols_fingerprint(s1) != symbols_fingerprint(s3))
}

// ── T8.4: precision ledger ────────────────────────────────────────────────

///|
fn ledger_finding(fp : String, rule : String, cwe? : Int = 113) -> Finding {
  {
    rule_id: { cwe, variant: rule, },
    severity: Warning,
    confidence: Medium,
    message: "m",
    file: "f.mbt",
    line: 1,
    column: 1,
    end_line: 1,
    end_column: 2,
    snippet: "s",
    fingerprint: fp,
  }
}

///|
fn ledger_prev(fp : String, rule : String) -> PrevFinding {
  { fingerprint: fp, rule_id: rule, file: "f.mbt", line: 1, message: "m", }
}

///|
test "t8_4_ledger_aggregation_correct" {
  // current: new-A (untriaged), new-B (triaged confirmed), keep-C (untriaged),
  //          keep-D (triaged fp); prev also had resolved-R
  // PrevFinding.rule_id must match rule_id_str output ("CWE-xxx/variant")
  let prev = [
    ledger_prev("B", "CWE-113/crlf-injection"), // B same fingerprint as a
    // current finding => neither new nor resolved (dropped from cur2)
    ledger_prev("C", "CWE-113/crlf-injection"),
    ledger_prev("D", "CWE-942/cors-credentials"),
    ledger_prev("R", "CWE-942/cors-credentials"),
  ]
  let cur2 = [
    ledger_finding("A", "crlf-injection"),
    ledger_finding("E", "crlf-injection"),
    ledger_finding("C", "crlf-injection"),
    ledger_finding("D", "cors-credentials", cwe=942),
  ]
  let diff = diff_findings(cur2, prev)
  let triage : Map[String, String] = Map([])
  triage["E"] = "confirmed"
  triage["D"] = "fp"
  let ledger = build_ledger(diff, triage)
  for l in ledger {
    println("[dbg] ledger rule=" + l.rule_id)
  }
  inspect(ledger.length(), content="2")
  // rule order sorted: CWE-113/... < CWE-942/... (string compare)
  inspect(ledger[0].rule_id, content="CWE-113/crlf-injection")
  inspect(ledger[0].tp_candidates, content="1") // A
  inspect(ledger[0].confirmed, content="1") // E
  inspect(ledger[0].untriaged, content="1") // C
  inspect(ledger[1].rule_id, content="CWE-942/cors-credentials")
  inspect(ledger[1].fp_suspects, content="2") // D(fp) + R(resolved)
  inspect(ledger[1].untriaged, content="0")
  // format includes the corpus summary line
  let text = format_ledger(ledger)
  inspect(text.contains("corpus: tp-candidates=1"), content="true")
  inspect(text.contains("confirmed=1"), content="true")
}

///|
test "t8_4_ledger_empty_input" {
  let diff : BaselineDiff = {
    new_findings: [],
    resolved: [],
    unchanged: [],
    prev_total: 0,
    current_total: 0,
  }
  let ledger = build_ledger(diff, Map([]))
  inspect(ledger.length(), content="0")
  let text = format_ledger(ledger)
  inspect(text.contains("corpus: tp-candidates=0"), content="true")
}
