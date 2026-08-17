// Tests for baseline file support.

///|
test "Baseline: generate and load round-trip" {
  let findings : Array[Finding] = [
    {
      rule_id: { cwe: 116, variant: "replace-escaping" },
      severity: Warning,
      confidence: High,
      message: "test finding",
      file: "src/foo.mbt",
      line: 10,
      column: 1,
      end_line: 10,
      end_column: 20,
      snippet: "s.replace(old=\"<\", new=\"&lt;\")",
      fingerprint: "12345",
    },
  ]
  let json = generate_baseline(findings)
  let path = "/tmp/moon_audit_test_baseline.json"
  @fs.write_string_to_file(path, json) catch { _ => return }
  let baseline = load_baseline(path)
  assert_true(baseline.length() > 0)
  assert_true(baseline.contains("CWE-116/replace-escaping:12345"))
  @fs.remove_file(path) catch { _ => () }
}

///|
test "Baseline: filter_baseline removes matched findings" {
  let f1 : Finding = {
    rule_id: { cwe: 116, variant: "replace-escaping" },
    severity: Warning,
    confidence: High,
    message: "known issue",
    file: "src/foo.mbt",
    line: 10,
    column: 1,
    end_line: 10,
    end_column: 20,
    snippet: "s.replace(old=\"<\")",
    fingerprint: "aaa",
  }
  let f2 : Finding = {
    rule_id: { cwe: 79, variant: "cmark-unsafe" },
    severity: Error,
    confidence: High,
    message: "new issue",
    file: "src/bar.mbt",
    line: 5,
    column: 1,
    end_line: 5,
    end_column: 30,
    snippet: "render(safe=false)",
    fingerprint: "bbb",
  }
  let baseline : Map[String, Bool] = Map([])
  baseline["CWE-116/replace-escaping:aaa"] = true
  let result = filter_baseline([f1, f2], baseline)
  assert_true(result.length() == 1)
  assert_true(result[0].fingerprint == "bbb")
}

///|
test "Baseline: filter_baseline with empty baseline returns all" {
  let f : Finding = {
    rule_id: { cwe: 116, variant: "replace-escaping" },
    severity: Warning,
    confidence: High,
    message: "test",
    file: "test.mbt",
    line: 1,
    column: 1,
    end_line: 1,
    end_column: 10,
    snippet: "code",
    fingerprint: "fp1",
  }
  let result = filter_baseline([f], Map([]))
  assert_true(result.length() == 1)
}

///|
test "Baseline: load_baseline handles missing file" {
  let baseline = load_baseline("/tmp/no_such_baseline.json")
  assert_true(baseline.length() == 0)
}

///|
test "Baseline: load_baseline handles invalid JSON" {
  let path = "/tmp/moon_audit_bad_baseline.json"
  @fs.write_string_to_file(path, "not json at all") catch { _ => return }
  let baseline = load_baseline(path)
  assert_true(baseline.length() == 0)
  @fs.remove_file(path) catch { _ => () }
}

///|
test "Baseline: generate_baseline handles special chars" {
  let findings : Array[Finding] = [
    {
      rule_id: { cwe: 79, variant: "xss" },
      severity: Error,
      confidence: High,
      message: "contains \"quotes\" and \\backslash",
      file: "src/test.mbt",
      line: 1,
      column: 1,
      end_line: 1,
      end_column: 10,
      snippet: "html(\"<script>\")",
      fingerprint: "fp",
    },
  ]
  let json = generate_baseline(findings)
  assert_true(json.contains("\\\"quotes\\\""))
  assert_true(json.contains("\\\\backslash"))
}
