// Tests for baseline file support.

///|
test "Baseline: generate and load round-trip" {
  let findings : Array[Finding] = [
    {
      rule_id: { cwe: 116, variant: "replace-escaping", },
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
  let path = test_tmp("moon_audit_test_baseline.json")
  @fs.write_string_to_file(path, json) catch {
    _ => return
  }
  let baseline = load_baseline(path)
  assert_true(baseline.length() > 0)
  inspect(filter_baseline(findings, baseline).length(), content="0")
  @fs.remove_file(path) catch {
    _ => ()
  }
}

///|
test "Baseline: filter_baseline removes matched findings" {
  let f1 : Finding = {
    rule_id: { cwe: 116, variant: "replace-escaping", },
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
    rule_id: { cwe: 79, variant: "cmark-unsafe", },
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
    rule_id: { cwe: 116, variant: "replace-escaping", },
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
  let baseline = load_baseline(test_tmp("no_such_baseline.json"))
  assert_true(baseline.length() == 0)
}

///|
test "Baseline: load_baseline handles invalid JSON" {
  let path = test_tmp("moon_audit_bad_baseline.json")
  @fs.write_string_to_file(path, "not json at all") catch {
    _ => return
  }
  let baseline = load_baseline(path)
  assert_true(baseline.length() == 0)
  @fs.remove_file(path) catch {
    _ => ()
  }
}

///|
test "Baseline: generate_baseline handles special chars" {
  let findings : Array[Finding] = [
    {
      rule_id: { cwe: 79, variant: "xss", },
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

///|
test "Baseline: same snippet in a different file stays visible" {
  let known : Finding = {
    rule_id: { cwe: 116, variant: "replace-escaping", },
    severity: Warning,
    confidence: High,
    message: "known",
    file: "src/foo.mbt",
    line: 10,
    column: 1,
    end_line: 10,
    end_column: 20,
    snippet: "same snippet",
    fingerprint: "shared",
  }
  let new_file = { ..known, file: "src/bar.mbt", }
  let moved = { ..known, file: "./src/foo.mbt", line: 20, end_line: 20, }
  let path = test_tmp("moon_audit_baseline_file_scope.json")
  @fs.write_string_to_file(path, generate_baseline([known]))
  let baseline = load_baseline(path)
  let remaining = filter_baseline([new_file, moved], baseline)
  inspect(remaining.length(), content="1")
  inspect(remaining[0].file, content="src/bar.mbt")
  @fs.remove_file(path)
}

///|
test "Baseline: JSON round-trips Unicode and control characters" {
  let message = "emoji 😀, null \u0000, backspace \b, form feed \u000c"
  let f : Finding = {
    rule_id: { cwe: 116, variant: "replace-escaping", },
    severity: Warning,
    confidence: High,
    message,
    file: "src/例子😀.mbt",
    line: 1,
    column: 1,
    end_line: 1,
    end_column: 20,
    snippet: "test",
    fingerprint: "unicode",
  }
  let parsed = @json.parse(generate_baseline([f]))
  match parsed {
    Array([{ "message": String(actual), "file": String(file), .. }]) => {
      inspect(actual == message, content="true")
      inspect(file == f.file, content="true")
    }
    _ => fail("baseline JSON did not round-trip")
  }
}

///|
fn counted_baseline_source(copies : Int) -> String {
  "fn f(resp : Response, value : String) -> Unit {\n" +
  "  resp.set_header(\"X\", value)\n".repeat(copies) +
  "}\n"
}

///|
test "Baseline: added identical sinks remain visible after generated baseline" {
  let root = test_tmp("moon_audit_baseline_occurrences")
  @fs.create_dir(root) catch {
    _ => ()
  }
  @fs.create_dir(pjoin(root, "src")) catch {
    _ => ()
  }
  @fs.write_string_to_file(
    pjoin(root, "moon.mod"),
    "name = \"fixture/baseline-counts\"\n",
  )
  @fs.write_string_to_file(pjoin(pjoin(root, "src"), "moon.pkg"), "")
  let source_file = pjoin(pjoin(root, "src"), "main.mbt")
  let baseline_file = pjoin(root, "baseline.json")
  for counts in [(1, 2, 1), (2, 3, 1), (2, 2, 0), (2, 1, 0)] {
    @fs.write_string_to_file(source_file, counted_baseline_source(counts.0))
    let before = scan_project(root, Config::default())
    inspect(before.errors.length(), content="0")
    assert_true(before.findings.length() == counts.0)
    @fs.write_string_to_file(
      baseline_file,
      generate_baseline(before.findings, root~),
    )
    let baseline = load_baseline(baseline_file)
    @fs.write_string_to_file(source_file, counted_baseline_source(counts.1))
    let after = scan_project(root, Config::default())
    inspect(after.errors.length(), content="0")
    assert_true(after.findings.length() == counts.1)
    assert_true(
      after.findings.all(fn(f) {
        f.fingerprint == before.findings[0].fingerprint
      }),
    )
    let remaining = filter_baseline(after.findings, baseline, root~)
    assert_eq(remaining.length(), counts.2)
    if counts.2 > 0 {
      assert_true(remaining[0].line == counts.0 + 2)
    }
    // A loaded baseline can be reused without consuming its stored allowance.
    assert_true(
      filter_baseline(after.findings, baseline, root~).length() == counts.2,
    )
  }
  @fs.write_string_to_file(source_file, counted_baseline_source(1))
  let before = scan_project(root, Config::default())
  @fs.write_string_to_file(
    baseline_file,
    generate_baseline(before.findings, root~),
  )
  let baseline = load_baseline(baseline_file)
  @fs.write_string_to_file(source_file, "\n\n" + counted_baseline_source(1))
  let moved = scan_project(root, Config::default())
  inspect(moved.findings.length(), content="1")
  inspect(moved.findings[0].line, content="4")
  inspect(
    filter_baseline(moved.findings, baseline, root~).length(),
    content="0",
  )
  @fs.write_string_to_file(
    source_file, "fn f(resp : Response) -> Unit { resp.set_header(\"X\", \"safe\") }\n",
  )
  let fixed = scan_project(root, Config::default())
  inspect(fixed.findings.length(), content="0")
  inspect(
    filter_baseline(fixed.findings, baseline, root~).length(),
    content="0",
  )
}

///|
test "Baseline: duplicate allowances survive project-relative path relocation" {
  let old_root = test_tmp("baseline_previous_checkout")
  let new_root = test_tmp("baseline_current_checkout")
  let known = { ..mk_finding("shared"), file: old_root + "/src/f.mbt", }
  let second = { ..known, line: 20, end_line: 20, }
  let path = test_tmp("baseline_relative_occurrences.json")
  let content = generate_baseline([known, second], root=old_root)
  let json = @json.parse(content)
  match json {
    Array([{ "file": String(first), .. }, { "file": String(next), .. }]) => {
      inspect(first, content="src/f.mbt")
      inspect(next, content="src/f.mbt")
    }
    _ => fail("generated baseline must retain each occurrence")
  }
  @fs.write_string_to_file(path, content)
  let baseline = load_baseline(path)
  let moved = {
    ..known,
    file: new_root + "/src/./f.mbt",
    line: 50,
    end_line: 50,
  }
  let current = [
    moved,
    { ..moved, line: 60, end_line: 60, },
    { ..moved, line: 70, end_line: 70, },
  ]
  let remaining = filter_baseline(current, baseline, root=new_root)
  inspect(remaining.length(), content="1")
  inspect(remaining[0].line, content="70")
  let other_file = { ..moved, file: new_root + "/src/other.mbt", }
  let other_rule = {
    ..moved,
    rule_id: { cwe: 116, variant: "tainted-output", },
  }
  inspect(
    filter_baseline([other_file, other_rule, moved], baseline, root=new_root).length(),
    content="2",
  )
  @fs.remove_file(path)
}

///|
test "Baseline: legacy entries without files still suppress all matching occurrences" {
  let path = test_tmp("baseline_legacy_global_occurrences.json")
  @fs.write_string_to_file(
    path, "[{\"rule_id\":\"CWE-113/crlf-injection\",\"fingerprint\":\"shared\"}]",
  )
  let baseline = load_baseline(path)
  let known = mk_finding("shared")
  let current = [
    known,
    { ..known, line: 20, end_line: 20, },
    { ..known, file: "other.mbt", },
    mk_finding("different"),
  ]
  let remaining = filter_baseline(current, baseline)
  inspect(remaining.length(), content="1")
  inspect(remaining[0].fingerprint, content="different")
  inspect(baseline.length(), content="1")
  @fs.remove_file(path)
}

///|
test "Baseline: project paths cannot match a different cwd-relative file" {
  let root = "p"
  let known = { ..mk_finding("shared"), file: "p/p/f.mbt", }
  let added = { ..known, file: "p/f.mbt", }
  let path = test_tmp("baseline_project_scope_nested.json")
  let content = generate_baseline([known], root~)
  match @json.parse(content) {
    Array([{ "path_scope": String("project"), "file": String(file), .. }]) =>
      inspect(file, content="p/f.mbt")
    _ => fail("project-relative baselines must identify their path scope")
  }
  @fs.write_string_to_file(path, content)
  let baseline = load_baseline(path)
  // An incremental scan contains only the new file. Its cwd-relative path
  // equals the older nested file's project-relative path, but identities differ.
  let incremental = filter_baseline([added], baseline, root~)
  inspect(incremental.length(), content="1")
  inspect(incremental[0].file, content="p/f.mbt")
  inspect(filter_baseline([known], baseline, root~).length(), content="0")
  let full = filter_baseline([added, known], baseline, root~)
  inspect(full.length(), content="1")
  inspect(full[0].file, content="p/f.mbt")
  @fs.remove_file(path)
}

///|
test "Baseline: legacy scoped paths keep cwd-relative and absolute compatibility" {
  let root = "p"
  let finding = { ..mk_finding("shared"), file: "p/f.mbt", }
  let duplicate = { ..finding, line: 20, end_line: 20, }
  let path = test_tmp("baseline_legacy_path_scope.json")
  for file in [finding.file, @path.Path(finding.file).resolve().0] {
    // Omitting root retains the previous JSON shape and path interpretation.
    let content = generate_baseline([{ ..finding, file, }])
    assert_false(content.contains("path_scope"))
    @fs.write_string_to_file(path, content)
    let baseline = load_baseline(path)
    let remaining = filter_baseline([finding, duplicate], baseline, root~)
    inspect(remaining.length(), content="1")
    inspect(remaining[0].line, content="20")
  }
  @fs.remove_file(path)
}
