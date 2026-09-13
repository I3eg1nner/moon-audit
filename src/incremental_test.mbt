// Tests for incremental scanning (changed_files filter).

///|
test "Incremental: scan_project respects changed_files filter" {
  let config : Config = {
    ..Config::default(),
    changed_files: ["nonexistent_file.mbt"],
  }
  let result = scan_project(".", config)
  assert_true(result.files_scanned == 0)
}

///|
test "Incremental: empty changed_files scans all" {
  let config = Config::default()
  assert_true(config.changed_files.length() == 0)
  let result = scan_project(".", config)
  assert_true(result.files_scanned > 0)
}

///|
test "Incremental: load_changed_files parses file list" {
  let test_path = test_tmp("moon_audit_test_changed.txt")
  @fs.write_string_to_file(test_path, "src/foo.mbt\nsrc/bar.mbt\n\nREADME.md\n") catch {
    _ => return
  }
  let files = load_changed_files(test_path)
  assert_true(files.length() == 2)
  assert_true(files[0] == "src/foo.mbt")
  assert_true(files[1] == "src/bar.mbt")
  @fs.remove_file(test_path) catch {
    _ => ()
  }
}

///|
test "Incremental: load_changed_files handles missing file" {
  let files = load_changed_files(test_tmp("nonexistent_file_list.txt"))
  assert_true(files.length() == 0)
}

///|
test "Incremental: changed_files limits scanned count" {
  let config_all = Config::default()
  let result_all = scan_project(".", config_all)
  let config_inc : Config = {
    ..Config::default(),
    changed_files: ["src/scanner.mbt"],
  }
  let result_inc = scan_project(".", config_inc)
  assert_true(result_inc.files_scanned <= result_all.files_scanned)
  assert_true(result_inc.files_scanned <= 1)
}

///|
fn make_incremental_fixture() -> String raise {
  let root = test_tmp("moon_audit_incremental_exact")
  @fs.create_dir(root) catch {
    _ => ()
  }
  @fs.create_dir(pjoin(root, "src")) catch {
    _ => ()
  }
  @fs.create_dir(pjoin(root, "other")) catch {
    _ => ()
  }
  @fs.write_string_to_file(pjoin(root, "moon.mod"), "name = \"fixture/inc\"\n")
  for dir in ["src", "other"] {
    @fs.write_string_to_file(pjoin(pjoin(root, dir), "moon.pkg"), "")
    @fs.write_string_to_file(
      pjoin(pjoin(root, dir), "foo.mbt"),
      "fn f(s : String) -> String { s.replace(old=\"<\", new=\"&lt;\") }",
    )
  }
  @fs.write_string_to_file(
    pjoin(pjoin(root, "src"), "myfoo.mbt"),
    "fn g() -> Unit {}",
  )
  root
}

///|
test "Incremental: explicit empty list scans zero files" {
  let root = make_incremental_fixture()
  let full = scan_project(root, Config::default())
  inspect(full.files_scanned, content="3")
  let result = scan_project(root, { ..Config::default(), incremental: true, })
  inspect(result.files_scanned, content="0")
  inspect(result.findings.length(), content="0")
  assert_true(result.analysis_scope.contains("incremental=true"))
}

///|
test "Incremental: paths are exact and relative to the project root" {
  let root = make_incremental_fixture()
  for
    name in [
      "src/foo.mbt",
      "./src/../src/foo.mbt",
      "src\\foo.mbt",
      pjoin(pjoin(root, "src"), "foo.mbt"),
    ] {
    let result = scan_project(root, {
      ..Config::default(),
      changed_files: [name],
    })
    inspect(result.files_scanned, content="1")
    inspect(result.findings.length(), content="1")
    assert_true(
      canonical_dir(result.findings[0].file).has_suffix("/src/foo.mbt"),
    )
  }
  let missing = scan_project(root, {
    ..Config::default(),
    changed_files: ["foo.mbt"],
  })
  inspect(missing.files_scanned, content="0")
}
