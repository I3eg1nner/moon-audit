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
  let test_path = "/tmp/moon_audit_test_changed.txt"
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
  let files = load_changed_files("/tmp/nonexistent_file_list.txt")
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
