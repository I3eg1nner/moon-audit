///|
fn module_fixture_dir(parent : String, name : String) -> String {
  let dir = pjoin(parent, name)
  @fs.create_dir(dir) catch {
    _ => ()
  }
  dir
}

///|
fn module_fixture_source(dir : String) -> String raise {
  let file = pjoin(dir, "source.mbt")
  @fs.write_string_to_file(
    file, "fn consume() -> Unit { panic(\"external input\") }\n",
  )
  file
}

///|
fn module_fixture_config() -> @src.Config {
  let config = @src.Config::default()
  config.rules["CWE-248/panic-reachable"] = { enabled: true, severity: None, }
  config
}

///|
test "module identity follows nearest configuration across nested modules" {
  let root = test_tmp("moon_audit_module_identity_nested")
  @fs.create_dir(root) catch {
    _ => ()
  }
  let core = module_fixture_dir(root, "core")
  @fs.write_string_to_file(
    pjoin(core, "moon.mod"),
    "name = \"moonbitlang/core\"\n",
  )
  ignore(module_fixture_source(core))
  let core_child = module_fixture_dir(core, "package")
  ignore(module_fixture_source(core_child))
  let app = module_fixture_dir(core, "app")
  @fs.write_string_to_file(
    pjoin(app, "moon.mod.json"),
    "{\"name\":\"fixture/app\"}",
  )
  let app_file = module_fixture_source(app)
  let app_child = module_fixture_dir(app, "package")
  let child_file = module_fixture_source(app_child)
  let legacy_core = module_fixture_dir(app, "legacy_core")
  @fs.write_string_to_file(
    pjoin(legacy_core, "moon.mod.json"),
    "{\"name\":\"moonbitlang/x\"}",
  )
  ignore(module_fixture_source(legacy_core))
  let report = @src.scan_project(root, module_fixture_config())
  assert_eq(report.errors.length(), 0)
  assert_eq(report.files_parsed, 5)
  assert_eq(report.findings.length(), 2)
  assert_true(report.findings.any(f => f.file == app_file))
  assert_true(report.findings.any(f => f.file == child_file))
  // Scanning the enclosing stdlib module must still reset at the app boundary.
  let enclosed = @src.scan_project(core, module_fixture_config())
  assert_eq(enclosed.errors.length(), 0)
  assert_eq(enclosed.findings.length(), 2)
}

///|
test "module identity does not cross the requested root or inherit package imports" {
  let parent = test_tmp("moon_audit_module_identity_boundary")
  @fs.create_dir(parent) catch {
    _ => ()
  }
  @fs.write_string_to_file(
    pjoin(parent, "moon.mod"),
    "name = \"moonbitlang/core\"\n",
  )
  let root = module_fixture_dir(parent, "selected")
  let source = module_fixture_source(root)
  let report = @src.scan_project(root, module_fixture_config())
  assert_eq(report.errors.length(), 0)
  assert_eq(report.findings.length(), 1)
  assert_eq(report.findings[0].file, source)
  @fs.write_string_to_file(
    pjoin(root, "moon.pkg"),
    "import { \"moonbitlang/cmark\", }\n",
  )
  let child = module_fixture_dir(root, "child")
  @fs.write_string_to_file(
    pjoin(child, "render.mbt"),
    "fn render_doc(value : String) -> Unit { render(value, safe=false) }\n",
  )
  let package_report = @src.scan_project(root, module_fixture_config())
  assert_eq(package_report.errors.length(), 0)
  assert_eq(package_report.findings.length(), 1)
}

///|
test "malformed nested module files report errors and reset inherited identity" {
  let root = test_tmp("moon_audit_module_identity_invalid")
  @fs.create_dir(root) catch {
    _ => ()
  }
  @fs.write_string_to_file(
    pjoin(root, "moon.mod"),
    "name = \"moonbitlang/core\"\n",
  )
  let fixtures = [
    ("syntax", "moon.mod", "name = \"unterminated"),
    ("lexical", "moon.mod", "name = \"moonbitlang/core\"\n$\n"),
    (
      "duplicate", "moon.mod", "name = \"fixture/a\"\nname = \"moonbitlang/core\"\n",
    ),
    ("bad_json", "moon.mod.json", "{\"name\":"),
    (
      "duplicate_json", "moon.mod.json", "{\"name\":\"fixture/app\",\"name\":\"moonbitlang/core\"}",
    ),
    (
      "escaped_duplicate", "moon.mod.json", "{\"name\":\"fixture/app\",\"na\\u006de\":\"moonbitlang/core\"}",
    ),
    ("bad_type", "moon.mod.json", "{\"name\":7}"),
    ("array", "moon.mod.json", "[]"),
  ]
  for fixture in fixtures {
    let dir = module_fixture_dir(root, fixture.0)
    @fs.write_string_to_file(pjoin(dir, fixture.1), fixture.2)
    ignore(module_fixture_source(dir))
    let child = module_fixture_dir(dir, "child")
    ignore(module_fixture_source(child))
  }
  let report = @src.scan_project(root, module_fixture_config())
  assert_eq(report.errors.length(), fixtures.length())
  assert_eq(report.findings.length(), fixtures.length() * 2)
  for fixture in fixtures {
    assert_true(
      report.errors.any(error => {
        error.contains(pjoin(pjoin(root, fixture.0), fixture.1))
      }),
    )
  }
}

///|
test "module name is exact parsed data rather than comment or string substring" {
  let root = test_tmp("moon_audit_module_identity_exact")
  @fs.create_dir(root) catch {
    _ => ()
  }
  @fs.write_string_to_file(
    pjoin(root, "moon.mod"),
    "name = \"fixture/app\" // name = \"moonbitlang/core\"\n",
  )
  ignore(module_fixture_source(root))
  let child = module_fixture_dir(root, "child")
  @fs.write_string_to_file(
    pjoin(child, "moon.mod.json"),
    "{\"name\":\"prefix/moonbitlang/core\",\"extra\":{\"name\":\"moonbitlang/core\"},\"note\":\"name\"}",
  )
  ignore(module_fixture_source(child))
  let report = @src.scan_project(root, module_fixture_config())
  assert_eq(report.errors.length(), 0)
  assert_eq(report.findings.length(), 2)
}
