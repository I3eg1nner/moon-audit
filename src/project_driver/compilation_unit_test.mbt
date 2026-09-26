///|
test "compiler identities preserve source-root and three roles for one file" {
  let root = @project_driver.absolute(".")
  let command = "moonc check src/lib/a.mbt -pkg fixture/app/lib -pkg-sources fixture/app/lib:src/lib -target native -workspace-path ."
  let plan = command +
    "\n" +
    command +
    " -whitebox-test\n" +
    "moonc check src/lib/a_test.mbt -doctest-only src/lib/a.mbt -include-doctests -pkg fixture/app/lib_blackbox_test -pkg-sources fixture/app/lib_blackbox_test:src/lib -target native -blackbox-test"
  let units = @project_driver.compilation_units(
    plan, root, "fixture/app", "native",
  ).unwrap()
  assert_eq(units.length(), 3)
  let production = units.filter(fn(unit) { unit.role is Production })[0]
  assert_eq(production.package_name, "fixture/app/lib")
  assert_eq(production.package_root, root + "/src/lib")
  assert_eq(production.inputs, [
    { path: root + "/src/lib/a.mbt", mode: @project_driver.Source, },
  ])
  let blackbox = units.filter(fn(unit) { unit.role is BlackboxTest })[0]
  assert_true(
    blackbox.inputs.contains({
      path: root + "/src/lib/a.mbt",
      mode: @project_driver.DoctestOnly,
    }),
  )
  assert_true(production.id != blackbox.id)
  assert_eq(
    @project_driver.compilation_units(
      command + "\n" + command,
      root,
      "fixture/app",
      "native",
    ).unwrap(),
    [production],
  )
}

///|
test "compiler role is a flag not a package suffix and option values are not input files" {
  let root = @project_driver.absolute(".")
  let plan = "moonc check real.mbt -w -a -o fake.mbt -pkg fixture/app_blackbox_test -pkg-sources 'fixture/app_blackbox_test:" +
    root +
    "' -target native"
  let result = @project_driver.compilation_units(
    plan, root, "fixture/app_blackbox_test", "native",
  )
  guard result is Ok(units) else {
    match result {
      Err(reason) => fail(reason)
      _ => fail("unreachable")
    }
  }
  assert_eq(units[0].role, @project_driver.Production)
  assert_eq(units[0].inputs, [
    { path: root + "/real.mbt", mode: @project_driver.Source, },
  ])
}

///|
test "unknown conflicting or rewriting compiler contexts never imply production" {
  let root = @project_driver.absolute(".")
  let command = "moonc check src/a.mbt -pkg fixture/app -pkg-sources fixture/app:src -target native"
  for
    suffix in [
      " -new-test-role", " -single-file", " -patch-file patch.json", " -replace-name src/a.mbt",
      " -replace-content abc", " -cfg feature=true", " -check-mi interface.mi", " -ignore-import-declaration",
      " -target js", " -pkg fixture/other", " -whitebox-test -blackbox-test", " -doctest-only src/a.mbt",
      " -include-doctests", " -pkg-sources fixture/app:src", " -workspace-path elsewhere",
      " -all-pkgs",
    ] {
    assert_true(
      @project_driver.compilation_units(
        command + suffix,
        root,
        "fixture/app",
        "native",
      )
      is Err(_),
    )
  }
  assert_true(
    @project_driver.compilation_units(command, root, "fixture/app", "js")
    is Err(_),
  )
  assert_true(
    @project_driver.compilation_units(
      command + "\n" + command.replace_all(old="src/a.mbt", new="src/b.mbt"),
      root,
      "fixture/app",
      "native",
    )
    is Err(_),
  )
}

///|
test "source may not belong to two production package identities" {
  let root = @project_driver.absolute(".")
  let common = "moonc check src/a.mbt -target native"
  let plan = common +
    " -pkg fixture/app/a -pkg-sources fixture/app/a:src\n" +
    common +
    " -pkg fixture/app/b -pkg-sources fixture/app/b:src"
  assert_true(
    @project_driver.compilation_units(plan, root, "fixture/app", "native")
    is Err(_),
  )
}

///|
test "package kinds are validated and part of the compilation identity" {
  let root = @project_driver.absolute(".")
  let command = "moonc check a.mbt -pkg fixture/app -pkg-sources fixture/app:. -target native"
  let legacy = @project_driver.compilation_units(
      command, root, "fixture/app", "native",
    ).unwrap()[0]
  assert_eq(legacy.package_kind, "library")
  for kind in ["library", "executable", "foreign_library"] {
    let unit = @project_driver.compilation_units(
        command + " -pkg-type " + kind,
        root,
        "fixture/app",
        "native",
      ).unwrap()[0]
    assert_eq(unit.package_kind, kind)
    assert_eq(unit.id == legacy.id, kind == "library")
  }
  for
    suffix in [
      " -pkg-type future", " -pkg-type library -is-main", " -pkg-type foreign_library -is-main",
    ] {
    assert_true(
      @project_driver.compilation_units(
        command + suffix,
        root,
        "fixture/app",
        "native",
      )
      is Err(_),
    )
  }
  assert_eq(
    @project_driver.compilation_units(
      command + " -is-main",
      root,
      "fixture/app",
      "native",
    ).unwrap()[0].package_kind,
    "executable",
  )
}

///|
test "dependency source rewriting invalidates source fingerprint model context" {
  let root = @project_driver.absolute(".")
  let production = "moonc check a.mbt -pkg fixture/app -pkg-sources fixture/app:. -target native"
  let dependency = "moonc check .mooncakes/vendor/lib/a.mbt -pkg vendor/lib -pkg-sources vendor/lib:.mooncakes/vendor/lib -target native"
  for
    suffix in [
      " -patch-file patch.json", " -replace-content abc", " -replace-name a.mbt",
      " -cfg feature=true", " -check-mi interface.mi", " -single-file", " -ignore-import-declaration",
      " -future-flag", " -pkg-type future", " -is-main -pkg-type library", " -whitebox-test -blackbox-test",
    ] {
    assert_true(
      @project_driver.compilation_units(
        production + "\n" + dependency + suffix,
        root,
        "fixture/app",
        "native",
      )
      is Err(_),
    )
  }
}
