// T1a-1: ProgramWorld data-layer tests (self-contained fixture; see ROADMAP-T T1.1/T1.4)

///|
fn make_t1a1_fixture() -> String {
  // /tmp/t1a1_fixture (or relative fallback): a minimal module + one dep + one .mbti
  let root = test_tmp("t1a1_fixture")
  // create_dir is NOT recursive: build the chain level by level
  @fs.create_dir(root) catch {
    _ => ()
  }
  let mut cur = root
  for seg in ["/.mooncakes", "/fixture", "/dep"] {
    cur = cur + seg
    @fs.create_dir(cur) catch {
      _ => ()
    }
  }
  @fs.create_dir(root + "/src") catch {
    _ => ()
  }
  let src = root + "/src"
  let dep = cur
  @fs.write_string_to_file(
    root + "/moon.mod",
    "name = \"fixture/app\"\nversion = \"0.1.0\"\n",
  ) catch {
    _ => ()
  }
  @fs.write_string_to_file(src + "/moon.pkg", "import { \"fixture/dep\" }") catch {
    _ => ()
  }
  @fs.write_string_to_file(
    src + "/lib.mbt",
    "pub fn app_fn(x : Int) -> Int { x + 1 }",
  ) catch {
    _ => ()
  }
  @fs.write_string_to_file(
    dep + "/dep.mbt",
    "pub fn dep_fn(y : Int) -> Int { y * 2 }",
  ) catch {
    _ => ()
  }
  @fs.write_string_to_file(
    dep + "/pkg.generated.mbti",
    "package \"fixture/dep\"\n\npub fn ifn(String) -> String\n",
  ) catch {
    _ => ()
  }
  root
}

///|
test "t1a1_load_module_packages" {
  let root = make_t1a1_fixture()
  let world = load_program_world(root, Config::default())
  inspect(world.packages.length() >= 1, content="true")
  let has_lib = world.packages.any(fn(p) {
    p.files.any(fn(f) { f.has_suffix("lib.mbt") })
  })
  inspect(has_lib, content="true")
  // .mooncakes is excluded from module packages
  let no_dep = world.packages.any(fn(p) { p.dir.has_suffix(".mooncakes") })
  inspect(no_dep, content="false")
}

///|
test "t1a1_symbols_from_module_deps_and_mbti" {
  let root = make_t1a1_fixture()
  let world = load_program_world(root, Config::default())
  // module source symbols
  inspect(world.symbols.fn_exists.contains("app_fn"), content="true")
  // dependency source ingestion
  inspect(world.symbols.fn_exists.contains("dep_fn"), content="true")
  // official interface files
  inspect(world.symbols.fn_exists.contains("ifn"), content="true")
}

///|
test "t1a1_alias_map_and_official_imports" {
  let root = make_t1a1_fixture()
  let world = load_program_world(root, Config::default())
  // every module package gets an alias-map entry (may be empty)
  let all_keyed = world.packages.any(fn(p) { !world.aliases.contains(p.dir) })
  inspect(all_keyed, content="false")
  // official import paths parsed from moon.pkg
  let src_dir = root + "/src"
  let imports = world_pkg_imports(world, src_dir)
  // CI probe (windows-only failure): dump what the loader actually saw
  let pkg_path = src_dir + "/moon.pkg"
  let content = @fs.read_file_to_string(pkg_path) catch { _ => "<unreadable>" }
  println("[t1a1-probe] pkg content len=" + content.length().to_string())
  println(
    "[t1a1-probe] world.imports has src_dir: " +
    world.imports.contains(src_dir).to_string(),
  )
  for p in world.packages {
    println("[t1a1-probe] pkg dir=" + p.dir)
  }
  inspect(imports.length() >= 1, content="true")
  let has_dep = imports.any(fn(i) { i == "fixture/dep" })
  inspect(has_dep, content="true")
}

///|
test "t1a1_workspace_and_reports_wellformed" {
  let root = make_t1a1_fixture() // no moon.work in fixture
  let world = load_program_world(root, Config::default())
  inspect(world.workspace_members.length(), content="0")
  inspect(world.config_reports.length(), content="0")
  // with_symbols=false keeps file facts but skips symbol tables
  let lite = load_program_world(root, Config::default(), with_symbols=false)
  inspect(lite.packages.length() >= 1, content="true")
  inspect(lite.symbols.fn_exists.length(), content="0")
}
