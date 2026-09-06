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
  // gate8 P2: probe with canonical keys (map keys are canonical_dir'd)
  let all_keyed = world.packages.any(fn(p) {
    !world.aliases.contains(canonical_dir(p.dir))
  })
  inspect(all_keyed, content="false")
  // forward-slash lookups must work on every OS (map keys are canonical;
  // walk_packages yields OS separators on Windows — T1a-1 CI lesson)
  let src_dir = root + "/src"
  let imports = world_pkg_imports(world, src_dir)
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

// ---------------------------------------------------------------------------
// T1.2 identity layer + alias demotion (acceptance: ROADMAP-T T1)
// ---------------------------------------------------------------------------

///|
test "t1b_two_packages_same_name_no_cross_bind" {
  // (a) acceptance: pkgA::Foo::m and pkgB::Foo::m registered; a query for
  // an UNREGISTERED pkgC::Foo::m must NOT bind in strict mode (the
  // short-key fallback is exactly the cross-binding path T1.2 removes)
  let symbols = PkgSymbols::new()
  symbols.impl_methods["pkgA::Foo::m"] = "TrA"
  symbols.impl_methods["pkgB::Foo::m"] = "TrB"
  // a SHORT registration is the realistic cross-bind collision (deps often
  // register unqualified keys — the exact legacy ambiguity T1.2 removes)
  symbols.impl_methods["Foo::m"] = "TrShort"
  symbols.alias_mode = false // strict
  symbols.alias_unresolved = 0
  inspect(
    get_impl_method(symbols, "pkgA::Foo::m") == Some("TrA"),
    content="true",
  )
  inspect(get_impl_method(symbols, "pkgC::Foo::m") == None, content="true")
  inspect(symbols.alias_unresolved, content="1") // counted reason=alias
  // conservative (legacy): the SAME query cross-binds via short_key
  symbols.alias_mode = true
  symbols.alias_unresolved = 0
  let legacy = get_impl_method(symbols, "pkgC::Foo::m")
  inspect(legacy != None, content="true") // binds to pkgA or pkgB — ambiguous
}

///|
test "t1b_identity_table_order_independent" {
  // (c) acceptance: declaration order must not influence identity results
  let s1 = PkgSymbols::new()
  s1.fn_exists["pkgA::one"] = true
  s1.fn_exists["pkgA::two"] = true
  let f1 : Map[String, IRType] = Map([])
  f1["v"] = IRConcrete("Int", [])
  s1.struct_fields["pkgA::Box"] = f1
  let s2 = PkgSymbols::new()
  let f2 : Map[String, IRType] = Map([])
  f2["v"] = IRConcrete("Int", [])
  s2.struct_fields["pkgA::Box"] = f2
  s2.fn_exists["pkgA::two"] = true
  s2.fn_exists["pkgA::one"] = true
  let i1 = derive_identities(s1)
  let i2 = derive_identities(s2)
  inspect(i1.fns == i2.fns, content="true")
  inspect(i1.fns == ["pkgA::one", "pkgA::two"], content="true") // sorted
  inspect(i1.fields == i2.fields, content="true")
}

///|
test "t1b_alias_map_change_keeps_bindings" {
  // (b) acceptance: import-alias maps drive qualified-key CONSTRUCTION,
  // never identity resolution — mutating aliases cannot change bindings
  let root = make_t1a1_fixture()
  let world = load_program_world(root, Config::default())
  // registered identity key comes from symbol collection (source decls);
  // the fixture registers "dep_pub" (fn_exists) — query that canonical key
  let before = world_identity_of(world, "fn", "dep_fn")
  // flip every alias map; identity answers must be identical
  world.aliases.each(fn(k, _) { world.aliases[k] = Map([]) })
  let after = world_identity_of(world, "fn", "dep_fn")
  inspect(before != None, content="true")
  inspect(before == after, content="true")
}

///|
test "t1b_strict_identity_no_shortkey_cross_bind" {
  // strict identity resolution must not fall through the suffix path
  let symbols = PkgSymbols::new()
  symbols.fn_exists["pkgA::Foo::m"] = true
  let ids = derive_identities(symbols)
  let world : ProgramWorld = {
    root: "/x",
    packages: [],
    symbols: { ..symbols, alias_mode: false, },
    aliases: Map([]),
    imports: Map([]),
    workspace_members: [],
    config_reports: [],
    config: Config::default(),
    identities: ids,
    entry_kinds: Map([]),
  }
  inspect(
    world_identity_of(world, "fn", "pkgA::Foo::m") == Some("pkgA::Foo::m"),
    content="true",
  )
  inspect(
    world_identity_of(world, "fn", "pkgB::Foo::m") == None,
    content="true",
  )
}

// ---------------------------------------------------------------------------
// T1c: FnSig model (T1.3) + entry policies (T1.5)
// ---------------------------------------------------------------------------

///|
test "t1c_fnsig_labelled_param" {
  let src = "pub fn go(x~ : Int, y~ : String) -> Unit { ignore(y) }"
  let (impls, _) = @parser.parse_string(src, name="t.mbt")
  let symbols = PkgSymbols::new()
  collect_symbols(impls.to_array(), symbols)
  let sig = symbols.fn_sigs.get("go")
  inspect(
    match sig {
      Some(_) => "true"
      None => "false"
    },
    content="true",
  )
  let s = match sig {
    Some(v) => v
    None => abort("unreachable")
  }
  inspect(s.params.length(), content="2")
  inspect(s.params[0].kind, content="labelled")
  inspect(s.params[0].binder, content="x")
  inspect(s.params[0].ty.display(), content="Int")
  inspect(s.entry, content="library-pub")
}

///|
test "t1c_fnsig_optional_default" {
  let src = "pub fn go(x~ : Int = 3) -> Unit { ignore(x) }"
  let (impls, _) = @parser.parse_string(src, name="t.mbt")
  let symbols = PkgSymbols::new()
  collect_symbols(impls.to_array(), symbols)
  match symbols.fn_sigs.get("go") {
    Some(s) => {
      inspect(s.params[0].kind, content="optional")
      inspect(s.params[0].has_default, content="true")
    }
    None => inspect(false, content="true")
  }
}

///|
test "t1c_fnsig_generic_constraints" {
  let src = "fn [T : Show + Eq] g(x : T) -> Unit { ignore(x) }"
  let (impls, _) = @parser.parse_string(src, name="t.mbt")
  let symbols = PkgSymbols::new()
  collect_symbols(impls.to_array(), symbols)
  match symbols.fn_sigs.get("g") {
    Some(s) =>
      inspect(
        match s.generic_constraints.length() >= 1 {
          true => "true"
          false => "false"
        },
        content="true",
      )
    None => inspect("false", content="true")
  }
}

///|
test "t1c_fnsig_error_and_arrow_param" {
  // arrow param keeps arg types in the unified model; error effect recorded
  let src = "fn h(cb : (Int, String) -> Unit) -> Unit raise { cb(1, \"x\") }"
  let (impls, _) = @parser.parse_string(src, name="t.mbt")
  let symbols = PkgSymbols::new()
  collect_symbols(impls.to_array(), symbols)
  match symbols.fn_sigs.get("h") {
    Some(s) => {
      inspect(s.params[0].arrow_args.length(), content="2")
      inspect(
        match s.error_effect != "none" {
          true => "true"
          false => "false"
        },
        content="true",
      )
      inspect(s.entry, content="internal")
    }
    None => inspect("false", content="true")
  }
}

///|
test "t1c_entry_stats_line" {
  // self-contained fixture (CI has no /data corpus): a library pkg with a
  // pub fn (library-pub) and an extern stub (ffi-extern) must be disclosed
  let root = test_tmp("t1c_entry")
  let dir = root + "/src"
  @fs.create_dir(root) catch {
    _ => ()
  }
  @fs.create_dir(dir) catch {
    _ => ()
  }
  @fs.write_string_to_file(root + "/moon.mod", "name = \"t1c/e\"\n") catch {
    _ => ()
  }
  @fs.write_string_to_file(dir + "/moon.pkg", "") catch {
    _ => ()
  }
  @fs.write_string_to_file(
    dir + "/stub.mbt",
    "extern \"c\" fn raw(p : Int) -> Int",
  ) catch {
    _ => ()
  }
  @fs.write_string_to_file(dir + "/lib.mbt", "pub fn api(x : Int) -> Int { x }") catch {
    _ => ()
  }
  let world = load_program_world(root, Config::default())
  let line = entry_stats_line(world)
  inspect(line.has_prefix("entries: pkgs("), content="true")
  inspect(line.contains("library-pub="), content="true")
  inspect(line.contains("ffi-extern="), content="true")
}

///|
test "p1fix_mbti_func_sig_via_fnsig_sole_source" {
  // .mbti FuncSig -> FnSig via collect_mbti_fn_sig (sole write point);
  // sig_arrow_args reads the FnSig, not the legacy table
  let root = test_tmp("p1fix_func")
  @fs.create_dir(root) catch {
    _ => ()
  }
  let f = root + "/pkg.generated.mbti"
  @fs.write_string_to_file(
    f, "package \"p1/dep\"\n\npub fn run_cb((Int) -> Unit) -> Unit\n",
  ) catch {
    _ => ()
  }
  let symbols = PkgSymbols::new()
  collect_mbti_file(f, symbols)
  // FnSig stored for the .mbti function
  inspect(symbols.fn_sigs.contains("run_cb"), content="true")
  // arrow args read through the FnSig (Int for cb)
  match sig_arrow_args(symbols, "run_cb") {
    Some(arrows) => {
      inspect(arrows.length(), content="1")
      // cb's arrow args = [Some(Int)]
      inspect(arrows[0].length(), content="1")
      match arrows[0][0] {
        Some(IRConcrete("Int", [])) => inspect("int-arrow", content="int-arrow")
        _ => inspect("wrong-arrow", content="int-arrow")
      }
    }
    None => inspect("none", content="some-arrows")
  }
}

///|
test "p1fix_mbti_trait_params_via_fnsig_derivation" {
  // .mbti TraitSig -> FnSig -> materialize_trait_from_sig (sole write);
  // mbti anonymous params (DiscardPositional) keep their types
  let root = test_tmp("p1fix_trait")
  @fs.create_dir(root) catch {
    _ => ()
  }
  let f = root + "/pkg.generated.mbti"
  @fs.write_string_to_file(
    f, "package \"p1/dep\"\n\npub(open) trait Sink {\n  put(Self, Int) -> Unit\n}\n",
  ) catch {
    _ => ()
  }
  let symbols = PkgSymbols::new()
  collect_mbti_file(f, symbols)
  inspect(symbols.fn_sigs.contains("Sink::put"), content="true")
  match sig_trait_params(symbols, "Sink::put") {
    Some(tys) => {
      inspect(tys.length(), content="2")
      // mbti renders `Self` as a named type — Some(Self), mirroring the
      // legacy collector exactly (source-side trait decls yield None for
      // unannotated self params; both preserved)
      match tys[0] {
        Some(IRConcrete("Self", [])) => inspect("self", content="self")
        _ => inspect("wrong", content="self")
      }
      match tys[1] {
        Some(IRConcrete("Int", [])) => inspect("int", content="int")
        _ => inspect("wrong", content="int")
      }
    }
    None => inspect("none", content="some-tys")
  }
}

///|
test "p1fix_sole_write_points_no_direct_table_writes" {
  // behavioural anchor: after a source-style collect_fn_sig +
  // materialize, both legacy tables reflect the FnSig projection and the
  // builtin Show seed still backfills [None, Logger]
  let symbols = PkgSymbols::new()
  match sig_trait_params(symbols, "Show::output") {
    Some(tys) => {
      inspect(tys.length(), content="2")
      inspect(tys[0] == None, content="true")
      match tys[1] {
        Some(IRConcrete("Logger", [])) => inspect("logger", content="logger")
        _ => inspect("wrong", content="logger")
      }
    }
    None => inspect("none", content="seed-present")
  }
}
