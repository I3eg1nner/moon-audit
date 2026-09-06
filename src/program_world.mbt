// T1.1+T1.4: Unified ProgramWorld — the single loading entry for all
// analysis CLIs (scan / ir-stats / call-graph). See docs/ir/ROADMAP-T.md.
//
// Loading pipeline (order matters for behavior equivalence with the
// pre-T1a duplicated loaders):
//   1. module package walk (walk_packages, same exclusions)
//   2. module symbol collection (source ASTs)
//   3. dependency source ingestion (.mooncakes)
//   4. official interface files (.mbti)
//   5. library models (taint-rules.json / .moon-audit.json taint section)
//   6. per-package alias maps (moon.pkg)
//   7. workspace members (moon.work, parsed with the official moon_config)
//
// moon.mod / moon.pkg / moon.work are PARSED with the official
// moonbitlang/parser/moon_config (official syntax + validation reports);
// annotation-level details the official Ast does not expose (import
// aliases) still go through the line-level scanner until the config
// package exports them.

///|
pub(all) struct PkgFiles {
  dir : String
  files : Array[String]
}

///|
pub(all) struct ProgramWorld {
  root : String
  packages : Array[PkgFiles] // module source packages (deps excluded)
  symbols : PkgSymbols // module + deps + .mbti + lib models
  aliases : Map[String, Map[String, String]] // pkg dir -> alias -> pkg path
  imports : Map[String, Array[String]] // pkg dir -> official import paths
  workspace_members : Array[String] // moon.work member dirs (absolute)
  config_reports : Array[String] // official moon_config validation reports
  config : Config
}

///|
pub fn load_program_world(
  root : String,
  config : Config,
  with_symbols? : Bool = true,
) -> ProgramWorld {
  // 1. module package walk — the file-fact source for every CLI
  let packages : Array[PkgFiles] = []
  walk_packages(root, config, fn(pkg_dir, mbt_files) {
    let files : Array[String] = []
    for f in mbt_files {
      files.push(f)
    }
    packages.push({ dir: pkg_dir, files, })
  })
  // 2-5. symbol tables (skippable for consumers that only need file facts,
  // e.g. the scanner today; T1b wires more of the scanner onto symbols)
  let symbols = PkgSymbols::new()
  if with_symbols {
    for pkgf in packages {
      for file in pkgf.files {
        let source = @fs.read_file_to_string(file) catch { _ => continue }
        let (impls, _) = @parser.parse_string(source, name=file)
        collect_symbols(impls.to_array(), symbols)
      }
    }
    collect_dep_symbols(root, symbols)
    collect_mbti_dir(root, symbols)
    let (lib_rs, _) = load_taint_rules(root)
    lib_rs.apply_to_symbols(symbols)
  }
  // 6. per-package alias maps
  let aliases : Map[String, Map[String, String]] = Map([])
  for pkgf in packages {
    aliases[pkgf.dir] = pkg_alias_map(pkgf.dir)
  }
  // 7. workspace members via the official config parser
  let workspace_members : Array[String] = []
  let config_reports : Array[String] = []
  let work_path = @path.Path(root).join(@path.Path("moon.work")).0
  let work_content = @fs.read_file_to_string(work_path) catch { _ => "" }
  if work_content != "" {
    let (ast, reports) = @moon_config.parse_moon_work(work_content)
    for r in reports {
      config_reports.push("moon.work: " + r.to_string())
    }
    collect_workspace_members(ast, root, workspace_members)
  }
  // 6b. official import paths per package (moon_config parse)
  let imports : Map[String, Array[String]] = Map([])
  for pkgf in packages {
    imports[pkgf.dir] = read_pkg_imports(pkgf.dir)
  }
  {
    root,
    packages,
    symbols,
    aliases,
    imports,
    workspace_members,
    config_reports,
    config,
  }
}

// official import paths of one package (moon_config parse + validation)

///|
fn read_pkg_imports(pkg_dir : String) -> Array[String] {
  let result : Array[String] = []
  let pkg_path = @path.Path(pkg_dir).join(@path.Path("moon.pkg")).0
  let content = @fs.read_file_to_string(pkg_path) catch { _ => return result }
  let (ast, _reports) = @moon_config.parse_moon_pkg(content)
  match ast {
    Obj(fields, ..) =>
      for pair in fields {
        if pair.0 == "import" {
          collect_import_paths(pair.1, result)
        }
      }
    _ => ()
  }
  result
}

// moon.work Ast shape: Obj with a "members" field of path strings.
// The official parser returns the generic Ast; interpretation stays here
// so config-syntax changes only affect the official layer.

///|
pub fn collect_workspace_members(
  ast : @moon_config.Ast,
  root : String,
  out : Array[String],
) -> Unit {
  match ast {
    Obj(fields, ..) =>
      for pair in fields {
        if pair.0 == "members" {
          collect_member_paths(pair.1, root, out)
        }
      }
    _ => ()
  }
}

///|
fn collect_member_paths(
  ast : @moon_config.Ast,
  root : String,
  out : Array[String],
) -> Unit {
  match ast {
    Arr(items, ..) =>
      for item in items {
        collect_member_paths(item, root, out)
      }
    Str(path, ..) => {
      let p = if path.has_prefix("/") {
        path
      } else {
        @path.Path(root).join(@path.Path(path)).0
      }
      let is_dir = @fs.is_dir(p) catch { _ => false }
      if is_dir && !out.contains(p) {
        out.push(p)
      }
    }
    _ => ()
  }
}

// Official import-name extraction from a moon.pkg Ast (validation-grade):
// returns the declared import package paths (alias annotations are not in
// the official generic Ast yet; aliases come from pkg_alias_map).

///|
pub fn world_pkg_imports(
  world : ProgramWorld,
  pkg_dir : String,
) -> Array[String] {
  or_empty(world.imports.get(pkg_dir))
}

///|
fn or_empty(v : Array[String]?) -> Array[String] {
  match v {
    Some(arr) => arr
    None => []
  }
}

///|
fn collect_import_paths(ast : @moon_config.Ast, out : Array[String]) -> Unit {
  match ast {
    Arr(items, ..) =>
      for item in items {
        collect_import_paths(item, out)
      }
    Str(p, ..) => if !out.contains(p) { out.push(p) }
    _ => ()
  }
}
