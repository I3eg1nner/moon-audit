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
pub(all) struct WorldIdentities {
  // T1.2: fully-qualified identity registry derived from the symbol tables
  // (source of truth unchanged; derivation is ordered/deduped)
  fns : Array[String] // "pkgpath::fn" / "Type::method" as registered
  types : Array[String]
  traits : Array[String]
  fields : Array[String]
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
  identities : WorldIdentities // T1.2 derived registry (sorted, deduped)
}

///|
pub fn load_program_world(
  root : String,
  config : Config,
  with_symbols? : Bool = true,
  conservative_alias? : Bool = false, // T1.2: CLI default is STRICT
) -> ProgramWorld {
  // T1.2 alias policy lands on the shared symbol table; PkgSymbols::new()
  // keeps conservative=true so direct unit-test constructors are unchanged

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
    symbols.alias_mode = conservative_alias
  }
  // 6. per-package alias maps
  let aliases : Map[String, Map[String, String]] = Map([])
  for pkgf in packages {
    aliases[canonical_dir(pkgf.dir)] = pkg_alias_map(pkgf.dir)
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
    imports[canonical_dir(pkgf.dir)] = read_pkg_imports(pkgf.dir)
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
    identities: derive_identities(symbols),
  }
}

// T1.2: derive the identity registry from the symbol tables.
// Keys registered by symbol collection become canonical identities;
// the registry is sorted and deduped so declaration order cannot
// influence lookup results (acceptance T1-(c)).

///|
pub fn derive_identities(symbols : PkgSymbols) -> WorldIdentities {
  let fns = identity_keys(symbols.fn_exists)
  let types = identity_keys_of(symbols.struct_fields)
  let traits = identity_keys(symbols.impl_methods)
  let fields : Array[String] = []
  symbols.struct_fields.each(fn(tyname, fields_map) {
    fields_map.each(fn(fname, _) { fields.push(tyname + "." + fname) })
  })
  sort_dedup(fields)
  { fns, types, traits, fields, }
}

///|
fn[V] identity_keys(m : Map[String, V]) -> Array[String] {
  let arr : Array[String] = []
  m.each(fn(k, _) { arr.push(k) })
  sort_dedup(arr)
  arr
}

///|
fn identity_keys_of(m : Map[String, Map[String, IRType]]) -> Array[String] {
  let arr : Array[String] = []
  m.each(fn(k, _) { arr.push(k) })
  sort_dedup(arr)
  arr
}

///|
fn sort_dedup(arr : Array[String]) -> Unit {
  arr.sort_by(fn(a, b) { a.compare(b) })
  let mut i = 1
  while i < arr.length() {
    if arr[i] == arr[i - 1] {
      let _ = arr.remove(i)
    } else {
      i += 1
    }
  }
}

// identity resolution: exact key -> the registered identity; strict mode
// NEVER resolves through the short-key fallback (that path is exactly the
// cross-binding risk T1.2 removes). Returns None in strict mode for
// keys that only the fallback could satisfy.

///|
pub fn world_identity_of(
  world : ProgramWorld,
  kind : String,
  key : String,
) -> String? {
  let table = match kind {
    "fn" => world.identities.fns
    "type" => world.identities.types
    "trait" => world.identities.traits
    "field" => world.identities.fields
    _ => []
  }
  let mut idx : String? = None
  for k in table {
    if k == key {
      idx = Some(k)
      break
    }
  }
  match idx {
    Some(k) => Some(k)
    None =>
      if world.symbols.alias_mode {
        // conservative: resolve via short-key suffix onto a registered id
        let sk = short_key(key)
        let mut hit : String? = None
        for k in table {
          if short_key(k) == sk {
            hit = Some(k)
            break
          }
        }
        hit
      } else {
        None // strict: no cross-binding through the fallback
      }
  }
}

// official import paths of one package (moon_config parse + validation)

// map keys are canonical (forward-slash) so lookups are OS-independent

///|
pub fn canonical_dir(dir : String) -> String {
  dir.replace(old="\\", new="/")
}

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
  or_empty(world.imports.get(canonical_dir(pkg_dir)))
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
