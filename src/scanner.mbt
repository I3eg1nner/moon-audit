// Finite syntax-pattern scanner. No type reconstruction or interprocedural solver.

///|
pub fn scan_project(
  root : String,
  config : Config,
  compiler_files? : Array[String]? = None,
) -> ScanResult {
  let findings : Array[Finding] = []
  let errors : Array[String] = []
  let file_coverage : Array[FileCoverage] = []
  let mut files_scanned = 0
  let mut files_selected = 0
  let mut files_parsed = 0
  let incremental = config.incremental || !config.changed_files.is_empty()
  let changed : Map[String, Bool] = Map([])
  for file in config.changed_files {
    let p = @path.Path(canonical_dir(file))
    let absolute = if p.is_absolute() {
      p.resolve()
    } else {
      @path.Path(root).join(p).resolve()
    }
    changed[canonical_dir(absolute.0)] = true
  }
  for name in ["moon.mod", "moon.mod.json"] {
    let file = @path.Path(root).join(@path.Path(name)).0
    if @fs.path_exists(file) && !(@fs.is_file(file) catch { _ => false }) {
      errors.push("Not a readable regular module file: " + file)
    }
  }
  let mod_imports = analyze_mod_imports(root)
  let package_imports : Map[String, ImportContext] = Map([])
  let mut parse_failures = 0
  walk_pattern_files(root, config, errors, 0, fn(dir, file) {
    if compiler_files is Some(files) &&
      !files.contains(canonical_dir(@path.Path(file).resolve().0)) {
      file_coverage.push({
        path: file,
        status: "skipped",
        reason: "not_in_compiler_plan",
        rules: [],
      })
      return
    }
    if incremental &&
      !changed.contains(canonical_dir(@path.Path(file).resolve().0)) {
      file_coverage.push({
        path: file,
        status: "skipped",
        reason: "not_in_changed_files",
        rules: [],
      })
      return
    }
    files_selected += 1
    if !(@fs.is_file(file) catch { _ => false }) {
      errors.push("Not a readable regular source file: " + file)
      file_coverage.push({
        path: file,
        status: "read_failed",
        reason: "not_regular_file",
        rules: [],
      })
      return
    }
    let source = read_regular_text(file) catch {
      _ => {
        errors.push("Failed to read " + file)
        file_coverage.push({
          path: file,
          status: "read_failed",
          reason: "read_error",
          rules: [],
        })
        return
      }
    }
    files_scanned += 1
    let (impls, reports) = parse_source(source, name=file)
    if !reports.is_empty() {
      parse_failures += 1
      file_coverage.push({
        path: file,
        status: "parse_failed",
        reason: "parser_rejected",
        rules: [],
      })
      for report in reports {
        errors.push("Parse error in " + file + ": " + Show::to_string(report))
      }
      return
    }
    files_parsed += 1
    let pkg_imports = match package_imports.get(dir) {
      Some(imports) => imports
      None => {
        let (imports, import_error) = analyze_imports_checked(dir)
        package_imports[dir] = imports
        match import_error {
          Some(message) => errors.push(message)
          None => ()
        }
        imports
      }
    }
    // Module dependencies only make packages available. Rule gates require
    // imports declared by this package; the module name still marks stdlib.
    let imports = {
      ..pkg_imports,
      is_stdlib: mod_imports.is_stdlib || pkg_imports.is_stdlib,
    }
    let rules = rule_coverage_for_file(config, imports)
    file_coverage.push({ path: file, status: "parsed", reason: "", rules, })
    run_all_rules(impls, file, source, findings, imports, config)
  })
  {
    findings: dedup_findings(findings),
    project_verification: None,
    semantic_analysis: None,
    files_scanned,
    files_selected,
    files_parsed,
    errors,
    file_coverage,
    configured_excludes: config.exclude,
    incremental,
    analysis_scope: "analyzer=moon-audit " +
    ANALYZER_VERSION +
    " (moonbitlang/parser " +
    PARSER_SPEC_VERSION +
    "); engine=syntax-pattern; interprocedural=false; type-resolution=false; sanitizer-resolution=false; cache=none; excludes=[" +
    config.exclude.join(",") +
    "]; implicit-excludes=[dotdirs,_build,*_test.mbt,*_wbtest.mbt]; selected=" +
    files_selected.to_string() +
    "; parsed=" +
    files_parsed.to_string() +
    "; parse-failures=" +
    parse_failures.to_string() +
    "; incremental=" +
    incremental.to_string() +
    "; unanalyzed-is-not-safe",
  }
}

///|
fn walk_pattern_files(
  dir : String,
  config : Config,
  errors : Array[String],
  depth : Int,
  visit : (String, String) -> Unit,
) -> Unit {
  if depth > 64 {
    errors.push("Directory traversal limit: " + dir)
    return
  }
  let entries = @fs.read_dir(dir) catch {
    _ => {
      errors.push("Failed to read directory " + dir)
      return
    }
  }
  for name in entries {
    if name.has_prefix(".") || name == "_build" || config.exclude.contains(name) {
      continue
    }
    let full = @path.Path(dir).join(@path.Path(name)).0
    let is_dir = @fs.is_dir(full) catch {
      _ => {
        errors.push("Failed to inspect " + full)
        continue
      }
    }
    if is_dir {
      walk_pattern_files(full, config, errors, depth + 1, visit)
    } else if name.has_suffix(".mbt") &&
      !name.has_suffix("_test.mbt") &&
      !name.has_suffix("_wbtest.mbt") {
      let excluded = config.exclude.any(fn(pattern) {
        pattern.has_prefix("*") && name.has_suffix(pattern[1:].to_owned())
      })
      if !excluded {
        visit(dir, full)
      }
    }
  }
}

///|
pub fn canonical_dir(dir : String) -> String {
  dir.replace(old="\\", new="/")
}

///|
pub fn parse_changed_files(content : String) -> Array[String] {
  let files : Array[String] = []
  for line in content.split("\n") {
    let file = line.to_owned().trim().to_owned()
    if file.has_suffix(".mbt") {
      files.push(file)
    }
  }
  files
}

///|
fn dedup_findings(findings : Array[Finding]) -> Array[Finding] {
  // Dedup key includes the line: two call sites with identical snippet text
  // at DIFFERENT lines are distinct vulnerabilities and must both report
  // (round-5 gate: c9 original+control collapsed to one alert). The
  // Finding.fingerprint itself stays line-independent — SARIF
  // partialFingerprints and the baseline diff keep their stable identity.
  let seen : Map[String, Bool] = Map([])
  let result : Array[Finding] = []
  for f in findings {
    let key = f.file +
      ":" +
      f.fingerprint +
      ":" +
      rule_id_str(f.rule_id) +
      ":" +
      f.line.to_string() +
      ":" +
      f.column.to_string()
    if !seen.contains(key) {
      seen[key] = true
      result.push(f)
    }
  }
  result
}

///|
fn rule_status(config : Config, imports : ImportContext, id : String) -> String {
  if !config.is_enabled(id) {
    return "disabled"
  }
  let applicable = match rule_requirement(id) {
    "cmark_import" => imports.has_cmark
    "rabbita_import" => imports.has_rabbita
    "mocket_or_crescent_import" => imports.has_mocket || imports.has_crescent
    "crescent_import" => imports.has_crescent
    "non_stdlib_module" => !imports.is_stdlib
    _ => true
  }
  if applicable {
    "evaluated"
  } else {
    "gated_out"
  }
}

///|
fn rule_coverage_for_file(
  config : Config,
  imports : ImportContext,
) -> Array[RuleCoverage] {
  let coverage : Array[RuleCoverage] = []
  for rule in list_all_rules() {
    let id = rule_id_str(rule.id)
    let status = rule_status(config, imports, id)
    let reason = match status {
      "disabled" => "rule_disabled"
      "gated_out" =>
        if rule_requirement(id) == "non_stdlib_module" {
          "stdlib_module_name_hint"
        } else {
          rule_requirement(id) + "_hint_absent"
        }
      _ => ""
    }
    coverage.push({ id, status, reason, })
  }
  coverage
}

///|
fn run_all_rules(
  impls : @list.List[@syntax.Impl],
  file : String,
  source : String,
  findings : Array[Finding],
  imports : ImportContext,
  config : Config,
) -> Unit {
  for entry in rule_registry() {
    let id = rule_id_str(entry.info.id)
    if rule_status(config, imports, id) == "evaluated" {
      (entry.run)(
        impls,
        file,
        source,
        findings,
        config.get_severity(id, entry.info.default_severity),
      )
    }
  }
}

///|
pub fn list_all_rules() -> Array[RuleInfo] {
  rule_registry().map(entry => entry.info)
}

///|
pub fn excluded_by_policy(
  file : String,
  root : String,
  config : Config,
) -> Bool {
  let relative = @path.Path(file).relative(base=@path.Path(root)).0.replace(
    old="\\",
    new="/",
  )
  let parts = relative.split("/").to_array()
  if parts.any(fn(part) {
      part.has_prefix(".") ||
      part == "_build" ||
      config.exclude.contains(part.to_owned())
    }) {
    return true
  }
  let name = parts.last().unwrap_or("").to_owned()
  name.has_suffix("_test.mbt") ||
  name.has_suffix("_wbtest.mbt") ||
  config.exclude.any(fn(pattern) {
    pattern.has_prefix("*") && name.has_suffix(pattern[1:].to_owned())
  })
}
