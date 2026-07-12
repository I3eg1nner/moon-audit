///|
pub fn scan_project(root : String, config : Config) -> ScanResult {
  let findings : Array[Finding] = []
  let errors : Array[String] = []
  let mut files_scanned = 0
  let mod_imports = analyze_mod_imports(root)
  walk_packages(root, config, fn(pkg_dir, mbt_files) {
    let pkg_imports = analyze_imports(pkg_dir)
    let imports = merge_imports(mod_imports, pkg_imports)
    for file in mbt_files {
      files_scanned += 1
      let source = @fs.read_file_to_string(file) catch {
        _ => {
          errors.push("Failed to read " + file)
          continue
        }
      }
      let (impls, reports) = @parser.parse_string(source, name=file)
      for report in reports {
        errors.push("Parse error in " + file + ": " + report.to_string())
      }
      run_all_rules(impls, file, source, findings, imports, config)
    }
  })
  { findings: dedup_findings(findings), files_scanned, errors }
}

///|
fn dedup_findings(findings : Array[Finding]) -> Array[Finding] {
  let seen : Map[String, Bool] = {}
  let result : Array[Finding] = []
  for f in findings {
    let key = f.file +
      ":" +
      f.line.to_string() +
      ":" +
      f.column.to_string() +
      ":" +
      rule_id_str(f.rule_id)
    if !seen.contains(key) {
      seen[key] = true
      result.push(f)
    }
  }
  result
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
  let cwe116_id = "CWE-116/replace-escaping"
  if config.is_enabled(cwe116_id) {
    run_cwe116(
      impls,
      file,
      source,
      findings,
      config.get_severity(cwe116_id, cwe116_info().default_severity),
    )
  }
  let cwe094_id = "CWE-94/eval-extern"
  if config.is_enabled(cwe094_id) {
    run_cwe094(
      impls,
      file,
      source,
      findings,
      config.get_severity(cwe094_id, cwe094_info().default_severity),
    )
  }
  if imports.has_cmark {
    let cwe079c_id = "CWE-79/cmark-unsafe"
    if config.is_enabled(cwe079c_id) {
      run_cwe079_cmark(
        impls,
        file,
        source,
        findings,
        config.get_severity(cwe079c_id, cwe079_cmark_info().default_severity),
      )
    }
  }
  if imports.has_rabbita {
    let cwe079i_id = "CWE-79/inner-html"
    if config.is_enabled(cwe079i_id) {
      run_cwe079_inner_html(
        impls,
        file,
        source,
        findings,
        config.get_severity(
          cwe079i_id,
          cwe079_inner_html_info().default_severity,
        ),
      )
    }
  }
  if imports.has_mocket || imports.has_crescent {
    let cwe942_id = "CWE-942/cors-credentials"
    if config.is_enabled(cwe942_id) {
      run_cwe942(
        impls,
        file,
        source,
        findings,
        config.get_severity(cwe942_id, cwe942_info().default_severity),
      )
    }
    let cwe614_id = "CWE-614/cookie-attrs"
    if config.is_enabled(cwe614_id) {
      run_cwe614(
        impls,
        file,
        source,
        findings,
        config.get_severity(cwe614_id, cwe614_info().default_severity),
      )
    }
    let cwe770_id = "CWE-770/no-body-limit"
    if config.is_enabled(cwe770_id) {
      run_cwe770(
        impls,
        file,
        source,
        findings,
        config.get_severity(cwe770_id, cwe770_info().default_severity),
      )
    }
    let cwe346_id = "CWE-346/ws-origin"
    if config.is_enabled(cwe346_id) {
      run_cwe346(
        impls,
        file,
        source,
        findings,
        config.get_severity(cwe346_id, cwe346_info().default_severity),
      )
    }
  }
  let cwe022_id = "CWE-22/path-concat"
  if config.is_enabled(cwe022_id) {
    run_cwe022(
      impls,
      file,
      source,
      findings,
      config.get_severity(cwe022_id, cwe022_info().default_severity),
    )
  }
  let cwe113_id = "CWE-113/crlf-injection"
  if config.is_enabled(cwe113_id) {
    run_cwe113(
      impls,
      file,
      source,
      findings,
      config.get_severity(cwe113_id, cwe113_info().default_severity),
    )
  }
  if imports.has_mocket || imports.has_crescent {
    let cwe079t_id = "CWE-79/template-injection"
    if config.is_enabled(cwe079t_id) {
      run_cwe079_template(
        impls,
        file,
        source,
        findings,
        config.get_severity(cwe079t_id, cwe079_template_info().default_severity),
      )
    }
  }
}

///|
fn walk_packages(
  root : String,
  config : Config,
  callback : (String, Array[String]) -> Unit,
) -> Unit {
  walk_dir(root, config, callback)
}

///|
fn walk_dir(
  dir : String,
  config : Config,
  callback : (String, Array[String]) -> Unit,
) -> Unit {
  let entries = @fs.read_dir(dir) catch { _ => return }
  let mbt_files : Array[String] = []
  let subdirs : Array[String] = []
  for entry in entries {
    let full = @path.Path(dir).join(@path.Path(entry)).0
    if should_exclude(entry, config) {
      continue
    }
    let is_dir = @fs.is_dir(full) catch { _ => false }
    if is_dir {
      subdirs.push(full)
    } else if entry.has_suffix(".mbt") && !entry.has_suffix("_test.mbt") {
      if !should_exclude_file(entry, config) {
        mbt_files.push(full)
      }
    }
  }
  if mbt_files.length() > 0 {
    callback(dir, mbt_files)
  }
  for subdir in subdirs {
    walk_dir(subdir, config, callback)
  }
}

///|
fn should_exclude(name : String, config : Config) -> Bool {
  if name.has_prefix(".") {
    return true
  }
  for pat in config.exclude {
    if name == pat {
      return true
    }
  }
  false
}

///|
fn should_exclude_file(name : String, config : Config) -> Bool {
  for pat in config.exclude {
    if pat.has_prefix("*") {
      let suffix = pat[1:].to_owned()
      if name.has_suffix(suffix) {
        return true
      }
    }
    if name == pat {
      return true
    }
  }
  false
}

///|
pub fn list_all_rules() -> Array[RuleInfo] {
  [
    cwe116_info(),
    cwe079_cmark_info(),
    cwe079_inner_html_info(),
    cwe079_template_info(),
    cwe094_info(),
    cwe113_info(),
    cwe942_info(),
    cwe614_info(),
    cwe770_info(),
    cwe346_info(),
    cwe022_info(),
  ]
}
