// Baseline file support: generate and filter known finding occurrences.
// File-scoped records suppress one occurrence each; line moves keep identity.
// Legacy records without files retain their global wildcard behavior.

///|
pub fn generate_baseline(
  findings : Array[Finding],
  root? : String = "",
) -> String {
  let entries : Array[Json] = findings.map(fn(f) {
    let entry : Json = {
      "rule_id": Json::string(rule_id_str(f.rule_id)),
      "fingerprint": Json::string(f.fingerprint),
      "file": Json::string(baseline_path(f.file, root)),
      "line": Json::number(f.line.to_double()),
      "message": Json::string(f.message),
    }
    if root != "" {
      match entry {
        Object(fields) => fields["path_scope"] = Json::string("project")
        _ => ()
      }
    }
    entry
  })
  Json::array(entries).stringify(indent=2) + "\n"
}

///|
pub fn load_baseline(path : String) -> Map[String, Bool] {
  let keys : Map[String, Bool] = Map([])
  let occurrences : Map[String, Int] = Map([])
  let content = @fs.read_file_to_string(path) catch { _ => return keys }
  let json = @json.parse(content) catch { _ => return keys }
  match json {
    Array(arr) =>
      for item in arr {
        match item {
          Object(obj) => {
            let rule_id = match obj.get("rule_id") {
              Some(String(s)) => s
              _ => ""
            }
            let fingerprint = match obj.get("fingerprint") {
              Some(String(s)) => s
              _ => ""
            }
            if rule_id.length() > 0 && fingerprint.length() > 0 {
              let project_scoped = match obj.get("path_scope") {
                Some(String("project")) => true
                _ => false
              }
              match obj.get("file") {
                Some(String(file)) if file.length() > 0 => {
                  let key = if project_scoped {
                    baseline_project_file_key(rule_id, fingerprint, file)
                  } else {
                    baseline_file_key(rule_id, fingerprint, file)
                  }
                  let count = match occurrences.get(key) {
                    Some(n) => n
                    None => 0
                  }
                  keys[baseline_occurrence_key(key, count)] = true
                  occurrences[key] = count + 1
                }
                // Legacy entries without a file retain their explicit global scope.
                _ =>
                  if !project_scoped {
                    keys[rule_id + ":" + fingerprint] = true
                  }
              }
            }
          }
          _ => ()
        }
      }
    _ => ()
  }
  keys
}

///|
pub fn filter_baseline(
  findings : Array[Finding],
  baseline : Map[String, Bool],
  root? : String = "",
) -> Array[Finding] {
  if baseline.length() == 0 {
    return findings
  }
  // Consumption belongs to this filtering operation. Reusing the loaded
  // Map for another scan must restore every known occurrence's allowance.
  let consumed : Map[String, Int] = Map([])
  findings.filter(fn(f) {
    let rule = rule_id_str(f.rule_id)
    let global_key = rule + ":" + f.fingerprint
    if baseline.contains(global_key) {
      // Entries without file scope have always been explicit wildcards.
      false
    } else {
      let candidates = [
        // New project-scoped records can only match this project-relative
        // interpretation. Legacy fallbacks below use a separate namespace.
        baseline_project_file_key(
          rule,
          f.fingerprint,
          baseline_path(f.file, root),
        ),
        baseline_file_key(rule, f.fingerprint, baseline_path(f.file, root)),
        baseline_file_key(rule, f.fingerprint, f.file),
      ]
      // Older CLI baselines stored the scan's absolute or cwd-relative path.
      if root != "" {
        candidates.push(
          baseline_file_key(rule, f.fingerprint, @path.Path(f.file).resolve().0),
        )
      }
      let mut matched = false
      for key in candidates {
        let count = match consumed.get(key) {
          Some(n) => n
          None => 0
        }
        if baseline.contains(baseline_occurrence_key(key, count)) {
          consumed[key] = count + 1
          matched = true
          break
        }
      }
      !matched
    }
  })
}

///|
fn baseline_occurrence_key(key : String, index : Int) -> String {
  if index == 0 {
    // Preserve the existing file-scoped key and public Map[String, Bool]
    // API. Further occurrences use a distinct JSON shape: a pair whose
    // second element is numeric, versus three or four strings in scoped keys.
    key
  } else {
    Json::array([Json::string(key), Json::number(index.to_double())]).stringify()
  }
}

///|
fn baseline_file_key(
  rule : String,
  fingerprint : String,
  file : String,
) -> String {
  // Encode components independently: file names can contain ':' or separators.
  Json::array([
    Json::string(rule),
    Json::string(fingerprint),
    Json::string(canonical_dir(@path.Path(canonical_dir(file)).normalize().0)),
  ]).stringify()
}

///|
fn baseline_project_file_key(
  rule : String,
  fingerprint : String,
  file : String,
) -> String {
  // Four strings distinguish project paths from the legacy three-part key.
  // Otherwise a project-relative "p/f.mbt" could accidentally match a
  // different file whose cwd-relative path is also "p/f.mbt".
  Json::array([
    Json::string("project"),
    Json::string(rule),
    Json::string(fingerprint),
    Json::string(canonical_dir(@path.Path(canonical_dir(file)).normalize().0)),
  ]).stringify()
}

///|
fn baseline_path(file : String, root : String) -> String {
  let path = @path.Path(canonical_dir(file))
  if root == "" {
    canonical_dir(path.normalize().0)
  } else {
    canonical_dir(path.relative(base=@path.Path(root)).0)
  }
}
