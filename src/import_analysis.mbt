///|
pub fn analyze_imports(pkg_dir : String) -> ImportContext {
  let (imports, _) = analyze_imports_checked(pkg_dir)
  imports
}

///|
fn analyze_imports_checked(pkg_dir : String) -> (ImportContext, String?) {
  let pkg_path = @path.Path(pkg_dir).join(@path.Path("moon.pkg")).0
  let legacy_path = @path.Path(pkg_dir).join(@path.Path("moon.pkg.json")).0
  if @fs.path_exists(pkg_path) {
    let content = read_regular_text(pkg_path) catch {
      _ => return (ImportContext::empty(), Some("Failed to read " + pkg_path))
    }
    return (
      import_context_from_paths(extract_import_strings(content), false),
      None,
    )
  }
  if !@fs.path_exists(legacy_path) {
    return (ImportContext::empty(), None)
  }
  let content = read_regular_text(legacy_path) catch {
    _ => return (ImportContext::empty(), Some("Failed to read " + legacy_path))
  }
  let json = match parse_project_json(content) {
    Some(parsed) => parsed
    None =>
      return (
        ImportContext::empty(),
        Some("Invalid package JSON: " + legacy_path),
      )
  }
  match json {
    Object(fields) =>
      match fields.get("import") {
        Some(value) => {
          if !legacy_import_shape_valid(value) {
            return (
              ImportContext::empty(),
              Some("Invalid package import field: " + legacy_path),
            )
          }
          (
            import_context_from_paths(extract_legacy_import_value(value), false),
            None,
          )
        }
        None => (ImportContext::empty(), None)
      }
    _ =>
      (
        ImportContext::empty(),
        Some("Invalid package JSON object: " + legacy_path),
      )
  }
}

///|
fn legacy_import_shape_valid(value : Json) -> Bool {
  match value {
    Array(items) =>
      items.all(fn(item) {
        match item {
          String(_) => true
          Object(fields) =>
            match fields.get("path") {
              Some(String(_)) => true
              _ => false
            }
          _ => false
        }
      })
    Object(fields) => {
      let mut valid = true
      for _, alias_value in fields {
        match alias_value {
          String(_) | Null => ()
          _ => valid = false
        }
      }
      valid
    }
    Null => true
    _ => false
  }
}

///|
pub fn analyze_mod_imports(project_root : String) -> ImportContext {
  let mod_path = @path.Path(project_root).join(@path.Path("moon.mod")).0
  let legacy_path = @path.Path(project_root).join(@path.Path("moon.mod.json")).0
  if @fs.path_exists(mod_path) {
    let content = read_regular_text(mod_path) catch {
      _ => return ImportContext::empty()
    }
    return import_context_from_paths(
      extract_import_strings(content),
      is_stdlib_module(content),
    )
  }
  let content = read_regular_text(legacy_path) catch {
    _ => return ImportContext::empty()
  }
  let json = @json.parse(content) catch { _ => return ImportContext::empty() }
  match json {
    Object(fields) => {
      let imports = match fields.get("deps") {
        Some(value) => extract_legacy_import_value(value)
        None => []
      }
      let is_stdlib = match fields.get("name") {
        Some(String(name)) => is_stdlib_name(name)
        _ => false
      }
      import_context_from_paths(imports, is_stdlib)
    }
    _ => ImportContext::empty()
  }
}

///|
fn import_context_from_paths(
  imports : Array[String],
  is_stdlib : Bool,
) -> ImportContext {
  {
    has_cmark: imports.iter().any(fn(s) { s.contains("cmark") }),
    has_rabbita: imports.iter().any(fn(s) { s.contains("rabbita") }),
    has_mocket: imports.iter().any(fn(s) { s.contains("mocket") }),
    has_crescent: imports.iter().any(fn(s) { s.contains("crescent") }),
    has_liquid: imports.iter().any(fn(s) { s.contains("liquid") }),
    has_pug: imports.iter().any(fn(s) { s.contains("pug") }),
    is_stdlib,
  }
}

///|
fn extract_legacy_import_value(value : Json) -> Array[String] {
  let imports : Array[String] = []
  match value {
    Array(items) =>
      for item in items {
        match item {
          String(path) => imports.push(path)
          Object(fields) =>
            match fields.get("path") {
              Some(String(path)) => imports.push(path)
              _ => ()
            }
          _ => ()
        }
      }
    Object(fields) =>
      for path, _ in fields {
        imports.push(path)
      }
    _ => ()
  }
  imports
}

///|
pub fn merge_imports(a : ImportContext, b : ImportContext) -> ImportContext {
  {
    has_cmark: a.has_cmark || b.has_cmark,
    has_rabbita: a.has_rabbita || b.has_rabbita,
    has_mocket: a.has_mocket || b.has_mocket,
    has_crescent: a.has_crescent || b.has_crescent,
    has_liquid: a.has_liquid || b.has_liquid,
    has_pug: a.has_pug || b.has_pug,
    is_stdlib: a.is_stdlib || b.is_stdlib,
  }
}

///|
fn is_stdlib_module(mod_content : String) -> Bool {
  for line in mod_content.split("\n") {
    let trimmed = line.to_owned().trim(chars=" \t\r")
    if trimmed.has_prefix("name") && trimmed.contains("=") {
      if is_stdlib_name(trimmed.to_owned()) {
        return true
      }
    }
  }
  false
}

///|
fn is_stdlib_name(name : String) -> Bool {
  [
    "moonbitlang/core", "moonbitlang/x", "moonbitlang/parser", "moonbitlang/lexer",
  ].contains(name) ||
  [
    "moonbitlang/core", "moonbitlang/x", "moonbitlang/parser", "moonbitlang/lexer",
  ].any(fn(stdlib) { name.contains("\"" + stdlib + "\"") })
}

///|
fn extract_import_strings(content : String) -> Array[String] {
  let results : Array[String] = []
  let lines = content.split("\n")
  let mut in_import_block = false
  for line in lines {
    let trimmed = line.to_owned().trim(chars=" \t\r")
    if trimmed.has_prefix("import") && trimmed.contains("{") {
      in_import_block = true
      // Handle single-line: import { "pkg" }
      if trimmed.contains("}") {
        in_import_block = false
        extract_quoted_imports(trimmed.to_owned(), results)
        continue
      }
      continue
    }
    if in_import_block {
      if trimmed.contains("}") {
        in_import_block = false
        continue
      }
      let cleaned = trimmed.to_owned().trim(chars=" \t\r,\"")
      if cleaned.length() > 0 && !cleaned.has_prefix("//") {
        let cleaned_str = cleaned.to_owned()
        let pkg = if cleaned_str.contains("\"") {
          extract_quoted(cleaned_str)
        } else {
          cleaned_str
        }
        if pkg.length() > 0 {
          results.push(pkg)
        }
      }
    }
  }
  results
}

///|
fn extract_quoted_imports(line : String, results : Array[String]) -> Unit {
  let chars = line.to_array()
  let mut i = 0
  while i < chars.length() {
    if chars[i] == '"' {
      let buf = StringBuilder()
      i += 1
      while i < chars.length() && chars[i] != '"' {
        buf.write_char(chars[i])
        i += 1
      }
      let pkg = buf.to_string()
      if pkg.length() > 0 {
        results.push(pkg)
      }
    }
    i += 1
  }
}

///|
fn extract_quoted(s : String) -> String {
  let chars = s.to_array()
  let buf = StringBuilder()
  let mut in_quote = false
  for c in chars {
    if c == '"' {
      if in_quote {
        break
      }
      in_quote = true
      continue
    }
    if in_quote {
      buf.write_char(c)
    }
  }
  buf.to_string()
}
