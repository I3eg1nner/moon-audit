///|
pub fn analyze_imports(pkg_dir : String) -> ImportContext {
  let pkg_path = @path.Path(pkg_dir).join(@path.Path("moon.pkg")).0
  let content = @fs.read_file_to_string(pkg_path) catch {
    _ => return ImportContext::empty()
  }
  let imports = extract_import_strings(content)
  {
    has_cmark: imports.iter().any(fn(s) { s.contains("cmark") }),
    has_rabbita: imports.iter().any(fn(s) { s.contains("rabbita") }),
    has_mocket: imports.iter().any(fn(s) { s.contains("mocket") }),
    has_crescent: imports.iter().any(fn(s) { s.contains("crescent") }),
    has_liquid: imports.iter().any(fn(s) { s.contains("liquid") }),
    has_pug: imports.iter().any(fn(s) { s.contains("pug") }),
    is_stdlib: false,
  }
}

///|
pub fn analyze_mod_imports(project_root : String) -> ImportContext {
  let mod_path = @path.Path(project_root).join(@path.Path("moon.mod")).0
  let content = @fs.read_file_to_string(mod_path) catch {
    _ => return ImportContext::empty()
  }
  let imports = extract_import_strings(content)
  {
    has_cmark: imports.iter().any(fn(s) { s.contains("cmark") }),
    has_rabbita: imports.iter().any(fn(s) { s.contains("rabbita") }),
    has_mocket: imports.iter().any(fn(s) { s.contains("mocket") }),
    has_crescent: imports.iter().any(fn(s) { s.contains("crescent") }),
    has_liquid: imports.iter().any(fn(s) { s.contains("liquid") }),
    has_pug: imports.iter().any(fn(s) { s.contains("pug") }),
    is_stdlib: is_stdlib_module(content),
  }
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
  let stdlib_names = [
    "moonbitlang/core", "moonbitlang/x", "moonbitlang/parser", "moonbitlang/lexer",
  ]
  for line in mod_content.split("\n") {
    let trimmed = line.to_owned().trim(chars=" \t\r")
    if trimmed.has_prefix("name") && trimmed.contains("=") {
      for name in stdlib_names {
        if trimmed.contains(name) {
          return true
        }
      }
    }
  }
  false
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
      let buf = StringBuilder::new()
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
  let buf = StringBuilder::new()
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
