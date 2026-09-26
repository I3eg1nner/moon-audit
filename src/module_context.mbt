// Module identity follows the nearest configuration within the requested root.
// Package imports deliberately remain local to each package.

///|
fn module_context_for_directory(
  dir : String,
  root : String,
  cache : Map[String, ImportContext],
  errors : Array[String],
) -> ImportContext {
  let directory = @path.Path(dir).resolve()
  let boundary = @path.Path(root).resolve()
  let key = canonical_dir(directory.0)
  match cache.get(key) {
    Some(context) => return context
    None => ()
  }
  let modern = directory.join(@path.Path("moon.mod")).0
  let legacy = directory.join(@path.Path("moon.mod.json")).0
  let context = if @fs.path_exists(modern) {
    read_module_identity(modern, modern=true, errors~)
  } else if @fs.path_exists(legacy) {
    read_module_identity(legacy, modern=false, errors~)
  } else if directory == boundary || directory.dirname() == directory {
    ImportContext::empty()
  } else {
    module_context_for_directory(directory.dirname().0, root, cache, errors)
  }
  cache[key] = context
  context
}

///|
fn read_module_identity(
  file : String,
  modern~ : Bool,
  errors~ : Array[String],
) -> ImportContext {
  let source = read_regular_text(file) catch {
    _ => {
      errors.push("Failed to read module configuration: " + file)
      return ImportContext::empty()
    }
  }
  let json = match @project_config.parse_module(source, modern, name=file) {
    Some(json) => json
    None => {
      errors.push(
        (if modern {
          "Invalid module configuration: "
        } else {
          "Invalid or duplicate module JSON: "
        }) +
        file,
      )
      return ImportContext::empty()
    }
  }
  match json {
    Object(fields) =>
      match fields.get("name") {
        Some(String(name)) if !name.is_empty() =>
          {
            ..ImportContext::empty(),
            is_stdlib: [
              "moonbitlang/core", "moonbitlang/x", "moonbitlang/parser", "moonbitlang/lexer",
            ].contains(name),
          }
        _ => {
          errors.push("Invalid module name: " + file)
          ImportContext::empty()
        }
      }
    _ => {
      errors.push("Invalid module configuration object: " + file)
      ImportContext::empty()
    }
  }
}
