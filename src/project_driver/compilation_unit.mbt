///|
pub(all) enum CompileRole {
  Production
  WhiteboxTest
  BlackboxTest
} derive(Eq, Debug)

///|
pub fn CompileRole::label(self : CompileRole) -> String {
  match self {
    Production => "production"
    WhiteboxTest => "whitebox_test"
    BlackboxTest => "blackbox_test"
  }
}

///|
pub(all) enum InputMode {
  Source
  DoctestOnly
} derive(Eq, Debug)

///|
pub fn InputMode::label(self : InputMode) -> String {
  match self {
    Source => "source"
    DoctestOnly => "doctest_only"
  }
}

///|
pub(all) struct SourceInput {
  path : String
  mode : InputMode
} derive(Eq, Debug)

///|
pub(all) struct CompilationUnit {
  id : String
  module_root : String
  module_name : String
  package_name : String
  package_root : String
  package_kind : String
  target : String
  role : CompileRole
  inputs : Array[SourceInput]
} derive(Eq, Debug)

///|
pub fn SourceInput::to_json(self : SourceInput) -> Json {
  { "path": self.path.to_json(), "mode": self.mode.label().to_json() }
}

///|
pub fn CompilationUnit::to_json(self : CompilationUnit) -> Json {
  {
    "id": self.id.to_json(),
    "module_root": self.module_root.to_json(),
    "module_name": self.module_name.to_json(),
    "package_name": self.package_name.to_json(),
    "package_root": self.package_root.to_json(),
    "package_kind": self.package_kind.to_json(),
    "target": self.target.to_json(),
    "role": self.role.label().to_json(),
    "inputs": self.inputs.map(SourceInput::to_json).to_json(),
  }
}

///|
fn project_input(path : String, root : String) -> Bool {
  path.has_prefix(root + "/") && !path.has_prefix(root + "/.mooncakes/")
}

///|
fn source_suffix(path : String) -> Bool {
  path.has_suffix(".mbt") ||
  path.has_suffix(".mbt.md") ||
  path.has_suffix(".mbtx")
}

///|
// Read compiler-declared package/role identities. Never infer test roles from
// package suffixes or directory names, and never execute dry-run output.
pub fn compilation_units(
  output : String,
  root : String,
  module_name : String,
  target : String,
) -> Result[Array[CompilationUnit], String] {
  let units : Map[String, CompilationUnit] = Map([])
  let owners : Map[String, String] = Map([])
  for line in output.split("\n") {
    let words = match plan_words(line.to_owned()) {
      Some(words) => words
      None => return Err("invalid_compiler_plan_quoting")
    }
    if words.length() < 2 {
      continue
    }
    let base = words[0]
      .replace_all(old="\\", new="/")
      .split("/")
      .to_array()
      .last()
      .unwrap()
      .to_owned()
    if (base != "moonc" && base != "moonc.exe") || words[1] != "check" {
      continue
    }
    let inputs : Array[SourceInput] = []
    let values : Map[String, String] = Map([])
    let package_sources : Array[String] = []
    let flags : Map[String, Bool] = Map([])
    let mut invalid = ""
    let mut i = 2
    while i < words.length() {
      let word = words[i]
      if word.has_prefix("-") {
        if [
            "-is-main", "-whitebox-test", "-blackbox-test", "-no-mi", "-include-doctests",
            "-output-json",
          ].contains(word) {
          if flags.contains(word) {
            invalid = "duplicate_compiler_flag: " + word
          }
          flags[word] = true
          i += 1
          continue
        }
        let has_value = [
          "-i", "-o", "-target", "-pkg", "-pkg-sources", "-workspace-path", "-std-path",
          "-error-format", "-patch-file", "-check-mi", "-cfg", "-doctest-only", "-w",
          "-alert", "-all-pkgs", "-pkg-type", "-replace-name", "-replace-content",
        ].contains(word)
        if !has_value {
          invalid = "unsupported_compiler_flag: " + word
          i += 1
          continue
        }
        if i + 1 >= words.length() {
          return Err("missing_compiler_argument: " + word)
        }
        let value = words[i + 1]
        if [
            "-patch-file", "-replace-name", "-replace-content", "-cfg", "-check-mi",
          ].contains(word) {
          return Err("unsupported_compiler_context: " + word)
        }
        if word == "-doctest-only" {
          if !source_suffix(value) {
            invalid = "unsupported_doctest_input"
          }
          let path = join(root, value)
          if project_input(path, root) {
            inputs.push({ path, mode: DoctestOnly, })
          }
        } else if word == "-pkg-sources" {
          package_sources.push(value)
        } else if ["-pkg", "-target", "-workspace-path", "-pkg-type"].contains(
            word,
          ) {
          if values.contains(word) {
            invalid = "duplicate_compiler_identity: " + word
          }
          values[word] = value
        }
        i += 2
      } else {
        if source_suffix(word) {
          let path = join(root, word)
          if project_input(path, root) {
            inputs.push({ path, mode: Source, })
          }
        } else {
          invalid = "unsupported_compiler_operand"
        }
        i += 1
      }
    }
    if invalid != "" {
      return Err(invalid)
    }
    let package_kind = match values.get("-pkg-type") {
      Some(kind) => kind
      None => if flags.contains("-is-main") { "executable" } else { "library" }
    }
    if !["executable", "library", "foreign_library"].contains(package_kind) {
      return Err("unsupported_package_kind")
    }
    if flags.contains("-is-main") && package_kind != "executable" {
      return Err("conflicting_package_kind")
    }
    let role = if flags.contains("-blackbox-test") {
      if flags.contains("-whitebox-test") {
        return Err("conflicting_compiler_roles")
      }
      BlackboxTest
    } else if flags.contains("-whitebox-test") {
      WhiteboxTest
    } else {
      Production
    }
    // Dependency inputs are not lowered, but their compiler contexts must
    // still be recognized because external models depend on original sources.
    if inputs.is_empty() {
      continue
    }
    let package_name = match values.get("-pkg") {
      Some(name) => name
      None => return Err("missing_package_identity")
    }
    if package_name != module_name &&
      !package_name.has_prefix(module_name + "/") {
      // A root package's blackbox identity appends the suffix to the module.
      if !(flags.contains("-blackbox-test") &&
        package_name == module_name + "_blackbox_test") {
        return Err("package_outside_module_identity")
      }
    }
    if values.get("-target") != Some(target) {
      return Err("compiler_target_identity_mismatch")
    }
    if values.get("-workspace-path") is Some(workspace) &&
      join(root, workspace) != root {
      return Err("compiler_module_root_mismatch")
    }
    if (
        flags.contains("-include-doctests") ||
        inputs.any(fn(input) { input.mode == DoctestOnly })
      ) &&
      role != BlackboxTest {
      return Err("doctest_outside_blackbox_role")
    }
    if inputs.any(fn(input) { input.mode == DoctestOnly }) &&
      !flags.contains("-include-doctests") {
      return Err("doctest_mode_not_enabled")
    }
    let prefix = package_name + ":"
    let matching = package_sources.filter(fn(source) {
      source.has_prefix(prefix)
    })
    if matching.length() != 1 {
      return Err("package_source_identity_not_unique")
    }
    let package_root = join(root, matching[0][prefix.length():].to_owned())
    if package_root != root && !project_input(package_root, root) {
      return Err("package_root_outside_module")
    }
    for input in inputs {
      if !input.path.has_prefix(package_root + "/") {
        return Err("source_outside_package_identity")
      }
    }
    inputs.sort_by(fn(a, b) {
      let order = String::lexical_compare(a.path, b.path)
      if order == 0 {
        String::lexical_compare(a.mode.label(), b.mode.label())
      } else {
        order
      }
    })
    let unique : Array[SourceInput] = []
    for input in inputs {
      if !unique.contains(input) {
        unique.push(input)
      }
    }
    let identity = [
        root,
        module_name,
        package_name,
        package_root,
        package_kind,
        target,
        role.label(),
      ]
      .to_json()
      .stringify()
    let id = "unit:" +
      @crypto.bytes_to_hex_string(@crypto.sha256(@utf8.encode(identity)))
    let unit : CompilationUnit = {
      id,
      module_root: root,
      module_name,
      package_name,
      package_root,
      package_kind,
      target,
      role,
      inputs: unique,
    }
    if units.get(id) is Some(previous) && previous != unit {
      return Err("conflicting_compiler_unit_inputs")
    }
    if role == Production {
      for input in unique {
        if owners.get(input.path) is Some(owner) && owner != id {
          return Err("ambiguous_production_source_identity")
        }
        owners[input.path] = id
      }
    }
    units[id] = unit
  }
  let result = units.values().to_array()
  if result.is_empty() {
    return Err("no_project_compilation_units")
  }
  result.sort_by(fn(a, b) { String::lexical_compare(a.id, b.id) })
  Ok(result)
}

///|
fn module_name_at(root : String) -> String? {
  for (file, modern) in [("moon.mod", true), ("moon.mod.json", false)] {
    let path = join(root, file)
    if @fs.path_exists(path) {
      let text = @fs.read_file_to_string(path) catch { _ => return None }
      return @project_config.module_name(text, modern)
    }
  }
  None
}

///|
pub extend CompileRole with Eq::{equal, not_equal}

///|
pub extend CompileRole with @debug.Debug::{to_repr}

///|
pub extend InputMode with Eq::{equal, not_equal}

///|
pub extend InputMode with @debug.Debug::{to_repr}

///|
pub extend SourceInput with Eq::{equal, not_equal}

///|
pub extend SourceInput with @debug.Debug::{to_repr}

///|
pub extend CompilationUnit with Eq::{equal, not_equal}

///|
pub extend CompilationUnit with @debug.Debug::{to_repr}
