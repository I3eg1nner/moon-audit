// CWE-22: Path concatenation with potentially user-controlled input.
// Heuristic-based: detects string concatenation involving path-like variables.

///|
priv struct Cwe022Visitor {
  findings : Array[Finding]
  file : String
  source : String
  severity : Severity
}

///|
pub fn cwe022_info() -> RuleInfo {
  {
    id: { cwe: 22, variant: "path-concat", },
    name: "Potential Path Traversal via String Concatenation",
    description: "Concatenation uses path/input-like names. Review any filesystem use, source trust and containment checks.",
    default_severity: Warning,
  }
}

///|
pub fn run_cwe022(
  impls : @list.List[@syntax.Impl],
  file : String,
  source : String,
  findings : Array[Finding],
  severity : Severity,
) -> Unit {
  let visitor : Cwe022Visitor = { findings, file, source, severity, }
  impls.each(fn(impl_) { @syntax.IterVisitor::visit_Impl(visitor, impl_) })
}

///|
fn is_path_like_var(name : String) -> Bool {
  if name.contains("url") ||
    name.contains("route") ||
    name.contains("uri") ||
    name.contains("endpoint") ||
    name.contains("href") {
    return false
  }
  if name.contains("offset") ||
    name.contains("size") ||
    name.contains("index") ||
    name.contains("count") ||
    name.contains("profile") ||
    name.contains("len") {
    return false
  }
  name.contains("path") ||
  name.contains("file") ||
  name.contains("dir") ||
  name.contains("filename") ||
  name.contains("filepath")
}

///|
fn is_input_like_var(name : String) -> Bool {
  name.contains("req") ||
  name.contains("param") ||
  name.contains("query") ||
  name.contains("input") ||
  name.contains("id") ||
  name.contains("slug") ||
  name.contains("name") ||
  name.contains("user")
}

///|
fn expr_var_name(expr : @syntax.Expr) -> String? {
  match expr {
    Ident(id~, ..) =>
      match id.name {
        Ident(name~) => Some(name)
        Dot(id~, ..) => Some(id)
      }
    Field(accessor~, ..) =>
      match accessor {
        Label(label) => Some(label.name)
        _ => None
      }
    _ => None
  }
}

///|
fn is_path_separator_string(expr : @syntax.Expr) -> Bool {
  match expr {
    Constant(c=String(s), ..) =>
      if is_non_path_fragment(s) {
        false
      } else {
        s == "/" || s == "\\" || s.has_prefix("/") || s.has_suffix("/")
      }
    _ => false
  }
}

///|
/// API routes and protocol identifiers rather than filesystem paths.
fn is_api_route_string(s : String) -> Bool {
  s.has_prefix("/runs/") ||
  s.has_prefix("/modules/") ||
  s.has_prefix("/api/") ||
  s.has_prefix("/steps/") ||
  s.has_prefix("wiki://") ||
  // refs/heads/, refs/tags/ and friends are git ref names, not file paths.
  s.has_prefix("refs/")
}

///|
/// Fragments that build shell scripts: test commands, env expansion, redirection.
fn is_shell_fragment(s : String) -> Bool {
  s.contains("[ -f") ||
  s.contains("[ -d") ||
  s.contains("[ -e") ||
  s.contains("[ -x") ||
  s.contains("$_TMPDIR") ||
  s.contains("$(") ||
  s.contains("> \"") ||
  s.contains(">/dev/null") ||
  s.contains("2>/dev/null")
}

///|
/// Framework-internal hardcoded paths, not user-input concatenation targets.
fn is_framework_internal_path(s : String) -> Bool {
  s.contains(".mooncakes/") || s.contains("__sol__")
}

///|
fn is_html_or_url_fragment(s : String) -> Bool {
  s.contains("<") ||
  s.contains(">") ||
  s.has_prefix("http://") ||
  s.has_prefix("https://") ||
  // Protocol-relative URLs and JS/MoonBit comment-style fragments.
  s.has_prefix("//") ||
  s.contains("://")
}

///|
/// Any constant fragment that is clearly not a filesystem path component.
fn is_non_path_fragment(s : String) -> Bool {
  is_html_or_url_fragment(s) ||
  is_api_route_string(s) ||
  is_shell_fragment(s) ||
  is_framework_internal_path(s)
}

///|
fn is_non_path_constant(expr : @syntax.Expr) -> Bool {
  match expr {
    Constant(c=String(s), ..) => is_non_path_fragment(s)
    _ => false
  }
}

///|
fn is_string_comparison_method(name : String) -> Bool {
  name == "has_suffix" || name == "has_prefix" || name == "contains"
}

///|
impl @syntax.IterVisitor for Cwe022Visitor with fn visit_Expr_DotApply(
  env,
  self~,
  method_name~,
  args~,
  return_self~,
  loc~,
) {
  if is_string_comparison_method(method_name.name) {
    return
  }
  @syntax.IterVisitor::visit_Expr_DotApply(
    @syntax.IterVisitor::base(env),
    self~,
    method_name~,
    args~,
    return_self~,
    loc~,
  )
}

///|
impl @syntax.IterVisitor for Cwe022Visitor with fn visit_Expr_Infix(
  env,
  op~,
  lhs~,
  rhs~,
  loc~,
) {
  match op.name {
    Ident(name="+") => {
      if is_non_path_constant(lhs) || is_non_path_constant(rhs) {
      } else {
      let lhs_name = expr_var_name(lhs)
      let rhs_name = expr_var_name(rhs)
      let has_path_context = match (lhs_name, rhs_name) {
        (Some(l), Some(r)) =>
          (is_path_like_var(l) && is_input_like_var(r)) ||
          (is_input_like_var(l) && is_path_like_var(r))
        (Some(l), None) => is_path_like_var(l) && !is_any_constant(rhs)
        (None, Some(r)) => is_path_separator_string(lhs) && is_input_like_var(r)
        _ => false
      }
      if has_path_context {
        env.findings.push(
          make_finding(
            { cwe: 22, variant: "path-concat", },
            env.severity,
            Low,
            "Concatenation uses path/input-like names. Review any filesystem use, source trust and containment checks.",
            env.file,
            env.source,
            loc,
          ),
        )
      }
      }
    }
    _ => ()
  }
  @syntax.IterVisitor::visit_Expr_Infix(
    @syntax.IterVisitor::base(env),
    op~,
    lhs~,
    rhs~,
    loc~,
  )
}
