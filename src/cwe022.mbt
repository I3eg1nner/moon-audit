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
    id: { cwe: 22, variant: "path-concat" },
    name: "Potential Path Traversal via String Concatenation",
    description: "String concatenation to build file paths without traversal protection may allow directory traversal attacks.",
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
  let visitor : Cwe022Visitor = { findings, file, source, severity }
  impls.each(fn(impl_) { @syntax.IterVisitor::visit_Impl(visitor, impl_) })
}

///|
fn is_path_like_var(name : String) -> Bool {
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
      s == "/" || s == "\\" || s.has_prefix("/") || s.has_suffix("/")
    _ => false
  }
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
            { cwe: 22, variant: "path-concat" },
            env.severity,
            "String concatenation to build file path. Use path sanitization to prevent directory traversal (e.g., reject '..' segments).",
            env.file,
            env.source,
            loc,
          ),
        )
      }
    }
    _ => ()
  }
  env.base().visit_Expr_Infix(op~, lhs~, rhs~, loc~)
}
