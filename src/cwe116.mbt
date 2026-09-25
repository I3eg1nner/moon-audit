// CWE-116: String::replace() used for HTML/security escaping
// MoonBit's replace() only replaces the FIRST occurrence.
// Must use replace_all() for security escaping.

///|
priv struct Cwe116Visitor {
  findings : Array[Finding]
  file : String
  source : String
  severity : Severity
}

///|
pub fn cwe116_info() -> RuleInfo {
  {
    id: { cwe: 116, variant: "replace-escaping", },
    name: "Possible Incomplete HTML Escaping",
    description: "Call named replace with an escaping-shaped replacement. If this resolves to builtin String::replace, only the first occurrence is replaced; review receiver identity and output context.",
    default_severity: Error,
  }
}

///|
pub fn run_cwe116(
  impls : @list.List[@syntax.Impl],
  file : String,
  source : String,
  findings : Array[Finding],
  severity : Severity,
) -> Unit {
  let visitor : Cwe116Visitor = { findings, file, source, severity, }
  impls.each(fn(impl_) { @syntax.IterVisitor::visit_Impl(visitor, impl_) })
}

///|
impl @syntax.IterVisitor for Cwe116Visitor with fn visit_Expr(env, expr) {
  match syntax_call(expr) {
    Some(call) => {
      let eligible = match call.form {
        Dot => true // Existing syntax rule; receiver type is not proven.
        Qualified => call.owner == Some("String")
      }
      if eligible &&
        call.name == "replace" &&
        is_security_relevant_replace(call.args) {
        env.findings.push(
          make_finding(
            { cwe: 116, variant: "replace-escaping", },
            env.severity,
            High,
            "Call named replace with an escaping-shaped replacement. If this resolves to builtin String::replace, only the first occurrence is replaced; review receiver identity and output context.",
            env.file,
            env.source,
            call.loc,
          ),
        )
      }
    }
    None => ()
  }
  @syntax.IterVisitor::visit_Expr(@syntax.IterVisitor::base(env), expr)
}

///|
pub fn cwe116_output_info() -> RuleInfo {
  {
    id: { cwe: 116, variant: "tainted-output", },
    name: "Tainted Output via Library Sink",
    description: "User-controlled data written to an output channel (FFI/network sink modeled via taint-rules.json or a library model) without neutralization.",
    default_severity: Warning,
  }
}
