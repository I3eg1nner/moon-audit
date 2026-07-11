// CWE-113: HTTP Response Splitting via CRLF Injection.
// Detects when user-controlled input is passed to response header setters
// without CRLF sanitization.

///|
priv struct Cwe113Visitor {
  findings : Array[Finding]
  file : String
  source : String
  severity : Severity
}

///|
pub fn cwe113_info() -> RuleInfo {
  {
    id: { cwe: 113, variant: "crlf-injection" },
    name: "HTTP Response Splitting via CRLF Injection",
    description: "Response header values set from user input without CRLF (\\r\\n) sanitization allow HTTP response splitting, enabling session fixation, XSS, and cache poisoning.",
    default_severity: Error,
  }
}

///|
pub fn run_cwe113(
  impls : @list.List[@syntax.Impl],
  file : String,
  source : String,
  findings : Array[Finding],
  severity : Severity,
) -> Unit {
  let visitor : Cwe113Visitor = { findings, file, source, severity }
  impls.each(fn(impl_) { @syntax.IterVisitor::visit_Impl(visitor, impl_) })
}

///|
fn is_header_setter(method_name : String) -> Bool {
  method_name == "set_header" ||
  method_name == "add_header" ||
  method_name == "append_header" ||
  method_name == "set_response_header"
}

///|
fn has_dynamic_header_value(args : @list.List[@syntax.Argument]) -> Bool {
  let mut pos_idx = 0
  let mut result = false
  args.each(fn(arg) {
    match arg.kind {
      Labelled(label) =>
        if label.name == "value" && !is_constant_string(arg.value) {
          result = true
        }
      LabelledPun(_) | LabelledOption(..) | LabelledOptionPun(..) => ()
      _ => {
        if pos_idx == 1 && !is_constant_string(arg.value) {
          result = true
        }
        pos_idx += 1
      }
    }
  })
  result
}

///|
impl @syntax.IterVisitor for Cwe113Visitor with fn visit_Expr_DotApply(
  env,
  self~,
  method_name~,
  args~,
  return_self~,
  loc~,
) {
  if is_header_setter(method_name.name) && has_dynamic_header_value(args) {
    env.findings.push(
      make_finding(
        { cwe: 113, variant: "crlf-injection" },
        env.severity,
        "Response header set with dynamic value without CRLF sanitization. Attacker can inject \\r\\n to split the HTTP response, enabling session fixation or XSS.",
        env.file,
        env.source,
        loc,
      ),
    )
  }
  env.base().visit_Expr_DotApply(self~, method_name~, args~, return_self~, loc~)
}
