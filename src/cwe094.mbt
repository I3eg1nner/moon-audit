// CWE-94: eval() or new Function() in extern JS blocks enables code injection.

///|
priv struct Cwe094Visitor {
  findings : Array[Finding]
  file : String
  source : String
  severity : Severity
  mut current_loc : @basic.Location?
}

///|
pub fn cwe094_info() -> RuleInfo {
  {
    id: { cwe: 94, variant: "eval-extern" },
    name: "Code Injection via eval in Extern JS",
    description: "eval() or new Function() in extern JS/JavaScript blocks enables arbitrary code execution.",
    default_severity: Error,
  }
}

///|
pub fn run_cwe094(
  impls : @list.List[@syntax.Impl],
  file : String,
  source : String,
  findings : Array[Finding],
  severity : Severity,
) -> Unit {
  let visitor : Cwe094Visitor = {
    findings,
    file,
    source,
    severity,
    current_loc: None,
  }
  impls.each(fn(impl_) { @syntax.IterVisitor::visit_Impl(visitor, impl_) })
}

///|
impl @syntax.IterVisitor for Cwe094Visitor with fn visit_Impl_TopFuncDef(
  env,
  fun_decl~,
  decl_body~,
  where_clause~,
  loc~,
) {
  env.current_loc = Some(loc)
  env.base().visit_Impl_TopFuncDef(fun_decl~, decl_body~, where_clause~, loc~)
  env.current_loc = None
}

///|
impl @syntax.IterVisitor for Cwe094Visitor with fn visit_FuncStubs_Embedded(
  env,
  language~,
  code~,
) {
  let is_js = match language {
    Some(lang) =>
      lang.contains("js") || lang.contains("javascript") || lang.contains("JS")
    None => true
  }
  if is_js {
    let code_str = match code {
      CodeString(s) => s
      CodeMultilineString(lines) => {
        let buf = StringBuilder::new()
        lines.each(fn(line) {
          buf.write_string(line)
          buf.write_char('\n')
        })
        buf.to_string()
      }
    }
    if code_str.contains("eval(") ||
      code_str.contains("new Function(") ||
      code_str.contains("new Function (") {
      let loc = match env.current_loc {
        Some(l) => l
        None =>
          {
            start: { fname: env.file, lnum: 0, bol: 0, cnum: 0 },
            end: { fname: env.file, lnum: 0, bol: 0, cnum: 0 },
          }
      }
      env.findings.push(
        make_finding(
          { cwe: 94, variant: "eval-extern" },
          env.severity,
          High,
          "eval() or new Function() in extern JS block enables code injection. Consider safer alternatives.",
          env.file,
          env.source,
          loc,
        ),
      )
    }
  }
  env.base().visit_FuncStubs_Embedded(language~, code~)
}
