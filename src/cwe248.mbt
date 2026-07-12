// CWE-248: panic()/abort() in library code can crash the entire program.
// Filters:
//   - guard...else{panic/abort}: logically unreachable, standard MoonBit pattern
//   - Platform stub files (.wasm.mbt, .js.mbt): platform-specific, won't execute on other targets
//   - abort("unreachable") / abort("unimplemented"): developer-annotated dead code
//   - Bare panic() with no arguments: typically a match-exhaustiveness sentinel, not a real error
//   - Contract assertions: standard library patterns like abort("index out of bounds"),
//     abort("division by zero") — these are correct runtime behavior, not security bugs

///|
priv struct Cwe248Visitor {
  findings : Array[Finding]
  file : String
  source : String
  severity : Severity
  mut in_guard_else : Bool
}

///|
pub fn cwe248_info() -> RuleInfo {
  {
    id: { cwe: 248, variant: "panic-reachable" },
    name: "Reachable panic/abort in Library Code",
    description: "panic() or abort() in library code terminates the program. Callers cannot recover. Use Result/Option or raise an error instead.",
    default_severity: Warning,
  }
}

///|
pub fn run_cwe248(
  impls : @list.List[@syntax.Impl],
  file : String,
  source : String,
  findings : Array[Finding],
  severity : Severity,
) -> Unit {
  if is_platform_stub_file(file) {
    return
  }
  let visitor : Cwe248Visitor = {
    findings,
    file,
    source,
    severity,
    in_guard_else: false,
  }
  impls.each(fn(impl_) { @syntax.IterVisitor::visit_Impl(visitor, impl_) })
}

///|
fn is_platform_stub_file(file : String) -> Bool {
  file.has_suffix(".wasm.mbt") ||
  file.has_suffix(".js.mbt") ||
  file.has_suffix(".native.mbt")
}

///|
fn get_panic_kind(func : @syntax.Expr) -> String {
  match func {
    Ident(id~, ..) =>
      match id.name {
        Ident(name="panic") => "panic"
        Ident(name="abort") => "abort"
        _ => ""
      }
    _ => ""
  }
}

///|
fn is_unreachable_abort(args : @list.List[@syntax.Argument]) -> Bool {
  args.any(fn(arg) {
    match arg.value {
      Constant(c=String(s), ..) => {
        let lower = s.to_lower()
        lower.contains("unreachable") || lower.contains("unimplemented")
      }
      _ => false
    }
  })
}

///|
fn is_bare_panic(kind : String, args : @list.List[@syntax.Argument]) -> Bool {
  kind == "panic" && args.is_empty()
}

///|
fn is_contract_assertion(
  kind : String,
  args : @list.List[@syntax.Argument],
) -> Bool {
  if kind != "abort" {
    return false
  }
  args.any(fn(arg) {
    match arg.value {
      Constant(c=String(s), ..) => {
        let lower = s.to_lower()
        lower.contains("out of bounds") ||
        lower.contains("division by zero") ||
        lower.contains("divide by zero") ||
        lower.contains("overflow") ||
        lower.contains("underflow") ||
        lower.contains("negative") ||
        lower.contains("empty") ||
        lower.contains("length") ||
        lower.contains("capacity") ||
        lower.contains("not found") ||
        lower.contains("invalid")
      }
      _ => false
    }
  })
}

///|
impl @syntax.IterVisitor for Cwe248Visitor with fn visit_Expr_Guard(
  env,
  cond~,
  otherwise~,
  body~,
  loc~,
) {
  let _ = loc
  env.base().visit_Expr(cond)
  match otherwise {
    Some(else_expr) => {
      let prev = env.in_guard_else
      env.in_guard_else = true
      env.base().visit_Expr(else_expr)
      env.in_guard_else = prev
    }
    None => ()
  }
  env.base().visit_Expr(body)
}

///|
impl @syntax.IterVisitor for Cwe248Visitor with fn visit_Expr_Apply(
  env,
  func~,
  args~,
  loc~,
) {
  let kind = get_panic_kind(func)
  if kind != "" &&
    !env.in_guard_else &&
    !is_unreachable_abort(args) &&
    !is_bare_panic(kind, args) &&
    !is_contract_assertion(kind, args) {
    env.findings.push(
      make_finding(
        { cwe: 248, variant: "panic-reachable" },
        env.severity,
        Medium,
        "panic()/abort() terminates the program. In library code, prefer returning Result or raising an error so callers can handle the failure.",
        env.file,
        env.source,
        loc,
      ),
    )
  }
  env.base().visit_Expr_Apply(func~, args~, loc~)
}
