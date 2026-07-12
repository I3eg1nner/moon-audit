// CWE-248: panic()/abort() in library code can crash the entire program.
// Filters:
//   - guard...else{panic/abort}: logically unreachable, standard MoonBit pattern
//   - Platform stub files (.wasm.mbt, .js.mbt): platform-specific, won't execute on other targets
//   - abort("unreachable") / abort("unimplemented"): developer-annotated dead code

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
fn is_panic_func(func : @syntax.Expr) -> Bool {
  match func {
    Ident(id~, ..) =>
      match id.name {
        Ident(name="panic") | Ident(name="abort") => true
        _ => false
      }
    _ => false
  }
}

///|
fn is_unreachable_abort(args : @list.List[@syntax.Argument]) -> Bool {
  args.any(fn(arg) {
    match arg.value {
      Constant(c=String(s), ..) =>
        s.contains("unreachable") || s.contains("unimplemented")
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
  if is_panic_func(func) && !env.in_guard_else && !is_unreachable_abort(args) {
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
