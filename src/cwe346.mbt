// CWE-346: WebSocket server without Origin validation.
// Only activated when mocket or crescent websocket is imported.

///|
priv struct Cwe346Visitor {
  findings : Array[Finding]
  file : String
  source : String
  severity : Severity
}

///|
pub fn cwe346_info() -> RuleInfo {
  {
    id: { cwe: 346, variant: "ws-origin", },
    name: "WebSocket Origin Configuration Review",
    description: "WebSocket-upgrade-shaped call lacks origin labels. Confirm a real upgrade API and inspect origin validation across middleware.",
    default_severity: Warning,
  }
}

///|
pub fn run_cwe346(
  impls : @list.List[@syntax.Impl],
  file : String,
  source : String,
  findings : Array[Finding],
  severity : Severity,
) -> Unit {
  let visitor : Cwe346Visitor = { findings, file, source, severity, }
  impls.each(fn(impl_) { @syntax.IterVisitor::visit_Impl(visitor, impl_) })
}

///|
fn is_ws_upgrade_func(func : @syntax.Expr) -> Bool {
  match func {
    Ident(id~, ..) =>
      match id.name {
        Ident(name="upgrade_websocket") | Ident(name="ws_upgrade") => true
        Dot(id="upgrade_websocket", ..) | Dot(id="ws_upgrade", ..) => true
        _ => false
      }
    _ => false
  }
}

///|
impl @syntax.IterVisitor for Cwe346Visitor with fn visit_Expr_DotApply(
  env,
  self~,
  method_name~,
  args~,
  return_self~,
  loc~,
) {
  if method_name.name == "upgrade_websocket" || method_name.name == "ws_upgrade" {
    if !has_labelled_arg(args, "origin") &&
      !has_labelled_arg(args, "allowed_origins") {
      env.findings.push(
        make_finding(
          { cwe: 346, variant: "ws-origin", },
          env.severity,
          Low,
          "WebSocket-upgrade-shaped call lacks origin labels. Confirm a real upgrade API and inspect origin validation across middleware.",
          env.file,
          env.source,
          loc,
        ),
      )
    }
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
impl @syntax.IterVisitor for Cwe346Visitor with fn visit_Expr_Apply(
  env,
  func~,
  args~,
  loc~,
) {
  if is_ws_upgrade_func(func) {
    if !has_labelled_arg(args, "origin") &&
      !has_labelled_arg(args, "allowed_origins") {
      env.findings.push(
        make_finding(
          { cwe: 346, variant: "ws-origin", },
          env.severity,
          Low,
          "WebSocket-upgrade-shaped call lacks origin labels. Confirm a real upgrade API and inspect origin validation across middleware.",
          env.file,
          env.source,
          loc,
        ),
      )
    }
  }
  @syntax.IterVisitor::visit_Expr_Apply(
    @syntax.IterVisitor::base(env),
    func~,
    args~,
    loc~,
  )
}
