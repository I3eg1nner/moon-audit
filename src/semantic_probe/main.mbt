// Development probe only; not the production moon-audit CLI.

///|
async fn main {
  let args = @env.args()
  if args.length() > 1 && args[1] == "--internal-supervise" {
    @sys.exit(@project.supervise(args) catch { _ => 125 })
    return
  }
  if args.length() != 3 {
    println("usage: semantic_probe PROJECT TOOLCHAIN_HOME")
    @sys.exit(2)
    return
  }
  let root = @project.absolute(args[1])
  let home = @project.absolute(args[2])
  let path = @path.Path(home).join(@path.Path("bin/moon")).0
  let executable = if @path.sep == '\\' { path + ".exe" } else { path }
  let verification = @project.verify(
    root,
    executable,
    Some(home),
    "native",
    300,
  )
  if verification.status != "compiler_verified" {
    println(verification.to_json().stringify(indent=2))
    @sys.exit(2)
    return
  }
  let result = @frontend.analyze(
    root,
    executable,
    Some(home),
    verification.units,
  )
  if !@project.unchanged(verification.snapshot, root) {
    println("project_changed")
    @sys.exit(2)
    return
  }
  let complete = match result {
    { "errors": Array(errors), "routes": Array(routes), .. } =>
      errors.is_empty() &&
      !routes.is_empty() &&
      routes.all(fn(route) {
        match route {
          { "result": { "status": String("complete"), .. }, .. } => true
          _ => false
        }
      })
    _ => false
  }
  if result is Object(fields) {
    fields["status"] = Json::string(
      if complete {
        "complete_within_supported_candidates"
      } else {
        "incomplete"
      },
    )
    fields["compiler_verification"] = {
      "status": Json::string(verification.status),
      "toolchain": Json::string(verification.toolchain),
      "target": Json::string(verification.target),
      "selected_files": verification.files.to_json(),
    }
  }
  println(result.stringify(indent=2))
  if !complete {
    @sys.exit(2)
  }
}
