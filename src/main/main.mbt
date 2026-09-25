///|
async fn main {
  let raw = @env.args()
  if raw.length() > 1 && raw[1] == "--internal-supervise" {
    let code = @project.supervise(raw) catch { _ => 125 }
    @sys.exit(code)
    return
  }
  if raw.length() > 1 && raw[1] == "--internal-semantic" {
    if raw.length() != 5 || !@project.limit_worker_memory(2048) {
      @sys.exit(2)
      return
    }
    let home = if raw[4] == "" { None } else { Some(raw[4]) }
    let verified = @project.verify(raw[2], raw[3], home, "native", 30)
    if verified.status != "compiler_verified" {
      println(verified.to_json().stringify())
      @sys.exit(2)
      return
    }
    let report = @semantic.analyze(raw[2], raw[3], home, verified.files)
    let complete = @audit.semantic_complete(report) &&
      @project.unchanged(verified.snapshot, raw[2])
    if report is Object(fields) {
      fields["status"] = Json::string(
        if complete {
          "complete_within_declared_scope"
        } else {
          "incomplete"
        },
      )
      fields["coverage_status"] = Json::string("explicit_callback_scope")
      fields["budget"] = {
        "wall_seconds": 60,
        "worker_address_space_or_commit_mib": 2048,
        "query_limit": 256,
        "parallel_queries": 4,
        "ir_units": 10000,
      }
    }
    println(report.stringify())
    if !complete {
      @sys.exit(2)
    }
    return
  }
  let options = [
    @argparse.OptionArg(
      "semantic-scope",
      long="semantic-scope",
      about="Required for semantic: mocket-get-callbacks",
    ),
    @argparse.OptionArg(
      "analysis",
      long="analysis",
      default_values=["syntax"],
      about="syntax, or explicitly scoped semantic analysis",
    ),
    @argparse.OptionArg(
      "project-toolchain",
      long="project-toolchain",
      about="Target MoonBit toolchain directory",
    ),
    @argparse.OptionArg(
      "project-moon",
      long="project-moon",
      about="Target moon executable",
    ),
    @argparse.OptionArg(
      "target",
      long="target",
      default_values=["native"],
      about="native, js, wasm or wasm-gc",
    ),
    @argparse.OptionArg(
      "timeout-seconds",
      long="timeout-seconds",
      default_values=["300"],
      about="Compiler command timeout",
    ),
    @argparse.OptionArg(
      "format",
      short='f',
      long="format",
      default_values=["text"],
      about="text, json or sarif",
    ),
    @argparse.OptionArg("output", short='o', long="output", about="Report file"),
    @argparse.OptionArg(
      "config",
      short='c',
      long="config",
      about="JSON configuration",
    ),
    @argparse.OptionArg(
      "severity",
      long="severity",
      default_values=["warning"],
      about="error, warning or info",
    ),
    @argparse.OptionArg(
      "rule",
      long="rule",
      action=@argparse.Append,
      about="Only run selected pattern rules",
    ),
    @argparse.OptionArg(
      "changed-files",
      long="changed-files",
      about="Restrict scan to listed files; no caller analysis",
    ),
    @argparse.OptionArg(
      "baseline",
      long="baseline",
      about="Suppress recorded finding occurrences",
    ),
  ]
  let positionals = [
    @argparse.PositionArg(
      "path",
      default_values=["."],
      about="Project directory",
    ),
  ]
  let cmd = @argparse.Command(
    "moon-audit",
    version=@audit.ANALYZER_VERSION,
    about="MoonBit syntax-pattern scanner; no interprocedural analysis",
    flags=[
      @argparse.FlagArg(
        "verify-project",
        long="verify-project",
        about="Verify with the target project toolchain",
      ),
      @argparse.FlagArg(
        "quiet",
        short='q',
        long="quiet",
        about="Suppress progress messages",
      ),
      @argparse.FlagArg(
        "verbose",
        short='v',
        long="verbose",
        about="Detailed text report",
      ),
      @argparse.FlagArg(
        "fail-on-error",
        long="fail-on-error",
        about="Exit 1 for error-level findings",
      ),
    ],
    options~,
    positionals~,
    subcommands=[
      @argparse.Command(
        "list-rules",
        about="List supported syntax-pattern rules",
      ),
      @argparse.Command(
        "generate-baseline",
        about="Record findings after a complete pattern scan",
        flags=[
          @argparse.FlagArg(
            "verify-project",
            long="verify-project",
            about="Verify with the project toolchain",
          ),
        ],
        options~,
        positionals~,
      ),
    ],
  )
  let matches = cmd.parse() catch {
    e => {
      cli_error(e.to_string())
      return
    }
  }
  match matches.subcommand {
    Some(("list-rules", _)) => {
      if get_val(matches, "format", "text") == "json" {
        println(@audit.rule_capabilities().stringify(indent=2))
        return
      }
      for rule in @audit.list_all_rules() {
        println(@audit.rule_id_str(rule.id) + "  " + rule.name)
      }
      println(
        "Scope: syntax patterns only; no type, sanitizer or cross-function resolution.",
      )
    }
    Some(("generate-baseline", sub)) => {
      // Preserve explicitly supplied parent options; child command-line values win.
      for key, value in matches.values {
        if matches.sources.get(key) is Some(Argv) &&
          !(sub.sources.get(key) is Some(Argv)) {
          sub.values[key] = value
        }
      }
      if flag(matches, "verify-project") {
        sub.flags["verify-project"] = true
      }
      scan(sub, true)
    }
    _ => scan(matches, false)
  }
}

///|
fn get_opt(matches : @argparse.Matches, key : String) -> String? {
  match matches.values.get(key) {
    Some(values) if !values.is_empty() => Some(values[0])
    _ => None
  }
}

///|
fn get_val(
  matches : @argparse.Matches,
  key : String,
  fallback : String,
) -> String {
  match get_opt(matches, key) {
    Some(v) => v
    None => fallback
  }
}

///|
fn flag(matches : @argparse.Matches, key : String) -> Bool {
  match matches.flags.get(key) {
    Some(v) => v
    None => false
  }
}

///|
fn cli_error(message : String) -> Unit {
  println("moon-audit: error: " + message)
  @sys.exit(2)
}

///|
fn read_json(path : String) -> Json? {
  let content = @audit.read_regular_text(path) catch {
    _ => {
      cli_error("cannot read " + path)
      return None
    }
  }
  let value = @json.parse(content) catch {
    _ => {
      cli_error("invalid JSON: " + path)
      return None
    }
  }
  Some(value)
}

///|
async fn scan(matches : @argparse.Matches, baseline : Bool) -> Unit {
  let root = @project.absolute(get_val(matches, "path", "."))
  if !(@fs.is_dir(root) catch { _ => false }) {
    cli_error("path not found or not a directory: " + root)
    return
  }
  let format = get_val(matches, "format", "text")
  if !["text", "json", "sarif"].contains(format) {
    cli_error("unknown output format: " + format)
    return
  }
  let analysis = get_val(matches, "analysis", "syntax")
  if !["syntax", "semantic"].contains(analysis) {
    cli_error("unknown analysis: " + analysis)
    return
  }
  if analysis == "semantic" &&
    get_opt(matches, "semantic-scope") != Some("mocket-get-callbacks") {
    cli_error(
      "semantic analysis requires --semantic-scope mocket-get-callbacks; it does not establish project-wide security coverage",
    )
    return
  }
  if analysis == "syntax" && get_opt(matches, "semantic-scope") is Some(_) {
    cli_error("semantic-scope requires --analysis semantic")
    return
  }
  let home = get_opt(matches, "project-toolchain").map(@project.absolute)
  let moon = get_opt(matches, "project-moon")
  if home is Some(_) && moon is Some(_) {
    cli_error("project-toolchain and project-moon are mutually exclusive")
    return
  }
  let verify = flag(matches, "verify-project")
  if analysis == "semantic" &&
    (!verify || get_opt(matches, "changed-files") is Some(_)) {
    cli_error(
      "semantic analysis requires --verify-project and a full file set (changed-files is unsupported)",
    )
    return
  }
  if !verify && (home is Some(_) || moon is Some(_)) {
    cli_error("toolchain options require --verify-project")
    return
  }
  let target = get_val(matches, "target", "native")
  if !["native", "js", "wasm", "wasm-gc"].contains(target) {
    cli_error("unknown target: " + target)
    return
  }
  if analysis == "semantic" && target != "native" {
    cli_error("semantic models currently require --target native")
    return
  }
  let seconds = @string.parse_int(get_val(matches, "timeout-seconds", "300")) catch {
    _ => 0
  }
  if seconds <= 0 || seconds > 86400 {
    cli_error("timeout-seconds must be between 1 and 86400")
    return
  }
  let severity = get_val(matches, "severity", "warning")
  if !["error", "warning", "info"].contains(severity) {
    cli_error("unknown severity: " + severity)
    return
  }
  let config_path = get_val(
    matches,
    "config",
    @path.Path(root).join(@path.Path(".moon-audit.json")).0,
  )
  if get_opt(matches, "config") is Some(_) || @fs.path_exists(config_path) {
    match read_json(config_path) {
      Some(Object(fields)) => {
        // Retired configuration must fail explicitly, never silently select a weaker engine.
        if fields.contains("taint") {
          cli_error(
            "taint configuration requires the retired interprocedural engine",
          )
          return
        }
        match fields.get("rules") {
          Some(Object(rules)) =>
            for id, _ in rules {
              if !@audit.list_all_rules().any(fn(r) {
                  @audit.rule_id_str(r.id) == id
                }) {
                cli_error("unsupported rule in config: " + id)
                return
              }
            }
          _ => ()
        }
      }
      Some(_) => {
        cli_error("config must be a JSON object")
        return
      }
      None => return
    }
  }
  if @fs.path_exists(@path.Path(root).join(@path.Path("taint-rules.json")).0) {
    cli_error("taint-rules.json is unsupported by the syntax-pattern scanner")
    return
  }
  let mut config = @audit.load_config(config_path)
  match get_opt(matches, "changed-files") {
    Some(path) => {
      let content = @audit.read_regular_text(path) catch {
        _ => {
          cli_error("cannot read changed-files list: " + path)
          return
        }
      }
      config = {
        ..config,
        changed_files: @audit.parse_changed_files(content),
        incremental: true,
      }
    }
    None => ()
  }
  match matches.values.get("rule") {
    Some(selected) if !selected.is_empty() => {
      let rules = @audit.list_all_rules()
      for id in selected {
        if !rules.any(fn(rule) { @audit.rule_id_str(rule.id) == id }) {
          cli_error("unknown rule: " + id)
          return
        }
      }
      for rule in rules {
        let id = @audit.rule_id_str(rule.id)
        let previous = config.rules.get(id)
        config.rules[id] = {
          enabled: selected.contains(id),
          severity: match previous {
            Some(p) => p.severity
            None => None
          },
        }
      }
    }
    _ => ()
  }
  let baseline_entries = match get_opt(matches, "baseline") {
    Some(path) => {
      match read_json(path) {
        Some(Array(_)) => ()
        Some(_) => {
          cli_error("baseline must be a JSON array")
          return
        }
        None => return
      }
      @audit.load_baseline(path)
    }
    None => Map([])
  }
  let verification = if verify {
    let executable = match (home, moon) {
      (Some(dir), _) => {
        let unix = @path.Path(dir).join(@path.Path("bin/moon")).0
        if @fs.path_exists(unix + ".exe") {
          unix + ".exe"
        } else {
          unix
        }
      }
      (_, Some(exe)) => @project.absolute(exe)
      _ => "moon"
    }
    Some(@project.verify(root, executable, home, target, seconds))
  } else {
    None
  }
  let selected = match verification {
    Some(v) if v.status == "compiler_verified" => Some(v.files)
    _ => None
  }
  let mut result = @audit.scan_project(root, config, compiler_files=selected)
  match verification {
    Some(v) => {
      let mut status = v.status
      if status == "compiler_verified" && !@project.unchanged(v.snapshot, root) {
        status = "project_changed"
      }
      let policy_excluded : Array[String] = []
      let missing : Array[String] = []
      for file in v.files {
        if @audit.excluded_by_policy(file, root, config) {
          policy_excluded.push(file)
          continue
        }
        let covered = result.file_coverage.any(fn(entry) {
          @project.absolute(entry.path) == file &&
          (
            entry.status == "parsed" ||
            (
              entry.status == "skipped" &&
              entry.reason == "not_in_changed_files"
            )
          )
        })
        if !covered {
          missing.push(file)
        }
      }
      if status == "compiler_verified" && !missing.is_empty() {
        status = "scope_incomplete"
      }
      if status == "compiler_verified" && !result.errors.is_empty() {
        status = "scanner_incomplete"
      }
      if status != "compiler_verified" {
        result.errors.push("project verification: " + status + ": " + v.detail)
      }
      let metadata = { ..v, status, }.to_json()
      if metadata is Object(fields) {
        fields["policy_excluded_files"] = Json::array(
          policy_excluded.map(Json::string),
        )
        fields["compiler_files_not_parsed"] = Json::array(
          missing.map(Json::string),
        )
      }
      result = { ..result, project_verification: Some(metadata), }
    }
    None => ()
  }
  if analysis == "semantic" && result.errors.is_empty() {
    let executable = match (home, moon) {
      (Some(dir), _) => {
        let name = @path.Path(dir).join(@path.Path("bin/moon")).0
        if @fs.path_exists(name + ".exe") {
          name + ".exe"
        } else {
          name
        }
      }
      (_, Some(exe)) => @project.absolute(exe)
      _ => "moon"
    }
    let report = @project.semantic_worker(
      root,
      executable,
      home,
      Int::min(seconds, 60),
    ) catch {
      e =>
        {
          "status": Json::string("incomplete"),
          "reason": Json::string(
            "semantic_worker_failed_or_budget: " + e.to_string(),
          ),
        }
    }
    let stable = match verification {
      Some(v) => @project.unchanged(v.snapshot, root)
      None => false
    }
    if !stable ||
      !(report is { "status": String("complete_within_declared_scope"), .. }) {
      result.errors.push(
        "semantic analysis incomplete; inspect semantic_analysis",
      )
    }
    for finding in @audit.semantic_findings(report) {
      result.findings.push(finding)
    }
    result = { ..result, semantic_analysis: Some(report), }
  }
  if baseline {
    if !result.errors.is_empty() {
      cli_error("scan incomplete; baseline was not written")
      return
    }
    write_output(
      @audit.generate_baseline(result.findings, root~),
      get_opt(matches, "output"),
    )
    return
  }
  let findings = @audit.filter_baseline(
    result.findings,
    baseline_entries,
    root~,
  ).filter(fn(f) {
    @audit.severity_level(f.severity) >=
    @audit.severity_level(@audit.severity_from_str(severity))
  })
  let filtered : @audit.ScanResult = { ..result, findings, }
  let report = match format {
    "json" => @audit.format_json(filtered)
    "sarif" => @audit.format_sarif(filtered)
    _ => @audit.format_text(filtered, flag(matches, "verbose"))
  }
  write_output(report, get_opt(matches, "output"))
  if !result.errors.is_empty() {
    @sys.exit(2)
  } else if flag(matches, "fail-on-error") &&
    findings.any(fn(f) { f.severity == @audit.Error }) {
    @sys.exit(1)
  }
}

///|
fn write_output(content : String, output : String?) -> Unit {
  match output {
    Some(path) =>
      @fs.write_string_to_file(path, content) catch {
        _ => cli_error("failed to write output file: " + path)
      }
    None => println(content)
  }
}
