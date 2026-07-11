///|
fn main {
  let cmd = @argparse.Command(
    "moon-audit",
    about="Static security scanner for MoonBit projects",
    version="0.1.0",
    flags=[
      @argparse.FlagArg(
        "quiet",
        short='q',
        long="quiet",
        about="Only output findings",
      ),
      @argparse.FlagArg(
        "verbose",
        short='v',
        long="verbose",
        about="Show detailed scan info",
      ),
    ],
    options=[
      @argparse.OptionArg(
        "format",
        short='f',
        long="format",
        about="Output format: text, json, sarif",
        default_values=["text"],
      ),
      @argparse.OptionArg(
        "output",
        short='o',
        long="output",
        about="Write output to file",
      ),
      @argparse.OptionArg(
        "config",
        short='c',
        long="config",
        about="Config file path",
        default_values=[".moon-audit.json"],
      ),
      @argparse.OptionArg(
        "severity",
        long="severity",
        about="Minimum severity: error, warning, info",
        default_values=["warning"],
      ),
      @argparse.OptionArg(
        "rule",
        long="rule",
        about="Only run specific rule(s)",
      ),
    ],
    positionals=[
      @argparse.PositionArg("path", about="Project path to scan", default_values=[
        ".",
      ]),
    ],
    subcommands=[
      @argparse.Command("list-rules", about="List all available rules"),
    ],
  )
  let matches = cmd.parse() catch {
    e => {
      println("Error: " + e.to_string())
      println(cmd.render_help())
      @builtin.panic()
    }
  }
  match matches.subcommand {
    Some(("list-rules", _)) => cmd_list_rules()
    _ => cmd_scan(matches)
  }
}

///|
fn cmd_list_rules() -> Unit {
  let rules = @audit.list_all_rules()
  let config = @audit.Config::default()
  println("Available rules:\n")
  for rule in rules {
    let id = @audit.rule_id_str(rule.id)
    let sev = @audit.severity_str(rule.default_severity)
    let status = if config.is_enabled(id) { "on" } else { "off" }
    println("  " + id + " [" + sev + "] (" + status + ")")
    println("    " + rule.name)
    println("    " + rule.description)
    println("")
  }
  println("Rules marked (off) require project-level context and have higher")
  println("false-positive risk. Enable them in .moon-audit.json when needed.")
}

///|
fn cmd_scan(matches : @argparse.Matches) -> Unit {
  let path = match matches.values.get("path") {
    Some(arr) => if arr.length() > 0 { arr[0] } else { "." }
    None => "."
  }
  let config_path = match matches.values.get("config") {
    Some(arr) => if arr.length() > 0 { arr[0] } else { ".moon-audit.json" }
    None => ".moon-audit.json"
  }
  let format = match matches.values.get("format") {
    Some(arr) => if arr.length() > 0 { arr[0] } else { "text" }
    None => "text"
  }
  let output_file = match matches.values.get("output") {
    Some(arr) => if arr.length() > 0 { Some(arr[0]) } else { None }
    None => None
  }
  let verbose = match matches.flags.get("verbose") {
    Some(v) => v
    None => false
  }
  let quiet = match matches.flags.get("quiet") {
    Some(v) => v
    None => false
  }
  let severity_filter = match matches.values.get("severity") {
    Some(arr) =>
      if arr.length() > 0 {
        @audit.severity_from_str(arr[0])
      } else {
        @audit.Warning
      }
    None => @audit.Warning
  }
  let mut config = @audit.load_config(config_path)
  config = { ..config, min_severity: severity_filter }
  let rule_filter = match matches.values.get("rule") {
    Some(arr) => if arr.length() > 0 { Some(arr[0]) } else { None }
    None => None
  }
  match rule_filter {
    Some(rule_id) => {
      let all_rules = @audit.list_all_rules()
      for rule in all_rules {
        let id = @audit.rule_id_str(rule.id)
        if id != rule_id {
          config.rules[id] = { enabled: false, severity: None }
        }
      }
    }
    None => ()
  }
  if !quiet {
    println("moon-audit v0.1.0 - Static security scanner for MoonBit\n")
    println("Scanning: " + path)
    println("")
  }
  let result = @audit.scan_project(path, config)
  let filtered_findings = result.findings.filter(fn(f) {
    @audit.severity_level(f.severity) >= @audit.severity_level(severity_filter)
  })
  let filtered_result : @audit.ScanResult = {
    findings: filtered_findings,
    files_scanned: result.files_scanned,
    errors: result.errors,
  }
  let output = if format == "json" {
    @audit.format_json(filtered_result)
  } else if format == "sarif" {
    @audit.format_sarif(filtered_result)
  } else {
    @audit.format_text(filtered_result, verbose)
  }
  match output_file {
    Some(out_path) => {
      @fs.write_string_to_file(out_path, output) catch {
        _ => println("Error writing output file")
      }
      if !quiet {
        println("Output written to: " + out_path)
      }
    }
    None => println(output)
  }
  let has_errors = filtered_findings
    .iter()
    .any(fn(f) { f.severity == @audit.Error })
  if has_errors {
    @builtin.panic()
  }
}
