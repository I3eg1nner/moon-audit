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
      @argparse.FlagArg(
        "fail-on-error",
        long="fail-on-error",
        about="Exit with code 1 when error-level findings exist (for CI gating)",
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
      @argparse.Command(
        "llm-analyze",
        about="Generate LLM analysis prompts for findings",
        options=[
          @argparse.OptionArg(
            "format",
            short='f',
            long="format",
            about="Output format: script (auto-run Python), json (API bodies), text (readable)",
            default_values=["json"],
          ),
          @argparse.OptionArg(
            "output",
            short='o',
            long="output",
            about="Write prompts to file",
          ),
          @argparse.OptionArg(
            "config",
            short='c',
            long="config",
            about="Config file path",
            default_values=[".moon-audit.json"],
          ),
        ],
        positionals=[
          @argparse.PositionArg("path", about="Project path to scan", default_values=[
            ".",
          ]),
        ],
      ),
      @argparse.Command(
        "generate-poc",
        about="Generate PoC exploit scripts from findings",
        options=[
          @argparse.OptionArg(
            "output",
            short='o',
            long="output",
            about="Write PoC report to file",
          ),
          @argparse.OptionArg(
            "config",
            short='c',
            long="config",
            about="Config file path",
            default_values=[".moon-audit.json"],
          ),
        ],
        positionals=[
          @argparse.PositionArg("path", about="Project path to scan", default_values=[
            ".",
          ]),
        ],
      ),
      @argparse.Command(
        "remediate",
        about="Generate remediation guide from findings",
        options=[
          @argparse.OptionArg(
            "output",
            short='o',
            long="output",
            about="Write remediation report to file",
          ),
          @argparse.OptionArg(
            "config",
            short='c',
            long="config",
            about="Config file path",
            default_values=[".moon-audit.json"],
          ),
        ],
        positionals=[
          @argparse.PositionArg("path", about="Project path to scan", default_values=[
            ".",
          ]),
        ],
      ),
      @argparse.Command(
        "pipeline",
        about="Run analysis pipeline: scan + taint + summary",
        flags=[
          @argparse.FlagArg(
            "fail-on-error",
            long="fail-on-error",
            about="Exit with code 1 when error-level findings exist",
          ),
        ],
        options=[
          @argparse.OptionArg(
            "output-dir",
            short='d',
            long="output-dir",
            about="Output directory for all reports (default: moon-audit-report)",
            default_values=["moon-audit-report"],
          ),
          @argparse.OptionArg(
            "config",
            short='c',
            long="config",
            about="Config file path",
            default_values=[".moon-audit.json"],
          ),
        ],
        positionals=[
          @argparse.PositionArg("path", about="Project path to scan", default_values=[
            ".",
          ]),
        ],
      ),
      @argparse.Command(
        "summary",
        about="Show scan summary with statistics",
        options=[
          @argparse.OptionArg(
            "format",
            short='f',
            long="format",
            about="Output format: text, json",
            default_values=["text"],
          ),
          @argparse.OptionArg(
            "output",
            short='o',
            long="output",
            about="Write summary to file",
          ),
          @argparse.OptionArg(
            "config",
            short='c',
            long="config",
            about="Config file path",
            default_values=[".moon-audit.json"],
          ),
        ],
        positionals=[
          @argparse.PositionArg("path", about="Project path to scan", default_values=[
            ".",
          ]),
        ],
      ),
    ],
  )
  let matches = cmd.parse() catch {
    e => {
      println("Error: " + e.to_string())
      println(cmd.render_help())
      @sys.exit(2)
      return
    }
  }
  match matches.subcommand {
    Some(("list-rules", _)) => cmd_list_rules()
    Some(("llm-analyze", sub)) => cmd_llm_analyze(sub)
    Some(("generate-poc", sub)) => cmd_generate_poc(sub)
    Some(("remediate", sub)) => cmd_remediate(sub)
    Some(("pipeline", sub)) => cmd_pipeline(sub)
    Some(("summary", sub)) => cmd_summary(sub)
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
  let fail_on_error = match matches.flags.get("fail-on-error") {
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
  let resolved_config_path = if config_path == ".moon-audit.json" {
    @path.Path(path).join(@path.Path(config_path)).0
  } else {
    config_path
  }
  let mut config = @audit.load_config(resolved_config_path)
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
  let path_ok = @fs.is_dir(path) catch { _ => false }
  if !path_ok {
    println("moon-audit: error: path not found or not a directory: " + path)
    return
  }
  let machine_output = format == "json" || format == "sarif"
  if !quiet && !machine_output {
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
        err => {
          let _ = err
          println("moon-audit: error: failed to write output file: " + out_path)
        }
      }
      if !quiet && !machine_output {
        println("Output written to: " + out_path)
      }
    }
    None => println(output)
  }
  if result.errors.length() > 0 && !quiet && !machine_output {
    println("")
    println(
      "Scan completed with " +
      result.errors.length().to_string() +
      " file error(s):",
    )
    for e in result.errors {
      println("  " + e)
    }
  }
  if fail_on_error {
    let has_errors = filtered_findings
      .iter()
      .any(fn(f) { f.severity == @audit.Error })
    if has_errors {
      @sys.exit(1)
    }
  }
}

///|
fn get_val(
  matches : @argparse.Matches,
  key : String,
  default : String,
) -> String {
  match matches.values.get(key) {
    Some(arr) => if arr.length() > 0 { arr[0] } else { default }
    None => default
  }
}

///|
fn get_opt(matches : @argparse.Matches, key : String) -> String? {
  match matches.values.get(key) {
    Some(arr) => if arr.length() > 0 { Some(arr[0]) } else { None }
    None => None
  }
}

///|
fn write_pipeline_file(path : String, content : String) -> Unit {
  @fs.write_string_to_file(path, content) catch {
    err => {
      let _ = err
      println("moon-audit: error: failed to write " + path)
    }
  }
}

///|
fn write_output(content : String, output_file : String?) -> Unit {
  match output_file {
    Some(out_path) => {
      @fs.write_string_to_file(out_path, content) catch {
        _ => println("Error writing output file")
      }
      println("Output written to: " + out_path)
    }
    None => println(content)
  }
}

///|
fn do_scan(matches : @argparse.Matches) -> @audit.ScanResult? {
  let path = get_val(matches, "path", ".")
  let path_ok = @fs.is_dir(path) catch { _ => false }
  if !path_ok {
    println("moon-audit: error: path not found or not a directory: " + path)
    return None
  }
  let config_path = get_val(matches, "config", ".moon-audit.json")
  let resolved_config = if config_path == ".moon-audit.json" {
    @path.Path(path).join(@path.Path(config_path)).0
  } else {
    config_path
  }
  let config = @audit.load_config(resolved_config)
  Some(@audit.scan_project(path, config))
}

///|
fn cmd_llm_analyze(matches : @argparse.Matches) -> Unit {
  let format = get_val(matches, "format", "json")
  let output_file = get_opt(matches, "output")
  let path = get_val(matches, "path", ".")
  println("moon-audit LLM Analysis\n")
  println("Scanning: " + path + "\n")
  let result = match do_scan(matches) {
    Some(r) => r
    None => return
  }
  if result.findings.length() == 0 {
    println("No findings to analyze.")
    return
  }
  println(
    "Found " +
    result.findings.length().to_string() +
    " finding(s), preparing LLM analysis...\n",
  )
  let llm_config = @audit.load_llm_config(path)
  println("LLM Config:")
  println("  Base URL: " + llm_config.base_url)
  println("  Model:    " + llm_config.model)
  if llm_config.api_key.length() > 0 {
    let end = if llm_config.api_key.length() > 8 {
      8
    } else {
      llm_config.api_key.length()
    }
    let masked = llm_config.api_key[0:end].to_owned()
    println("  API Key:  " + masked + "...")
  } else {
    println("  API Key:  (not set - configure LLM_API_KEY in .env)")
  }
  println("")
  let sources : Map[String, String] = {}
  for f in result.findings {
    if !sources.contains(f.file) {
      let content = @fs.read_file_to_string(f.file) catch { _ => "" }
      sources[f.file] = content
    }
  }
  let imports = @audit.ImportContext::empty()
  let requests = @audit.generate_batch_prompts(
    result.findings,
    sources,
    imports,
  )
  if format == "script" || format == "run" {
    let script = @audit.generate_llm_script(llm_config, requests)
    let script_file = match output_file {
      Some(f) => f
      None => "llm_analyze.py"
    }
    @fs.write_string_to_file(script_file, script) catch {
      _ => {
        println("Error writing script file")
        return
      }
    }
    println("Generated: " + script_file)
    println("")
    println("Run the analysis:")
    println("  python3 " + script_file)
  } else if format == "json" {
    let buf = StringBuilder::new()
    buf.write_string("[\n")
    for i, req in requests {
      if i > 0 {
        buf.write_string(",\n")
      }
      buf.write_string(@audit.format_prompt_as_json(req))
    }
    buf.write_string("\n]")
    write_output(buf.to_string(), output_file)
  } else {
    let buf = StringBuilder::new()
    buf.write_string("# LLM Analysis Prompts\n\n")
    buf.write_string(
      "Use these prompts with Claude or other LLMs to verify findings.\n\n",
    )
    for i, req in requests {
      buf.write_string("## Finding ")
      buf.write_string((i + 1).to_string())
      buf.write_string(": ")
      buf.write_string(@audit.rule_id_str(req.finding.rule_id))
      buf.write_string(" (")
      buf.write_string(req.finding.file)
      buf.write_string(":")
      buf.write_string(req.finding.line.to_string())
      buf.write_string(")\n\n")
      buf.write_string("### System Prompt\n\n```\n")
      buf.write_string(req.system_prompt)
      buf.write_string("\n```\n\n")
      buf.write_string("### User Prompt\n\n```\n")
      buf.write_string(req.prompt)
      buf.write_string("\n```\n\n---\n\n")
    }
    write_output(buf.to_string(), output_file)
  }
}

///|
fn cmd_generate_poc(matches : @argparse.Matches) -> Unit {
  let output_file = get_opt(matches, "output")
  let path = get_val(matches, "path", ".")
  println("moon-audit PoC Generator\n")
  println("Scanning: " + path + "\n")
  let result = match do_scan(matches) {
    Some(r) => r
    None => return
  }
  if result.findings.length() == 0 {
    println("No findings to generate PoC for.")
    return
  }
  let imports = @audit.ImportContext::empty()
  let pocs = @audit.generate_all_pocs(result.findings, imports)
  if pocs.length() == 0 {
    println("No PoC templates available for the detected finding types.")
    return
  }
  println("Generated " + pocs.length().to_string() + " PoC template(s)\n")
  let report = @audit.format_poc_report(pocs)
  write_output(report, output_file)
}

///|
fn cmd_remediate(matches : @argparse.Matches) -> Unit {
  let output_file = get_opt(matches, "output")
  let path = get_val(matches, "path", ".")
  println("moon-audit Remediation Guide Generator\n")
  println("Scanning: " + path + "\n")
  let result = match do_scan(matches) {
    Some(r) => r
    None => return
  }
  if result.findings.length() == 0 {
    println("No findings to remediate.")
    return
  }
  let remediations = @audit.get_all_remediations(result.findings)
  println(
    "Generated remediation guide for " +
    remediations.length().to_string() +
    " rule(s)\n",
  )
  let report = @audit.format_remediation_report(remediations)
  write_output(report, output_file)
}

///|
fn cmd_summary(matches : @argparse.Matches) -> Unit {
  let format = get_val(matches, "format", "text")
  let output_file = get_opt(matches, "output")
  let path = get_val(matches, "path", ".")
  println("moon-audit Scan Summary\n")
  println("Scanning: " + path + "\n")
  let result = match do_scan(matches) {
    Some(r) => r
    None => return
  }
  let rules = @audit.list_all_rules()
  let summary = @audit.build_summary(result, rules)
  let score = @audit.risk_score(summary)
  let level = @audit.risk_level(score)
  let output = if format == "json" {
    @audit.format_summary_json(summary)
  } else {
    let text = @audit.format_summary_text(summary)
    let buf = StringBuilder::new()
    buf.write_string(text)
    buf.write_string("\n  Risk Score: ")
    buf.write_string(score.to_string())
    buf.write_string(" / 100 (")
    buf.write_string(level)
    buf.write_string(")\n")
    buf.to_string()
  }
  write_output(output, output_file)
}

///|
fn cmd_pipeline(matches : @argparse.Matches) -> Unit {
  let path = get_val(matches, "path", ".")
  let out_dir = get_val(matches, "output-dir", "moon-audit-report")
  let fail_on_error = match matches.flags.get("fail-on-error") {
    Some(v) => v
    None => false
  }
  let config_path = get_val(matches, "config", ".moon-audit.json")
  let resolved_config = if config_path == ".moon-audit.json" {
    @path.Path(path).join(@path.Path(config_path)).0
  } else {
    config_path
  }
  println("=".repeat(60))
  println("  moon-audit Analysis Pipeline")
  println("=".repeat(60))
  println("")
  println("  Target:  " + path)
  println("  Output:  " + out_dir + "/")
  println("")
  let path_ok = @fs.is_dir(path) catch { _ => false }
  if !path_ok {
    println("moon-audit: error: path not found or not a directory: " + path)
    return
  }
  @fs.create_dir(out_dir) catch {
    err => {
      let _ = err
      println(
        "moon-audit: error: failed to create output directory: " + out_dir,
      )
      return
    }
  }
  let config = @audit.load_config(resolved_config)
  // Phase 1: Static scan
  println("[1/3] Static scan...")
  let result = @audit.scan_project(path, config)
  println(
    "      " +
    result.files_scanned.to_string() +
    " files scanned, " +
    result.findings.length().to_string() +
    " finding(s)",
  )
  let scan_text = @audit.format_text(result, true)
  let scan_path = @path.Path(out_dir).join(@path.Path("scan-results.txt")).0
  write_pipeline_file(scan_path, scan_text)
  let sarif = @audit.format_sarif(result)
  let sarif_path = @path.Path(out_dir).join(@path.Path("scan-results.sarif")).0
  write_pipeline_file(sarif_path, sarif)
  let json_out = @audit.format_json(result)
  let json_path = @path.Path(out_dir).join(@path.Path("scan-results.json")).0
  write_pipeline_file(json_path, json_out)
  if result.findings.length() == 0 {
    println("")
    println("No findings detected. Scan results written to " + out_dir + "/")
    println("Pipeline complete (phases 2-3 skipped: no findings to analyze).")
    return
  }
  // Phase 2: Taint analysis
  println("[2/3] Taint analysis...")
  let sources : Map[String, String] = {}
  for f in result.findings {
    if !sources.contains(f.file) {
      let content = @fs.read_file_to_string(f.file) catch { _ => "" }
      sources[f.file] = content
    }
  }
  let mod_imports = @audit.analyze_mod_imports(path)
  let all_flows : Array[@audit.TaintFlow] = []
  for file, source in sources {
    let (impls, _) = @parser.parse_string(source, name=file)
    let state = @audit.run_taint_analysis(impls, file, source, mod_imports)
    for flow in state.flows {
      all_flows.push(flow)
    }
  }
  let taint_report = @audit.format_taint_report(all_flows)
  let taint_path = @path.Path(out_dir).join(@path.Path("taint-analysis.txt")).0
  write_pipeline_file(taint_path, taint_report)
  println("      " + all_flows.length().to_string() + " taint flow(s) traced")
  // Phase 3: Summary
  println("[3/3] Summary report...")
  let rules = @audit.list_all_rules()
  let summary = @audit.build_summary(result, rules)
  let score = @audit.risk_score(summary)
  let level = @audit.risk_level(score)
  let summary_text = @audit.format_summary_text(summary)
  let summary_path = @path.Path(out_dir).join(@path.Path("summary.txt")).0
  write_pipeline_file(summary_path, summary_text)
  let summary_json = @audit.format_summary_json(summary)
  let summary_json_path = @path.Path(out_dir).join(@path.Path("summary.json")).0
  write_pipeline_file(summary_json_path, summary_json)
  // Final output
  println("")
  println("=".repeat(60))
  println("  Pipeline Complete")
  println("=".repeat(60))
  println("")
  println("  Findings:    " + result.findings.length().to_string())
  println("  Risk Score:  " + score.to_string() + " / 100 (" + level + ")")
  println("")
  println("  Output directory: " + out_dir + "/")
  println("    scan-results.txt      Static scan findings (text)")
  println("    scan-results.json     Static scan findings (JSON)")
  println("    scan-results.sarif    SARIF 2.1.0 (GitHub Code Scanning)")
  println("    taint-analysis.txt    Data flow taint traces")
  println("    summary.txt           Risk summary (text)")
  println("    summary.json          Risk summary (JSON)")
  println("")
  println("  Optional next steps:")
  println("    moon-audit llm-analyze " + path + "   # LLM-assisted triage")
  println("    moon-audit generate-poc " + path + "  # PoC exploit templates")
  println("    moon-audit remediate " + path + "     # Fix guide")
  if fail_on_error {
    let has_errors = result.findings
      .iter()
      .any(fn(f) { f.severity == @audit.Error })
    if has_errors {
      @sys.exit(1)
    }
  }
}
