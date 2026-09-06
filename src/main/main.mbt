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
      @argparse.OptionArg(
        "changed-files",
        long="changed-files",
        about="File containing changed file paths (one per line) for incremental scanning",
      ),
      @argparse.OptionArg(
        "baseline",
        long="baseline",
        about="Baseline file to exclude known findings",
      ),
      @argparse.OptionArg(
        "baseline-report",
        long="baseline-report",
        about="Previous scan report (JSON) to diff against: classifies findings as new/resolved/unchanged by fingerprint",
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
      @argparse.Command(
        "call-graph",
        about="M4 slice: closed-world call graph (CHA + devirtualization)",
        flags=[
          @argparse.FlagArg(
            "details",
            short='d',
            long="details",
            about="List all edges",
          ),
          @argparse.FlagArg(
            "conservative-alias",
            long="conservative-alias",
            about="Enable legacy short-key alias binding (default: strict)",
          ),
        ],
        positionals=[
          @argparse.PositionArg("path", about="Project path to analyze", default_values=[
            ".",
          ]),
        ],
      ),
      @argparse.Command(
        "ir-stats",
        about="M1 IR spike: measure type-reconstruction call-site resolution rate",
        flags=[
          @argparse.FlagArg(
            "details",
            short='d',
            long="details",
            about="List unresolved call sites",
          ),
          @argparse.FlagArg(
            "conservative-alias",
            long="conservative-alias",
            about="Enable legacy short-key alias binding (default: strict)",
          ),
          @argparse.FlagArg(
            "live-vars",
            long="live-vars",
            about="T3.4: live-variable summary per function on the HIR statement layer",
          ),
        ],
        positionals=[
          @argparse.PositionArg("path", about="Project path to analyze", default_values=[
            ".",
          ]),
        ],
      ),
      @argparse.Command(
        "generate-baseline",
        about="Generate a baseline file from current scan findings",
        options=[
          @argparse.OptionArg(
            "output",
            short='o',
            long="output",
            about="Baseline output file path",
            default_values=[".moon-audit-baseline.json"],
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
        "deep-audit",
        about="Generate LLM-powered deep security audit script (static + AI code review)",
        options=[
          @argparse.OptionArg(
            "output",
            short='o',
            long="output",
            about="Output script file path",
            default_values=["deep_audit.py"],
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
    Some(("generate-baseline", sub)) => cmd_generate_baseline(sub)
    Some(("ir-stats", sub)) => cmd_ir_stats(sub)
    Some(("call-graph", sub)) => cmd_call_graph(sub)
    Some(("deep-audit", sub)) => cmd_deep_audit(sub)
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
  // Taint rule DSL: show the effective taint vocabulary source
  let (rs, source) = @audit.load_taint_rules(".")
  println("")
  println("Taint rule vocabulary:")
  println("  source:      " + source)
  println(
    "  custom entries: " +
    rs.size().to_string() +
    " (sources " +
    rs.sources.length().to_string() +
    ", sinks " +
    rs.sinks.length().to_string() +
    ", sanitizers " +
    rs.sanitizers.length().to_string() +
    ")",
  )
  println(
    "  (built-in tables always apply; custom entries ADD — see docs/ir/RULES-DSL.md)",
  )
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
  config = { ..config, min_severity: severity_filter, }
  let changed_files_path = get_opt(matches, "changed-files")
  match changed_files_path {
    Some(cf_path) => {
      let changed = @audit.load_changed_files(cf_path)
      config = { ..config, changed_files: changed, }
      // T0.2/T0.4: incremental mode limits the scanned set; callers of a
      // changed function are NOT invalidated (G8) — the result describes
      // the changed files only, not the whole project
      println(
        "analysis-scope: incremental=true; scanned-files=" +
        changed.length().to_string() +
        "; caller-invalidation=not-implemented (G8 — affected callers of changed functions are NOT re-analyzed); unanalyzed-is-not-safe",
      )
    }
    None => ()
  }
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
          config.rules[id] = { enabled: false, severity: None, }
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
    println("moon-audit v0.2.1 - Static security scanner for MoonBit\n")
    println("Scanning: " + path)
    if config.changed_files.length() > 0 {
      println(
        "Incremental mode: " +
        config.changed_files.length().to_string() +
        " changed file(s)",
      )
    }
    println("")
  }
  let result = @audit.scan_project(path, config)
  let baseline_path = get_opt(matches, "baseline")
  let baseline = match baseline_path {
    Some(bp) => @audit.load_baseline(bp)
    None => Map([])
  }
  let after_baseline = @audit.filter_baseline(result.findings, baseline)
  let baseline_filtered = result.findings.length() - after_baseline.length()
  if baseline_filtered > 0 && !quiet && !machine_output {
    println(
      "Baseline: filtered " +
      baseline_filtered.to_string() +
      " known finding(s)",
    )
  }
  let filtered_findings = after_baseline.filter(fn(f) {
    @audit.severity_level(f.severity) >= @audit.severity_level(severity_filter)
  })
  let filtered_result : @audit.ScanResult = {
    findings: filtered_findings,
    files_scanned: result.files_scanned,
    errors: result.errors,
    analysis_scope: result.analysis_scope,
  }
  // Acceptance mode: diff against a previous scan report (TP/FP/FN tracking)
  let baseline_report_path = get_opt(matches, "baseline-report")
  let diff = match baseline_report_path {
    Some(brp) => {
      let content = @fs.read_file_to_string(brp) catch {
        _ => {
          println("moon-audit: error: cannot read baseline report: " + brp)
          return
        }
      }
      let prev = @audit.parse_report_findings(content)
      Some(@audit.diff_findings(filtered_findings, prev))
    }
    None => None
  }
  let output = if format == "json" {
    match diff {
      Some(d) => @audit.format_json_with_diff(filtered_result, d)
      None => @audit.format_json(filtered_result)
    }
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
  // text mode: print the baseline-diff summary after the report
  match (diff, machine_output, quiet) {
    (Some(d), false, false) => println(@audit.format_baseline_diff(d))
    _ => ()
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
  let sources : Map[String, String] = Map([])
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
    let buf = StringBuilder()
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
    let buf = StringBuilder()
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
    let buf = StringBuilder()
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
  let sources : Map[String, String] = Map([])
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

///|
fn cmd_generate_baseline(matches : @argparse.Matches) -> Unit {
  let path = get_val(matches, "path", ".")
  let config_path = get_val(matches, "config", ".moon-audit.json")
  let output_path = get_val(matches, "output", ".moon-audit-baseline.json")
  let resolved_config = if config_path == ".moon-audit.json" {
    @path.Path(path).join(@path.Path(config_path)).0
  } else {
    config_path
  }
  let config = @audit.load_config(resolved_config)
  let path_ok = @fs.is_dir(path) catch { _ => false }
  if !path_ok {
    println("moon-audit: error: path not found or not a directory: " + path)
    return
  }
  println("moon-audit: generating baseline from: " + path)
  let result = @audit.scan_project(path, config)
  let baseline = @audit.generate_baseline(result.findings)
  @fs.write_string_to_file(output_path, baseline) catch {
    err => {
      let _ = err
      println("moon-audit: error: failed to write baseline to " + output_path)
      return
    }
  }
  println(
    "Baseline written to: " +
    output_path +
    " (" +
    result.findings.length().to_string() +
    " findings)",
  )
  println("Use --baseline " + output_path + " to filter these in future scans")
}

///|
fn cmd_deep_audit(matches : @argparse.Matches) -> Unit {
  let path = get_val(matches, "path", ".")
  let output_path = get_val(matches, "output", "deep_audit.py")
  let config_path = get_val(matches, "config", ".moon-audit.json")
  let resolved_config = if config_path == ".moon-audit.json" {
    @path.Path(path).join(@path.Path(config_path)).0
  } else {
    config_path
  }
  let config = @audit.load_config(resolved_config)
  let path_ok = @fs.is_dir(path) catch { _ => false }
  if !path_ok {
    println("moon-audit: error: path not found: " + path)
    return
  }
  println("moon-audit Deep Audit\n")
  println("Scanning: " + path)
  let result = @audit.scan_project(path, config)
  println("Static findings: " + result.findings.length().to_string())
  let source_files = @audit.collect_audit_files(path, config)
  println("Source files collected: " + source_files.length().to_string())
  let llm_config = @audit.load_llm_config(path)
  println("LLM: " + llm_config.model + " @ " + llm_config.base_url)
  if llm_config.api_key.length() == 0 {
    println("\nWarning: No API key configured. Set LLM_API_KEY in .env")
  }
  println("")
  let script = @audit.generate_deep_audit_script(
    llm_config,
    result.findings,
    source_files,
  )
  @fs.write_string_to_file(output_path, script) catch {
    _ => {
      println("Error writing script: " + output_path)
      return
    }
  }
  println("Generated: " + output_path)
  println("")
  println("Run the deep audit:")
  println("  python3 " + output_path)
  println("")
  println("The script will:")
  println(
    "  1. Verify " +
    result.findings.length().to_string() +
    " static findings with LLM (true/false positive)",
  )
  println(
    "  2. Send " +
    source_files.length().to_string() +
    " source files for deep security review",
  )
  println("  3. Save combined report to deep_audit_report.json")
}

///|
// enumerate .mbt source files under root with the standard excludes

///|
fn collect_mbt_files(root : String) -> Array[String] {
  let out : Array[String] = []
  fn walk(dir : String) -> Unit {
    let entries = @fs.read_dir(dir) catch { _ => return }
    for entry in entries {
      if entry.has_prefix(".") ||
        entry == "_build" ||
        entry == "examples" ||
        entry == "benchmarks" {
        continue
      }
      let full = @path.Path(dir).join(@path.Path(entry)).0
      let is_dir = @fs.is_dir(full) catch { _ => false }
      if is_dir {
        walk(full)
      } else if entry.has_suffix(".mbt") &&
        !entry.has_suffix("_test.mbt") &&
        !entry.has_suffix("_wbtest.mbt") {
        out.push(full)
      }
    }
  }
  walk(root)
  out
}

///|
fn cmd_ir_stats(matches : @argparse.Matches) -> Unit {
  let path = get_val(matches, "path", ".")
  let details = match matches.flags.get("details") {
    Some(v) => v
    None => false
  }
  let live_vars = match matches.flags.get("live-vars") {
    Some(v) => v
    None => false
  }
  println("moon-audit ir-stats (M1 type-reconstruction spike)")
  println("target: " + path)
  println("")
  // measurement tools use the standard exclude set (examples/benchmarks
  // are not product code) instead of inheriting the tool repo's config
  let config = @audit.Config::default()
  let conservative = match matches.flags.get("conservative-alias") {
    Some(v) => v
    None => false
  }
  let stats = @audit.run_ir_stats(path, config, conservative_alias=conservative)
  println(
    "alias mode: " +
    (if conservative {
      "conservative (legacy short-key binding)"
    } else {
      "strict (default; fallback misses count as unknown(alias))"
    }),
  )
  println("files scanned:  " + stats.files_scanned.to_string())
  println("funcs scanned:  " + stats.funcs_scanned.to_string())
  println("call sites:     " + stats.total_calls.to_string())
  println("")
  println(
    "static calls:   " +
    stats.static_calls.to_string() +
    "  resolved " +
    stats.static_resolved.to_string() +
    " (" +
    pct(stats.static_resolved, stats.static_calls) +
    ")",
  )
  println(
    "receiver calls: " +
    stats.receiver_calls.to_string() +
    "  concrete " +
    stats.receiver_resolved.to_string() +
    " (" +
    pct(stats.receiver_resolved, stats.receiver_calls) +
    ")  dispatch " +
    stats.receiver_dispatch.to_string() +
    "  pt-resolved " +
    stats.pt_resolved_dispatch().to_string() +
    "  unknown " +
    stats.receiver_unknown.to_string(),
  )
  println(
    "higher-order:   " +
    stats.higher_calls.to_string() +
    "  (closure/callback callees — M2/M4 scope)",
  )
  println("")
  // T0.2: split metrics — no single mixed-denominator percentage.
  // - bound sites = call sites with a KNOWN target function (static
  //   confirmed + receiver-with-impl-hit)
  // - candidates = devirtualized/dyn sites contributing candidate edges
  //   (candidate != bound)
  // - unknown = no target identified, with reason buckets
  println("metrics (T0.2 split — legacy 'combined' kept for continuity):")
  println(
    "  bound sites:     " +
    (stats.static_resolved + stats.receiver_resolved).to_string() +
    "/" +
    stats.total_calls.to_string(),
  )
  println(
    "  candidate sites: " +
    stats.receiver_dispatch.to_string() +
    "  (dyn/trait-object — candidate edges, NOT bound)",
  )
  println(
    "  unknown sites:   " +
    (stats.receiver_unknown +
    (stats.static_calls - stats.static_resolved) +
    stats.higher_calls).to_string() +
    "  (receiver=" +
    stats.receiver_unknown.to_string() +
    " static=" +
    (stats.static_calls - stats.static_resolved).to_string() +
    " higher=" +
    stats.higher_calls.to_string() +
    ")",
  )
  // T0.2: unknown-site reason classification (four classes)
  let mut ffi = 0
  let mut cascade = 0
  let mut higher = 0
  let mut unsupported = 0
  let alias_unresolved = stats.alias_unresolved
  for site in stats.sites {
    // dispatch sites are CANDIDATES (reported above), not unknown
    let is_dispatch = site.recv_ty.has_prefix("trait:") ||
      site.recv_ty.has_prefix("T:")
    if !site.resolved && !is_dispatch {
      match site_reason(site) {
        "ffi" => ffi += 1
        "cascade" => cascade += 1
        "higher" => higher += 1
        _ => unsupported += 1
      }
    }
  }
  println(
    "  unknown by reason: ffi=" +
    ffi.to_string() +
    "  cascade=" +
    cascade.to_string() +
    "  higher=" +
    higher.to_string() +
    "  unsupported=" +
    unsupported.to_string() +
    "  alias=" +
    alias_unresolved.to_string() +
    "  (alias = strict-mode short-key fallback misses; see --conservative-alias)",
  )
  if live_vars {
    // T3.4: second analysis on the SAME HIR statement layer — no taint
    // semantics involved (live_vars consumes Array[Stmt] only)
    println("")
    println("live variables (T3.4, shared HIR layer):")
    let mut total_fns = 0
    let mut total_decls = 0
    let mut total_dead = 0
    let files = collect_mbt_files(path)
    for file in files {
      let source = @fs.read_file_to_string(file) catch { _ => continue }
      let (impls, _) = @parser.parse_string(source, name=file)
      for pair in @audit.collect_fn_traces(impls, file, source) {
        total_fns += 1
        let summary = @audit.live_vars_of_trace(pair.1)
        total_decls += summary.total
        total_dead += summary.dead
        println(
          "  " +
          pair.0 +
          ": " +
          @audit.live_vars_line(summary) +
          "  | " +
          @audit.live_vars_examples(summary, 2),
        )
      }
    }
    println(
      "  -- " +
      total_fns.to_string() +
      " funcs, " +
      total_decls.to_string() +
      " decls, " +
      total_dead.to_string() +
      " dead",
    )
  }
  if details {
    println("")
    println("unknown-site reasons (per site):")
    for site in stats.sites {
      if !site.resolved {
        println(
          "  [" +
          site_reason(site) +
          "] " +
          site.kind +
          " " +
          site.file +
          ":" +
          site.line.to_string() +
          "  target=" +
          site.target +
          "  recv=" +
          site.recv_ty,
        )
      }
    }
  }
}

///|
// T0.2 unknown-site reason classes:
//   ffi          — site lives in an FFI binding context (native/js/mongoose)
//   higher       — callee is a function value (closure/callback)
//   cascade      — receiver type lost via an unresolved chain
//   unsupported  — static identity not established (cross-pkg, no decl)
fn site_reason(site : @audit.CallSiteStat) -> String {
  if site.kind == "higher" {
    return "higher"
  }
  let f = site.file
  if f.contains("/native/") ||
    f.contains("/js/") ||
    f.contains("mongoose") ||
    f.contains(".native.") ||
    f.contains(".js.") {
    return "ffi"
  }
  if site.kind == "receiver" {
    return "cascade"
  }
  "unsupported"
}

///|
fn pct(num : Int, den : Int) -> String {
  if den == 0 {
    return "0%"
  }
  (num * 100 / den).to_string() + "%"
}

///|
fn cmd_call_graph(matches : @argparse.Matches) -> Unit {
  let path = get_val(matches, "path", ".")
  let details = match matches.flags.get("details") {
    Some(v) => v
    None => false
  }
  println("moon-audit call-graph (M4 closed-world slice)")
  println("target: " + path)
  println("")
  let config = @audit.Config::default()
  let conservative = match matches.flags.get("conservative-alias") {
    Some(v) => v
    None => false
  }
  let cg = @audit.run_call_graph(path, config, conservative_alias=conservative)
  println(
    "alias mode: " +
    (if conservative {
      "conservative (legacy short-key binding)"
    } else {
      "strict (default)"
    }),
  )
  println("direct edges:      " + cg.edges.length().to_string())
  println(
    "dispatch edges:    " +
    cg.dispatch_edges.length().to_string() +
    "  (devirtualized via impl enumeration)",
  )
  println("unresolved edges:  " + cg.unresolved.length().to_string())
  // T4c-2: dispatch sites whose candidate set was REFINED by the
  // receiver's points-to types (intersection with impl enumeration)
  println(
    "pt-resolved dispatch: " +
    cg.pt_resolved_sites.to_string() +
    "  (receiver points-to types narrowed the target set)",
  )
  // T0.2: candidate-edge sets are reported separately from bound edges;
  // the legacy single 'edge coverage' percentage mixed candidate edges
  // into the numerator and is removed (review counterexample: 1 of 2
  // sites with candidate sets showed 75% via 3 candidate edges)
  println(
    "candidate-set size: total dispatch edges / sites with candidates = " +
    cg.dispatch_edges.length().to_string() +
    "/" +
    cg.candidate_sites.to_string() +
    "  (avg " +
    avg_set_size(cg) +
    ")",
  )
  // T0.2(b): per-site coverage — denominator is CALL SITES, never edges
  println(
    "site coverage:      " +
    (
      (cg.bound_sites + cg.candidate_sites).to_string() +
      "/" +
      cg.site_total().to_string() +
      " = " +
      cg.site_coverage().to_string() +
      "%  (denominator = call sites; a 13-target candidate set is ONE site)"
    ),
  )
  println("note: candidate != bound (T0.2 four-level status vocabulary)")
  if details {
    println("")
    println("edges:")
    for e in cg.edges {
      println("  " + e)
    }
    println("dispatch edges:")
    for e in cg.dispatch_edges {
      println("  " + e)
    }
  }
}

///|

///|
fn avg_set_size(cg : @audit.CallGraph) -> String {
  let sites = cg.candidate_sites
  if sites == 0 {
    return "0"
  }
  (cg.dispatch_edges.length() / sites).to_string()
}
