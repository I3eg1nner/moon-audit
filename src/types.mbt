///|
pub(all) enum Severity {
  Error
  Warning
  Info
} derive(Eq, Debug)

///|
pub(all) enum Confidence {
  High
  Medium
  Low
} derive(Eq, Debug)

///|
pub(all) struct RuleId {
  cwe : Int
  variant : String
} derive(Debug)

///|
pub(all) struct RuleInfo {
  id : RuleId
  name : String
  description : String
  default_severity : Severity
}

///|
pub(all) struct Finding {
  rule_id : RuleId
  severity : Severity
  confidence : Confidence
  message : String
  file : String
  line : Int
  column : Int
  end_line : Int
  end_column : Int
  snippet : String
  fingerprint : String
  evidence : String
  dataflow : Array[String]
} derive(Debug)

///|
pub(all) struct ScanResult {
  findings : Array[Finding]
  project_verification : Json?
  semantic_analysis : Json?
  files_scanned : Int // Legacy count: readable files with parse attempted.
  files_selected : Int // Files selected after excludes/incremental filtering.
  files_parsed : Int // Files parsed successfully and sent through enabled rules.
  errors : Array[String]
  analysis_scope : String // T0.4 disclosure: analyzer/excludes/parse-failures (+reserved)
  file_coverage : Array[FileCoverage]
  configured_excludes : Array[String]
  incremental : Bool
}

///|
pub(all) struct RuleCoverage {
  id : String
  status : String // evaluated, disabled, or gated_out
  reason : String
}

///|
pub(all) struct FileCoverage {
  path : String
  status : String // parsed, parse_failed, read_failed, unsupported, or skipped
  reason : String
  rules : Array[RuleCoverage]
}

///|
/// Development version for the reduced pattern scanner.
pub const ANALYZER_VERSION = "0.5.0-dev"

///|
/// Frontend spec pinned in moon.mod (moonbitlang/parser).
pub const PARSER_SPEC_VERSION = "0.4.0+moon-audit-legacy.1"

///|
pub(all) struct ImportContext {
  has_cmark : Bool
  has_rabbita : Bool
  has_mocket : Bool
  has_crescent : Bool
  has_liquid : Bool
  has_pug : Bool
  is_stdlib : Bool
}

///|
pub(all) struct Config {
  rules : Map[String, RuleConfig]
  exclude : Array[String]
  includes : Array[String]
  output_format : String
  min_severity : Severity
  changed_files : Array[String]
  incremental : Bool // Explicit empty change lists must scan zero files.
}

///|
pub(all) struct RuleConfig {
  enabled : Bool
  severity : Severity?
}

///|
pub fn ImportContext::empty() -> ImportContext {
  {
    has_cmark: false,
    has_rabbita: false,
    has_mocket: false,
    has_crescent: false,
    has_liquid: false,
    has_pug: false,
    is_stdlib: false,
  }
}

///|
pub fn Config::default() -> Config {
  let rules : Map[String, RuleConfig] = Map([])
  for entry in rule_registry() {
    rules[rule_id_str(entry.info.id)] = {
      enabled: entry.default_enabled,
      severity: None,
    }
  }
  {
    rules,
    exclude: ["_build", ".mooncakes", "examples", "benchmarks"],
    includes: [],
    output_format: "text",
    min_severity: Warning,
    changed_files: [],
    incremental: false,
  }
}

///|
pub fn Config::is_enabled(self : Config, rule_id : String) -> Bool {
  match self.rules.get(rule_id) {
    Some(rc) => rc.enabled
    None => true
  }
}

///|
pub fn Config::get_severity(
  self : Config,
  rule_id : String,
  default : Severity,
) -> Severity {
  match self.rules.get(rule_id) {
    Some(rc) =>
      match rc.severity {
        Some(s) => s
        None => default
      }
    None => default
  }
}

///|
pub fn rule_id_str(id : RuleId) -> String {
  "CWE-" + id.cwe.to_string() + "/" + id.variant
}

///|
pub fn severity_str(s : Severity) -> String {
  match s {
    Error => "error"
    Warning => "warning"
    Info => "info"
  }
}

///|
pub fn severity_from_str(s : String) -> Severity {
  if s == "error" {
    Error
  } else if s == "info" {
    Info
  } else {
    Warning
  }
}

///|
pub fn severity_level(s : Severity) -> Int {
  match s {
    Error => 3
    Warning => 2
    Info => 1
  }
}

///|
pub fn confidence_str(c : Confidence) -> String {
  match c {
    High => "high"
    Medium => "medium"
    Low => "low"
  }
}

///|
pub fn confidence_from_str(s : String) -> Confidence {
  if s == "high" {
    High
  } else if s == "low" {
    Low
  } else {
    Medium
  }
}

///|
pub extend Severity with Eq::{not_equal, equal}

///|
pub extend Severity with Debug::{to_repr}

///|
pub extend Confidence with Eq::{not_equal, equal}

///|
pub extend Confidence with Debug::{to_repr}

///|
pub extend RuleId with Debug::{to_repr}

///|
pub extend Finding with Debug::{to_repr}

///|
/// Changes when AST selection semantics change, independently of package version.
pub const PARSER_POLICY_VERSION = "handrolled-moonyacc-interpolation-v2"
