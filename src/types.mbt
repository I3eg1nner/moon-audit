///|
pub(all) enum Severity {
  Error
  Warning
  Info
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
  message : String
  file : String
  line : Int
  column : Int
  end_line : Int
  end_column : Int
  snippet : String
} derive(Debug)

///|
pub(all) struct ScanResult {
  findings : Array[Finding]
  files_scanned : Int
  errors : Array[String]
}

///|
pub(all) struct ImportContext {
  has_cmark : Bool
  has_rabbita : Bool
  has_mocket : Bool
  has_crescent : Bool
  has_liquid : Bool
  has_pug : Bool
}

///|
pub(all) struct Config {
  rules : Map[String, RuleConfig]
  exclude : Array[String]
  includes : Array[String]
  output_format : String
  min_severity : Severity
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
  }
}

///|
pub fn Config::default() -> Config {
  let rules : Map[String, RuleConfig] = {}
  rules["CWE-94/eval-extern"] = { enabled: false, severity: None }
  rules["CWE-79/inner-html"] = { enabled: false, severity: None }
  rules["CWE-22/path-concat"] = { enabled: false, severity: None }
  {
    rules,
    exclude: ["_build", ".mooncakes"],
    includes: [],
    output_format: "text",
    min_severity: Warning,
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
