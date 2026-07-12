///|
pub fn format_sarif(result : ScanResult) -> String {
  let rule_descriptors : Array[Json] = []
  let seen_rules : Map[String, Bool] = {}
  for f in result.findings {
    let id = rule_id_str(f.rule_id)
    if !seen_rules.contains(id) {
      seen_rules[id] = true
      rule_descriptors.push(rule_to_sarif_descriptor(f.rule_id))
    }
  }
  let sarif_results : Array[Json] = []
  for f in result.findings {
    sarif_results.push(finding_to_sarif(f))
  }
  let sarif : Json = {
    "$schema": Json::string(
      "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
    ),
    "version": Json::string("2.1.0"),
    "runs": Json::array([
      {
        "tool": {
          "driver": {
            "name": Json::string("moon-audit"),
            "version": Json::string("0.1.0"),
            "rules": Json::array(rule_descriptors),
          },
        },
        "results": Json::array(sarif_results),
      },
    ]),
  }
  sarif.stringify(indent=2)
}

///|
fn rule_to_sarif_descriptor(id : RuleId) -> Json {
  let info = get_rule_info_by_id(id)
  {
    "id": Json::string(rule_id_str(id)),
    "shortDescription": { "text": Json::string(info.name) },
    "helpUri": Json::string(
      "https://cwe.mitre.org/data/definitions/" + id.cwe.to_string() + ".html",
    ),
  }
}

///|
fn finding_to_sarif(f : Finding) -> Json {
  let level = match f.severity {
    Error => "error"
    Warning => "warning"
    Info => "note"
  }
  {
    "ruleId": Json::string(rule_id_str(f.rule_id)),
    "level": Json::string(level),
    "message": { "text": Json::string(f.message) },
    "locations": Json::array([
      {
        "physicalLocation": {
          "artifactLocation": { "uri": Json::string(f.file) },
          "region": {
            "startLine": Json::number(f.line.to_double()),
            "startColumn": Json::number(f.column.to_double()),
            "endLine": Json::number(f.end_line.to_double()),
            "endColumn": Json::number(f.end_column.to_double()),
          },
        },
      },
    ]),
    "partialFingerprints": { "moon-audit/v1": Json::string(f.fingerprint) },
    "properties": { "confidence": Json::string(confidence_str(f.confidence)) },
  }
}

///|
fn get_rule_info_by_id(id : RuleId) -> RuleInfo {
  let rules = list_all_rules()
  for rule in rules {
    if rule.id.cwe == id.cwe && rule.id.variant == id.variant {
      return rule
    }
  }
  { id, name: rule_id_str(id), description: "", default_severity: Warning }
}
