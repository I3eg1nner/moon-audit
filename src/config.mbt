///|
pub fn load_config(path : String) -> Config {
  let content = @fs.read_file_to_string(path) catch {
    _ => return Config::default()
  }
  let json = @json.parse(content) catch { _ => return Config::default() }
  parse_config(json)
}

///|
fn parse_config(json : Json) -> Config {
  let mut config = Config::default()
  match json {
    Object(obj) => {
      match obj.get("rules") {
        Some(Object(rules_obj)) =>
          rules_obj.each(fn(key, value) {
            match value {
              Object(rule_obj) => {
                let enabled = match rule_obj.get("enabled") {
                  Some(True) => true
                  Some(False) => false
                  _ => true
                }
                let severity : Severity? = match rule_obj.get("severity") {
                  Some(String(s)) => Some(severity_from_str(s))
                  _ => None
                }
                config.rules[key] = { enabled, severity }
              }
              _ => ()
            }
          })
        _ => ()
      }
      match obj.get("exclude") {
        Some(Array(arr)) => {
          let excludes : Array[String] = []
          for item in arr {
            match item {
              String(s) => excludes.push(s)
              _ => ()
            }
          }
          if excludes.length() > 0 {
            config = { ..config, exclude: excludes }
          }
        }
        _ => ()
      }
      match obj.get("output_format") {
        Some(String(fmt)) => config = { ..config, output_format: fmt }
        _ => ()
      }
      match obj.get("severity") {
        Some(String(s)) =>
          config = { ..config, min_severity: severity_from_str(s) }
        _ => ()
      }
    }
    _ => ()
  }
  config
}
