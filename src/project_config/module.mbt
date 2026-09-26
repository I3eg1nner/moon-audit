///|
pub fn parse_module(
  source : String,
  modern : Bool,
  name? : String = "",
) -> Json? {
  if !modern {
    return parse_json(source)
  }
  let (ast, reports) = @moon_config.parse_moon_mod(source, name~)
  if !reports.is_empty() || !@moon_config.validate_moon_mod(ast).is_empty() {
    return None
  }
  Some(ToJson::to_json(ast))
}

///|
pub fn module_name(source : String, modern : Bool) -> String? {
  match parse_module(source, modern) {
    Some({ "name": String(name), .. }) if !name.is_empty() => Some(name)
    _ => None
  }
}
