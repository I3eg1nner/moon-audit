// Shared JSONC contract for scanner configuration and compiler input identity.

///|
fn parse_project_json(source : String) -> Json? {
  @project_config.parse_json(source)
}
