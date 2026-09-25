// Shared official parser adapter; rule scanning owns no separate AST fallback.

///|
pub fn parse_source(
  source : String,
  name? : String = "",
) -> (@list.List[@syntax.Impl], Array[@basic.Report]) {
  @source_parser.parse_source(source, name~)
}
