///|
test "frontend preserves byte return value and source location" {
  let source = "pub fn empty() -> Bytes {\n  return b\"ok\"\n}"
  let (items, reports) = @src.parse_source(source, name="bytes.mbt")
  inspect(reports.length(), content="0")
  inspect(items.length(), content="1")
  let mut found = false
  for item in items {
    match item {
      TopFuncDef(
        decl_body=DeclBody(
          expr=Return(return_value=Some(Constant(c=Bytes(value), loc~)), ..)
        ),
        ..
      ) => {
        inspect(value, content="ok")
        inspect(loc.start.fname, content="bytes.mbt")
        inspect(loc.start.lnum, content="2")
        found = true
      }
      _ => ()
    }
  }
  inspect(found, content="true")
}

///|
test "frontend keeps original diagnostics when both parsers reject input" {
  let source = "pub fn broken() -> Bytes { return b\"\" + }"
  let (_, primary) = @official_parser.parse_string(source, name="broken.mbt")
  let (_, actual) = @src.parse_source(source, name="broken.mbt")
  inspect(actual.length() > 0, content="true")
  inspect(actual.length() == primary.length(), content="true")
  for i in 0..<actual.length() {
    inspect(actual[i].msg == primary[i].msg, content="true")
    inspect(actual[i].loc == primary[i].loc, content="true")
  }
}

///|
test "frontend retains primary AST for accepted current syntax" {
  let source = "pub fn cleanup() -> Unit { errdefer (); () }"
  let (primary, reports) = @official_parser.parse_string(
    source,
    name="cleanup.mbt",
  )
  let (actual, errors) = @src.parse_source(source, name="cleanup.mbt")
  inspect(reports.length(), content="0")
  inspect(errors.length(), content="0")
  inspect(
    actual.map(fn(i) { i.json_repr() }) == primary.map(fn(i) { i.json_repr() }),
    content="true",
  )
}
