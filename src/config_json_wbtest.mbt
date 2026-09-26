///|
test "project JSONC keeps strings and accepts only lexical extensions" {
  let actual = parse_project_json(
    (
      #|{ // line
      #|  "name": "fixture/app", /* block */
      #|  "url": "https://example.com/a/*path*/",
      #|  "quote": "\"// still a string",
      #|  "arr": [1, {"nested": true,},],
      #|}
    ),
  )
  assert_eq(
    actual,
    Some({
      "name": "fixture/app",
      "url": "https://example.com/a/*path*/",
      "quote": "\"// still a string",
      "arr": [1, { "nested": true }],
    }),
  )
}

///|
test "project JSONC does not accept wider JSON5 or broken syntax" {
  for
    text in [
      "{name:1}", "{'name':'x'}", "{\"x\": NaN}", "{\"x\": 0x10}", "{,}", "[,]",
      "[1,,]", "{\"name\":,}", "{\"x\":1/*gap*/2}", "{\"name\":\"x\"} /*", "\uFEFF{\"name\":\"x\"}",
    ] {
    assert_eq(parse_project_json(text), None)
  }
}

///|
test "project JSONC rejects escaped duplicate root keys and ignores nested names" {
  assert_eq(
    parse_project_json(
      "{\"name\":\"app\",\"na\\u006de\":\"moonbitlang/core\",}",
    ),
    None,
  )
  assert_true(
    parse_project_json(
      "{\"name\":\"app\",\"extra\":{\"name\":\"moonbitlang/core\"},}",
    )
    is Some(_),
  )
}
