///|
test "source literal spelling is decoded before HTML context analysis" {
  assert_eq(literal_value("plain <p>"), Some("plain <p>"))
  assert_eq(literal_value("<div id=\\\"app\\\">"), Some("<div id=\"app\">"))
  assert_eq(literal_value("\\\\u003c"), Some("\\u003c"))
  assert_eq(literal_value("\\n\\r\\t\\b\\f\\/"), Some("\n\r\t\b\u000c/"))
}

///|
test "unreviewed numeric escapes cannot conceal HTML delimiters" {
  for value in ["\\u003c", "\\u{3c}", "\\x3c", "\\074", "trailing\\"] {
    assert_eq(literal_value(value), None)
  }
}
