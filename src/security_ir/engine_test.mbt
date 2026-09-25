///|
fn operations() -> Array[@security_ir.Op] {
  [
    Request(1, 0),
    Query(2, 1, "request.query"),
    Literal(3, "q"),
    Lookup(4, 2, 3),
    Literal(5, ""),
    Default(6, 4, 5),
  ]
}

///|
fn check_tail(
  tail : Array[@security_ir.Op],
  limit? : Int = 10000,
) -> @security_ir.Result {
  @security_ir.analyze(
    [
      { id: "route", parameters: [0], operations: operations() + tail, },
      { id: "helper", parameters: [0], operations: [Return(0)], },
    ],
    "route",
    limit~,
  )
}

///|
test "only returned responder contributes an output path" {
  let raw = check_tail([
    Call(7, "helper", [6], "helper.call"),
    Response(8, 7, true, "html"),
    Return(8),
  ])
  assert_eq(raw.status, "complete")
  assert_eq(raw.source_paths, [
    ["request.query", "helper.call", "html", "route:route_response"],
  ])
  let discarded = check_tail([
    Response(7, 6, true, "discarded"),
    Literal(8, "constant"),
    Response(9, 8, true, "returned"),
    Return(9),
  ])
  assert_eq(discarded.source_paths, [])
  let overwritten = check_tail([
    Response(7, 6, true, "overwritten"),
    Literal(8, "constant"),
    Response(9, 8, true, "returned"),
    Copy(7, 9),
    Return(7),
  ])
  assert_eq(overwritten.source_paths, [])
}

///|
test "encoding is specific to HTML text" {
  let safe = check_tail([
    EscapeHtmlText(7, 6),
    Response(8, 7, true, "html"),
    Return(8),
  ])
  assert_eq(safe.status, "complete")
  assert_eq(safe.source_paths, [])
  let script = check_tail([
    EscapeHtmlText(7, 6),
    Literal(8, "<script>"),
    Literal(9, "</script>"),
    Concat(10, [8, 7, 9]),
    Response(11, 10, true, "html"),
    Return(11),
  ])
  assert_eq(script.status, "incomplete")
  assert_eq(script.reason, "unsupported_html_context")
  assert_eq(script.source_paths.length(), 1)
  let plain = check_tail([Response(7, 6, false, "text"), Return(7)])
  assert_eq(plain.source_paths, [])
}

///|
test "undefined values and exhausted budgets cannot report complete" {
  assert_eq(
    check_tail([Response(8, 77, true, "html"), Return(8)]).status,
    "incomplete",
  )
  assert_eq(
    check_tail([Response(8, 6, true, "html"), Return(8)], limit=2).reason,
    "incomplete_budget",
  )
}

///|
test "compact doubling program cannot allocate unbounded segments" {
  let ops = operations()
  for slot in 7..<42 {
    ops.push(Concat(slot, [slot - 1, slot - 1]))
  }
  ops.push(Response(42, 41, true, "html"))
  ops.push(Return(42))
  let result = @security_ir.analyze(
    [{ id: "route", parameters: [0], operations: ops, }],
    "route",
  )
  assert_eq(result.status, "incomplete")
  assert_eq(result.reason, "incomplete_budget")
  assert_true(result.steps <= 10000)
}

///|
test "markdown fragment and encoding have distinct context contracts" {
  let safe = check_tail([
    RenderMarkdown(7, 6, true, "markdown"),
    Response(8, 7, true, "html"),
    Return(8),
  ])
  assert_eq(safe.status, "complete")
  assert_eq(safe.source_paths, [])
  let unsafe_after_escape = check_tail([
    EscapeHtmlText(7, 6),
    RenderMarkdown(8, 7, false, "markdown"),
    Response(9, 8, true, "html"),
    Return(9),
  ])
  assert_eq(unsafe_after_escape.status, "incomplete")
  assert_eq(unsafe_after_escape.source_paths.length(), 1)
  let script = check_tail([
    RenderMarkdown(7, 6, true, "markdown"),
    Literal(8, "<script>"),
    Literal(9, "</script>"),
    Concat(10, [8, 7, 9]),
    Response(11, 10, true, "html"),
    Return(11),
  ])
  assert_eq(script.reason, "unsupported_html_context")
  assert_eq(script.source_paths.length(), 1)
}
