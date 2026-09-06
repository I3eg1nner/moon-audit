// ── C7 (T2.2) defer executes on the exit path ───────────────────────────
// Expected: defer body runs AFTER the enclosing block; a taint written in
// defer must be visible to code after the block.
fn case7_defer_order(
  b : Box,
  sink : (String) -> Unit,
) -> Unit {
  defer { b.value = input() }
  ignore(b)
  sink(b.value) // defer has not run yet here: expected clean at THIS point
}
