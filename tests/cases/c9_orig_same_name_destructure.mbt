// ── C9 (G2) ORIGINAL round-5 counterexample: same-name destructure ───────
// let (x, value) = ("safe", x); sink(value)
// Expected: ALERT — the RHS tuple is ("safe", OUTER x); full evaluation of
//   the RHS happens BEFORE any pattern binding, so `value` carries the
//   tainted outer parameter x.
// Current (round-5 P0): the engine binds the first pattern variable `x`
//   first and then evaluates the second RHS component — reading the NEW
//   clean x instead of the outer tainted one. MISS.
// Status: PASS (R3/R4/R5 fixed — declaration ids + eval-then-bind;
//   gate counts isolated scans, so the control no longer dedups this).
fn case9_orig_same_name_destructure(
  sink : (String) -> Unit,
  x : String,
) -> Unit {
  let (x, value) = ("safe", x)
  sink(value)
}

///|
// control: same body without shadowing — must stay ALERTING (guards against
// the engine silently silencing the whole function)
fn case9_control(sink : (String) -> Unit, x : String) -> Unit {
  let (a, value) = ("safe", x)
  sink(value)
}
