// ── C8 (T2.4) call inside a default argument expression ─────────────────
// Expected: the call in the default expression enters the call graph.
// Current: FIXED (T0.2(a)) — default~ expressions now visited; see
// t0_default_param_call_enters_graph. Kept as regression lock.
fn case8_default_argument_call() -> Unit {
  ignore(greet())
}

///|
fn greet(name~ : String = decorated()) -> String {
  "hi " + name
}

///|
fn decorated() -> String {
  "world"
}
