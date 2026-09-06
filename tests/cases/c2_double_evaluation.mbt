// ── C2 (G2) sink argument evaluated twice by the rule walk ───────────────
// fn probe(x) { log(x); x }   // side effect inside the expression
// Expected: log side effects enter the analysis exactly once.
fn case2_double_evaluation(sink : (String) -> Unit) -> Unit {
  sink(probe(input()))
}

///|
fn probe(x : String) -> String {
  ignore(x)
  x
}
