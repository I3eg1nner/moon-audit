// ── C4 (G5) loop propagation needing >3 passes / heap change ─────────────
// Expected: taint introduced in iteration 1 reaches the sink in a later
// iteration regardless of pass count (worklist to fixpoint).
fn case4_loop_propagation(
  step : (Int) -> String,
  sink : (String) -> Unit,
) -> Unit {
  let acc = ""
  let mut i = 0
  while i < 5 {
    let acc = step(i) + acc
    if i == 4 {
      sink(acc)
    }
    i += 1
  }
  ignore(acc)
}
