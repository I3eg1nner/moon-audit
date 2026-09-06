// ── C1 (G2) same-name shadowing after destructure ────────────────────────
// let (v, safe) = (user(), "safe"); let v = safe; sink(v)
// Expected: silent (v is the clean component). Current: alerts in some
// rewrite orders — eval and binding are entangled (T2.1 single-evaluation).
fn case1_shadowed_component(sink : (String) -> Unit) -> Unit {
  let pair = (input(), "safe")
  let (v, _) = pair
  let v = pair.1
  sink(v)
}

///|
