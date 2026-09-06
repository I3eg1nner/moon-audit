// ── C1 (G2) same-name shadowing after destructure ────────────────────────
// let (v, safe) = (user(), "safe"); let v = safe; sink(v)
// Expected: silent (v is the clean component). FIXED (T2 first batch):
// scoped variable ids + tuple component projection — `pair.1` reads the
// exact recorded component, same-name re-binding cannot alias the outer var.
fn case1_shadowed_component(sink : (String) -> Unit) -> Unit {
  let pair = (input(), "safe")
  let (v, _) = pair
  let v = pair.1
  sink(v)
}

///|
