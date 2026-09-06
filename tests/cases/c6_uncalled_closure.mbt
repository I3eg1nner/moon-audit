// ── C6 (T2.5) closure created but never called ───────────────────────────
// Expected: no side effect from an uncalled closure (creation != execution).
fn case6_uncalled_closure(capture : String) -> Unit {
  let f = fn() { sink_unreachable(capture) }
  ignore(f)
}

///|
fn sink_unreachable(_s : String) -> Unit {
  ()
}
