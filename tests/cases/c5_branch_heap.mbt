// ── C5 (G4) branch heap isolation ────────────────────────────────────────
// One branch overwrites a tainted record field; the other branch's taint
// must survive the merge. Current: shared heap channel can erase it.
fn case5_branch_heap(
  mk : () -> Box,
  sink : (String) -> Unit,
) -> Unit {
  let b = mk()
  if b.flag {
    b.value = "clean"
  } else {
    b.value = input()
  }
  sink(b.value) // may be tainted: must alert
}

///|
struct Box {
  mut value : String
  flag : Bool
}
