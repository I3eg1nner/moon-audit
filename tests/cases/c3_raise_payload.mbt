// ── C3 (G3) error payload raised directly ────────────────────────────────
// raise Bad(query()) — Expected: alert via catch binding. Current: missed
// (Raise drops the value; catch guesses from the environment).
fn case3_direct_error_payload(
  query : () -> String,
  emit : (String) -> Unit,
) -> Unit {
  try {
    emit(may_raise(query()))
  } catch {
    Bad(value) => emit(value) // value should carry query()'s taint
  }
}

///|
fn may_raise(x : String) -> String raise Bad {
  raise Bad(x)
}

///|
suberror Bad { Bad(String) }
