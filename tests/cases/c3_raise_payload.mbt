// ── C3 (G3) error payload raised directly ────────────────────────────────
// raise Bad(query()) — Expected: alert via catch binding. FIXED (T2 first
// batch): Raise carries its payload taint directly; the enclosing Try unions
// it into the error value the catch pattern binds (env union kept only as
// the conservative supplement).
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
