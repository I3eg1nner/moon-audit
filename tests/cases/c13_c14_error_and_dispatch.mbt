// ── C13 (G3) nested try clears outer error facts (round-5 P0) ────────────
// try { if p { raise Bad(input()) }; try { raise FineNotOk } catch { _ => () } }
// catch { Bad(value) => sink(value) }
// Expected: ALERT — on the error path, Bad carries input()'s taint; the
//   inner (successfully handled) FineNotOk try must not erase that fact.
// Status: FIXED by R6 error-exit isolation (raise scopes snapshotted per
//   Try; irrefutable catches consume own raises only; outer facts restored).
suberror FineNotOk

///|
fn flip_coin() -> Bool {
  true
}

///|
// review-original form: NO parameters (so the conservative env-union in
// err_t cannot mask the outcome — the alert must come from the payload)
priv struct NestedResp {}

///|
fn NestedResp::set_header(
  _self : NestedResp,
  _name : String,
  _value : String,
) -> Unit {
  ()
}

///|
fn case13_nested_try_error_clear() -> Unit {
  let resp = NestedResp::{}
  try {
    if flip_coin() {
      raise Bad(input())
    }
    try { raise FineNotOk } catch { _ => () }
  } catch {
    Bad(value) => resp.set_header("X-Nested", value)
  }
}

///|
// ── C14 (R7) dispatch with zero implementations — empty candidate set ────
// Expected (findings): 0 — no sink involved; kept as the corpus case for
//   the site-coverage classification fix: a dispatch with an EMPTY
//   candidate set must count as unknown/unresolved, NOT as covered.
// Current (post-R7): empty candidate set classifies as unknown(no-impls);
//   run.sh asserts site coverage 0/1 for this project.
// Status: PASS(0 findings) + R7 coverage assertion active in run.sh.
trait NoImplAction {
  act(Self) -> Unit
}

///|
fn case14_empty_candidate_dispatch(a : &NoImplAction) -> Unit {
  a.act()
}
