// ── C13 (G3) nested try clears outer error facts (round-5 P0) ────────────
// try { if p { raise Bad(dirty_query()) }; try { raise Fine } catch { _ => () } }
// catch { Bad(value) => sink(value) }
// Expected: ALERT — on the error path, Bad carries query()'s taint; the
//   inner (successfully handled) Fine try must not erase that fact.
// Current: the error payload buffer is shared and cleared on entering each
//   try, so the inner handler wipes the outer Bad payload. MISS.
// Status: EXPECT-FAIL (G3 error-exit isolation, ROADMAP-T R6).
suberror FineNotOk

///|
fn flip_coin() -> Bool {
  true
}

///|
fn dirty_query() -> String {
  "dirty"
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
      raise Bad(dirty_query())
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
// Current (round-5 P1): `call-graph` shows site coverage 1/1 = 100% for
//   this single call site. Classification fix lands with ROADMAP-T R7;
//   this run.sh gate asserts findings only until then.
// Status: PASS(0 findings) + TODO(R7 coverage assertion).
trait NoImplAction {
  act(Self) -> Unit
}

///|
fn case14_empty_candidate_dispatch(a : &NoImplAction) -> Unit {
  a.act()
}
