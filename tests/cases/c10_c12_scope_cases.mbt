// ── C10 (G2) match pattern shadows outer variable (round-5 P0) ───────────
// match "safe" { x => ignore(x) }; sink(x)
// Expected: ALERT — the pattern variable x exists only inside the match
//   arm; after the match the outer tainted parameter x is unchanged.
// Current: the pattern is bound BEFORE entering a branch scope, and the
//   binding leaks to the outer environment, silencing the later sink. MISS.
// Status: PASS (R4 branch/block scopes + R3 declaration ids).
fn case10_match_pattern_shadow(
  sink : (String) -> Unit,
  x : String,
) -> Unit {
  match "safe" { x => ignore(x) }
  sink(x)
}

///|
// ── C11 (G2) block-expression let leaks outward (round-5 P0) ─────────────
// let _v = { let x = "safe"; x }; sink(x)
// Expected: ALERT — the inner x is scoped to the block expression; the
//   outer tainted parameter survives it.
// Current: the block reuses the current environment without a scope, the
//   inner clean binding leaks outward and silences the sink. MISS.
// Status: PASS (R4 block semantics: Let/LetMut/LetAnd/LetFn and Sequence
//   each scope their bindings).
fn case11_block_let_leak(
  sink : (String) -> Unit,
  x : String,
) -> Unit {
  let _v = { let x = "safe"; x }
  sink(x)
}

///|
// ── C12 (G2/R5) tuple rebinding reuses stale component info (round-5) ───
// let pair = ("safe", "safe"); let pair = make_pair(x); sink(pair.0)
// Expected: ALERT — after rebinding, pair.0 is tainted via make_pair.
// Current: the old component summary for the same variable name is reused,
//   pair.0 reads the stale clean component. MISS.
// Status: PASS (R3/R5: rebinding allocates a new declaration id; stale
//   component summaries become unreachable).
fn make_pair_dirty(x : String) -> (String, String) {
  (x, x)
}

///|
fn case12_tuple_rebind_stale(
  sink : (String) -> Unit,
  x : String,
) -> Unit {
  let pair = ("safe", "safe")
  ignore(pair)
  let pair = make_pair_dirty(x)
  sink(pair.0)
}
