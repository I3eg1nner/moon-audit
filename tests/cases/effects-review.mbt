// T0.1 counterexample corpus — fourth review round (2026-09-05), standalone
// compilable project. Each case notes the engine behavior gap (G# from
// docs/ir/ROADMAP-T.md). This file intentionally does NOT live under src/
// so it is not part of the analyzer package; it is the regression target
// for T2 acceptance ("one command reproduces every known failure").
// Verified: moon check — 0 errors (unused-name warnings only, by design).

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
fn input() -> String {
  "dirty"
}

// ── C2 (G2) sink argument evaluated twice by the rule walk ───────────────
// fn probe(x) { log(x); x }   // side effect inside the expression
// Expected: log side effects enter the analysis exactly once.
fn case2_double_evaluation(sink : (String) -> Unit) -> Unit {
  sink(probe(input()))
}

///|
fn probe(x : String) -> String {
  ignore(x)
  x
}

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

// ── C7 (T2.2) defer executes on the exit path ───────────────────────────
// Expected: defer body runs AFTER the enclosing block; a taint written in
// defer must be visible to code after the block.
fn case7_defer_order(
  b : Box,
  sink : (String) -> Unit,
) -> Unit {
  defer { b.value = input() }
  ignore(b)
  sink(b.value) // defer has not run yet here: expected clean at THIS point
}

// ── C8 (T2.4) call inside a default argument expression ─────────────────
// Expected: the call in the default expression enters the call graph.
// Current: missing from ir-stats/call-graph (review metric counterexample 1).
fn case8_default_argument_call() -> Unit {
  ignore(greet())
}

///|
fn greet(name~ : String = decorated()) -> String {
  "hi " + name
}

///|
fn decorated() -> String {
  "world"
}
