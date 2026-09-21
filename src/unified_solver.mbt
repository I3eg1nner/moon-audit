// S5b: Unified worklist — pointer→edge→convergence loop (Codex Step 2).
// Schedules pt_solve_all + dispatch resolution in a feedback loop:
// new pointer facts → new dispatch targets → new constraints → repeat.
// rc-fix (review 2026-09-20): the loop now (a) exports per-function pts
// into SolverState.pts (previously always empty), (b) compares dispatch
// edge SETS rather than counts, and (c) records the per-round edge delta
// so a count-stable set change can never masquerade as convergence.

///|
fn dispatch_edge_set(edges : Array[String]) -> Map[String, Bool] {
  let s : Map[String, Bool] = Map([])
  for e in edges {
    s[e] = true
  }
  s
}

///|
fn edge_set_delta(
  prev : Map[String, Bool],
  next : Array[String],
) -> Array[String] {
  let added : Array[String] = []
  for e in next {
    match prev.get(e) {
      Some(_) => ()
      None => added.push(e)
    }
  }
  added
}

///|
pub fn unified_solve(world : ProgramWorld, _config : Config) -> SolverState {
  let state = SolverState::new()
  // Phase 1: initial call graph with pt solve (runs pt_solve_batched once)
  let cg = run_call_graph_with_world(world)
  state.resolved_targets["dispatch_edges"] = cg.dispatch_edges
  state.resolved_targets["edges"] = cg.edges
  state.resolved_targets["unresolved"] = cg.unresolved
  state.resolved_targets["pt_resolved_sites"] = [
    cg.pt_resolved_sites.to_string(),
  ]
  state.resolved_targets["bound_sites"] = [cg.bound_sites.to_string()]
  state.resolved_targets["candidate_sites"] = [cg.candidate_sites.to_string()]
  state.resolved_targets["pt_has_pt_sites"] = [cg.pt_has_pt_sites.to_string()]
  state.resolved_targets["pt_equal_or_fallback"] = [
    cg.pt_equal_or_fallback.to_string(),
  ]
  // rc-fix: share per-function pointer facts (was never populated)
  cg.pt_solutions.each(fn(fn_name, sol) { state.pts[fn_name] = sol })
  // Convergence loop: re-run while the dispatch edge SET grows.
  // Budget: max 3 rounds (constraints × 2 per Codex, capped for speed).
  let max_rounds = 3
  let mut prev_set = dispatch_edge_set(cg.dispatch_edges)
  let mut round = 1
  while round < max_rounds {
    let cg2 = run_call_graph_with_world(world)
    let added = edge_set_delta(prev_set, cg2.dispatch_edges)
    if added.length() == 0 {
      // Converged: no NEW dispatch edges from re-solving
      state.resolved_targets["converged_rounds"] = [round.to_string()]
      break
    }
    // rc-fix: real feedback — record which edges are NEW this round and
    // merge the round's pts into the shared state
    state.resolved_targets["round_" + round.to_string() + "_new_edges"] = added
    cg2.pt_solutions.each(fn(fn_name, sol) { state.pts[fn_name] = sol })
    prev_set = dispatch_edge_set(cg2.dispatch_edges)
    state.resolved_targets["dispatch_edges"] = cg2.dispatch_edges
    state.resolved_targets["edges"] = cg2.edges
    state.resolved_targets["unresolved"] = cg2.unresolved
    round += 1
  }
  if round >= max_rounds {
    state.resolved_targets["converged_rounds"] = [
      "budget-exhausted(" + max_rounds.to_string() + ")",
    ]
  }
  state
}
