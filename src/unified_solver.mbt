// S5b: Unified worklist — pointer→edge→convergence loop (Codex Step 2).
// Schedules pt_solve_all + dispatch resolution in a feedback loop:
// new pointer facts → new dispatch targets → new constraints → repeat.
// The solver itself is unchanged; this is a SCHEDULING layer that decides
// when to re-run and when to stop.

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
  // Convergence loop: re-run if dispatch edges changed.
  // Budget: max 3 rounds (constraints × 2 per Codex, capped for speed).
  let max_rounds = 3
  let mut prev_dispatch_count = cg.dispatch_edges.length()
  let mut round = 1
  while round < max_rounds {
    let cg2 = run_call_graph_with_world(world)
    let new_count = cg2.dispatch_edges.length()
    if new_count == prev_dispatch_count {
      // Converged: no new dispatch edges from re-solving
      state.resolved_targets["converged_rounds"] = [round.to_string()]
      state.resolved_targets["dispatch_edges"] = cg2.dispatch_edges
      state.resolved_targets["edges"] = cg2.edges
      state.resolved_targets["unresolved"] = cg2.unresolved
      break
    }
    prev_dispatch_count = new_count
    round += 1
  }
  if round >= max_rounds {
    state.resolved_targets["converged_rounds"] = [
      "budget-exhausted(" + max_rounds.to_string() + ")",
    ]
  }
  state
}
