// E2: real points-to precision closure — worklist convergence, container/
// closure coverage, cross-file carrier. Measured corpus deltas recorded in
// docs/ir/ROADMAP-T.md (same-commit rule).

///|
fn e2_scan(src : String) -> IRStatsResult {
  // deferred mode: slices stay in the carrier so constraint-level
  // assertions can inspect them before the batched solve
  let (impls, _) = @parser.parse_string(src, name="t.mbt")
  let symbols = PkgSymbols::new()
  let stats = IRStatsResult::new()
  stats.pt_carrier = Some({ slices: [], pendings: [], })
  scan_package_calls(
    impls.to_array(),
    "t.mbt",
    symbols,
    stats,
    pt_deferred=true,
  )
  pt_solve_batched(stats)
  stats
}

///|
fn e2_slice_constraints(stats : IRStatsResult) -> Array[PTConstraint] {
  let all : Array[PTConstraint] = []
  match stats.pt_carrier {
    Some(car) =>
      for s in car.slices {
        for c in s.constraints {
          all.push(c)
        }
      }
    None => ()
  }
  all
}

///|
fn e2_recv_pt(s : IRStatsResult) -> Int {
  let mut n = 0
  for site in s.sites {
    if site.kind == "receiver" && site.recv_pt.length() > 0 {
      n += 1
    }
  }
  n
}

///|
test "e2_factory_declared_ret_fills_recv_pt" {
  // factory: callee's DECLARED ret seeds the caller's local even when the
  // factory body itself ends in an unknown-ret call (C::new has no sig)
  let src = "trait Act { fn act(Self) -> Unit } struct C { } impl Act for C with fn act(self) -> Unit { } pub fn make() -> C { C::new() } pub fn go() -> Unit { let r = make(); r.act() }"
  let s = e2_scan(src)
  // the declared-ret fallback seeds make's ret summary -> r -> dispatch recv
  inspect(e2_recv_pt(s) >= 1, content="true")
}

///|
test "e2_worklist_budget_disclosed" {
  // budget exhaustion is DISCLOSED (pt_not_converged), never silent
  let src = "pub fn a0() -> Int { a1() } pub fn a1() -> Int { a2() } pub fn a2() -> Int { a3() } pub fn a3() -> Int { 0 } pub fn go() -> Int { a0() }"
  let s = e2_scan(src)
  // small module converges far below budget -> not flagged
  inspect(s.pt_not_converged, content="false")
  inspect(s.pt_iterations >= 1, content="true")
}

///|
test "e2_array_elem_flow" {
  // container model: literal alloc + elem stores; ForEach loads back
  let src = "struct C { v : Int } pub fn go() -> Unit { let xs = [C::new()]; for x in xs { ignore(x.v) } }"
  let s = e2_scan(src)
  // the slice must contain the elem store AND the ForEach elem load
  let mut has_store = false
  let mut has_load = false
  for c in e2_slice_constraints(s) {
    match c {
      PTStore(_, "elem", _) => has_store = true
      PTLoad(_, _, "elem") => has_load = true
      _ => ()
    }
  }
  inspect(has_store, content="true")
  inspect(has_load, content="true")
}

///|
test "e2_closure_capture_site" {
  // closure binding allocs a closure site; captured outer ident stores
  // into the "cap:<name>" slot
  let src = "pub fn go(seed : Int) -> Int { let h = fn(x : Int) -> Int { x + seed }; h(1) }"
  let s = e2_scan(src)
  let mut has_cap = false
  for c in e2_slice_constraints(s) {
    match c {
      PTStore(_, f, "seed") => if f.has_prefix("cap:") { has_cap = true }
      _ => ()
    }
  }
  inspect(has_cap, content="true")
}

///|
test "e2_cross_file_carrier_argret" {
  // THE mocket shape: caller in "file A" seeds a &Trait param of a fn
  // defined in "file B" — the batch carrier merges slices+pendings across
  // scan_package_calls invocations and the worklist fills recv_pt
  let src_a = "trait Act { fn act(Self) -> Unit } struct C { } impl Act for C with fn act(self) -> Unit { } pub fn f(x : &Act) -> Unit { x.act() }"
  let src_b = "pub fn go() -> Unit { f(\"hello\") }"
  let (ia, _) = @parser.parse_string(src_a, name="a.mbt")
  let (ib, _) = @parser.parse_string(src_b, name="b.mbt")
  let symbols = PkgSymbols::new()
  let stats = IRStatsResult::new()
  stats.pt_carrier = Some({ slices: [], pendings: [], })
  scan_package_calls(ia.to_array(), "a.mbt", symbols, stats, pt_deferred=true)
  scan_package_calls(ib.to_array(), "b.mbt", symbols, stats, pt_deferred=true)
  pt_solve_batched(stats)
  // without the carrier the per-file clear dropped b's pending -> 0;
  // with it the dispatch site in f gets recv_pt = [String]
  inspect(e2_recv_pt(stats) >= 1, content="true")
}

///|
test "e2_debug_solver_direct" {
  // direct solver check: PTCopy(x, node) + PTAlloc(node, s) => pts(x) ∋ s
  let cs : Array[PTConstraint] = [
    PTAlloc("fn@f.param:x", "String@ipc"),
    PTCopy("x", "fn@f.param:x"),
  ]
  let sol = solve_pt_constraints(cs)
  inspect(sol.pts_of("x").length(), content="1")
}
