// T4.3 thin (slice 1/2): points_to data layer unit tests — pure, unwired.

///|
test "pt_literal_alloc_reaches_alias" {
  let cs : Array[PTConstraint] = [PTAlloc("x", "f.mbt:10"), PTCopy("y", "x")]
  let sol = solve_pt_constraints(cs)
  assert_true(sol.contains("x", "f.mbt:10"))
  assert_true(sol.contains("y", "f.mbt:10")) // alias propagated
  inspect(sol.converged, content="true")
}

///|
test "pt_alias_chain_converges" {
  let cs : Array[PTConstraint] = [
    PTAlloc("a", "s1"),
    PTCopy("b", "a"),
    PTCopy("c", "b"),
    PTCopy("d", "c"),
  ]
  let sol = solve_pt_constraints(cs)
  let d = sol.pts_of("d")
  inspect(d.length(), content="1")
  inspect(d[0], content="s1")
  inspect(sol.iterations > 0, content="true")
}

///|
test "pt_param_passing_constraint_shape_from_hir" {
  // CallStmt("handler", [0]) must lower to the ParamToParam Subset form
  let trace : Array[Stmt] = [CallStmt("handler", [0])]
  let cs : Array[PTConstraint] = []
  constraints_from_trace(trace, cs)
  inspect(cs.length(), content="1")
  match cs[0] {
    PTCopy(to, from) => {
      inspect(to, content="fn@handler.param0")
      inspect(from, content="t0")
    }
    _ => inspect("wrong-constraint", content="never")
  }
  // BindVar/AssignStmt also lower to Subset copies
  let trace2 : Array[Stmt] = [
    LetEvalTemp(0, 0),
    BindVar("x:1", RTemp(0)),
    AssignStmt("x:1", 0),
  ]
  let cs2 : Array[PTConstraint] = []
  constraints_from_trace(trace2, cs2)
  inspect(cs2.length(), content="2")
  match cs2[0] {
    PTCopy(to, from) => {
      inspect(to, content="x:1")
      inspect(from, content="t0")
    }
    _ => ()
  }
}

///|
test "pt_field_store_load_roundtrip" {
  let cs : Array[PTConstraint] = [
    PTAlloc("obj", "S@1"),
    PTAlloc("v", "V@1"),
    PTStore("obj", "name", "v"),
    PTLoad("r", "obj", "name"),
  ]
  let sol = solve_pt_constraints(cs)
  assert_true(sol.contains("r", "V@1")) // field-sensitive load
  inspect(sol.fstore_of("S@1", "name").length(), content="1")
  assert_true(!sol.contains("r", "S@1")) // object identity not leaked
}

///|
test "pt_budget_exhaustion_disclosed" {
  let cs : Array[PTConstraint] = []
  cs.push(PTAlloc("x", "s"))
  cs.push(PTCopy("y", "x"))
  let sol = solve_pt_constraints(cs, budget=0)
  inspect(sol.converged, content="false") // budget exhausted must surface
}
