// T4.2 acceptance: SCC-ordered iterative summaries (direct recursion,
// mutual recursion, DAG order-independence) + transitive sink convergence.

///|
fn t42_units(src : String) -> Array[SummaryUnit] {
  let (impls, _) = @parser.parse_string(src, name="t.mbt")
  extract_summary_units(impls, "t.mbt")
}

///|
fn t42_ret_from(ictx : InterProceduralContext, name : String) -> Array[String] {
  match ictx.summaries.get(name) {
    Some(s) => s.ret_from
    None => []
  }
}

///|
test "t42_direct_recursion_fixpoint" {
  // rec(n, x): base returns x, else recurs with x — ret_from(x) requires
  // consuming rec's OWN summary (unavailable on a single blind pass)
  let units = t42_units(
    "fn rec(n : Int, x : String) -> String { if n <= 0 { x } else { rec(n - 1, x) } }",
  )
  inspect(units.length(), content="1")
  let ictx = InterProceduralContext::new()
  collect_summaries_scc(units, ictx)
  let rf = t42_ret_from(ictx, "rec")
  inspect(rf.contains("x"), content="true")
  inspect(ictx.not_converged, content="0")
}

///|
test "t42_mutual_recursion_fixpoint" {
  // a(n,x) -> b(n-1,x) -> a(n,x): both summaries need the fixpoint
  let units = t42_units(
    "fn a(n : Int, x : String) -> String { if n <= 0 { x } else { b(n - 1, x) } } fn b(n : Int, x : String) -> String { a(n, x) }",
  )
  inspect(units.length(), content="2")
  let ictx = InterProceduralContext::new()
  collect_summaries_scc(units, ictx)
  inspect(t42_ret_from(ictx, "a").contains("x"), content="true")
  inspect(t42_ret_from(ictx, "b").contains("x"), content="true")
  inspect(ictx.not_converged, content="0")
}

///|
test "t42_dag_order_independent_and_stable" {
  // c -> d, d returns its param: reverse-topo solves c in ONE sweep; the
  // result must be identical regardless of declaration order in the source
  let u1 = t42_units(
    "fn c(x : String) -> String { d(x) } fn d(x : String) -> String { x }",
  )
  let ictx1 = InterProceduralContext::new()
  collect_summaries_scc(u1, ictx1)
  let u2 = t42_units(
    "fn d(x : String) -> String { x } fn c(x : String) -> String { d(x) }",
  )
  let ictx2 = InterProceduralContext::new()
  collect_summaries_scc(u2, ictx2)
  // both orders: c's taint comes transitively from d's ret_from
  inspect(t42_ret_from(ictx1, "c").contains("x"), content="true")
  inspect(t42_ret_from(ictx2, "c").contains("x"), content="true")
  // re-running the driver is idempotent (fixpoint already reached)
  collect_summaries_scc(u1, ictx1)
  inspect(t42_ret_from(ictx1, "c").contains("x"), content="true")
  inspect(ictx1.not_converged, content="0")
}

///|
test "t42_transitive_param_sink_converges" {
  // inner: v reaches a header sink. outer passes w to inner — outer's
  // summary must record w -> HeaderValue via the callee's param_sinks
  // (collection-mode transitivity, gated by the record channel)
  let units = t42_units(
    "fn inner(resp : Resp, v : String) -> Unit { resp.set_header(\"X\", v) } fn outer(resp : Resp, w : String) -> Unit { inner(resp, w) }",
  )
  let ictx = InterProceduralContext::new()
  collect_summaries_scc(units, ictx)
  match ictx.summaries.get("inner") {
    Some(s) => inspect(s.param_sinks.contains("v"), content="true")
    None => inspect("missing-inner", content="present-inner")
  }
  match ictx.summaries.get("outer") {
    Some(s) => inspect(s.param_sinks.contains("w"), content="true")
    None => inspect("missing-outer", content="present-outer")
  }
}

///|
test "t42_external_callees_dropped_from_graph" {
  // callee not among the collected units: edge dropped, no crash, and the
  // caller keeps the (unrefined) args-union behavior — no false precision
  let units = t42_units("fn c(x : String) -> String { external(x) }")
  let ictx = InterProceduralContext::new()
  collect_summaries_scc(units, ictx)
  // external callee is unresolved — apply_ret_from misses, but the
  // args-union fallback PRESERVES provenance, so c keeps ret_from=[x]
  // (honest under-resolution: fallback precision, no false refinement)
  inspect(t42_ret_from(ictx, "c").contains("x"), content="true")
}
