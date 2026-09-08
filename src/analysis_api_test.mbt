// T6.1+T6.2 thin: analysis registry tests

///|
fn dummy_scan_result() -> ScanResult {
  { findings: [], files_scanned: 0, errors: [], analysis_scope: "", }
}

///|
fn make_t6_fixture() -> String {
  let root = test_tmp("t6_registry")
  let src = root + "/src"
  @fs.create_dir(root) catch {
    _ => ()
  }
  @fs.create_dir(src) catch {
    _ => ()
  }
  @fs.write_string_to_file(root + "/moon.mod", "name = \"t6/e\"\\n") catch {
    _ => ()
  }
  @fs.write_string_to_file(src + "/moon.pkg", "") catch {
    _ => ()
  }
  @fs.write_string_to_file(src + "/lib.mbt", "pub fn one() -> Int { 1 }") catch {
    _ => ()
  }
  root
}

///|
test "t6_registry_dependency_order" {
  // TaintFlow depends on CallGraph: run_all([TaintFlow]) must execute
  // CallGraph FIRST even though it was not explicitly requested
  let root = make_t6_fixture()
  let world = load_program_world(root, Config::default())
  let order : Array[String] = []
  let reg = AnalysisRegistry::new()
  reg.register({
    id: CallGraph,
    deps: [],
    run: fn(_w) {
      order.push("cg")
      TaintFlowR(dummy_scan_result())
    },
  })
  reg.register({
    id: TaintFlow,
    deps: [CallGraph],
    run: fn(_w) {
      order.push("tf")
      TaintFlowR(dummy_scan_result())
    },
  })
  let results = reg.run_all([TaintFlow], world)
  inspect(results is Ok(_), content="true")
  let parts : Array[String] = []
  for o in order {
    parts.push(o)
  }
  inspect(parts.join(","), content="cg,tf")
}

///|
test "t6_registry_result_sharing_runs_once" {
  // explicitly requested AND a dependency: the shared analysis runs ONCE
  let root = make_t6_fixture()
  let world = load_program_world(root, Config::default())
  let cg_runs : Array[Int] = [0]
  let tf_runs : Array[Int] = [0]
  let reg = AnalysisRegistry::new()
  reg.register({
    id: CallGraph,
    deps: [],
    run: fn(_w) {
      cg_runs[0] += 1
      TaintFlowR(dummy_scan_result())
    },
  })
  reg.register({
    id: TaintFlow,
    deps: [CallGraph],
    run: fn(_w) {
      tf_runs[0] += 1
      TaintFlowR(dummy_scan_result())
    },
  })
  let results = reg.run_all([CallGraph, TaintFlow], world)
  inspect(results is Ok(_), content="true")
  // both results present; dependency executed exactly once
  inspect(cg_runs[0].to_string(), content="1")
  inspect(tf_runs[0].to_string(), content="1")
  match results {
    Ok(map) => {
      inspect(map.contains(CallGraph), content="true")
      inspect(map.contains(TaintFlow), content="true")
    }
    Err(_) => inspect("unreachable", content="reached")
  }
}

///|
test "t6_registry_unknown_id_errors" {
  let root = make_t6_fixture()
  let world = load_program_world(root, Config::default())
  let reg = AnalysisRegistry::new() // empty: LiveVars has no spec
  match reg.run_all([LiveVars], world) {
    Err(msg) => inspect(msg.contains("unknown analysis id"), content="true")
    Ok(_) => inspect("should have errored", content="errored")
  }
}

// ── E3 single-world plumbing ─────────────────────────────────────────────

///|
test "e3_run_all_builds_world_once" {
  let root = make_t6_fixture()
  world_loads.count = 0
  let world = load_program_world(root, Config::default())
  let reg = default_registry()
  let requested : Array[AnalysisId] = [
    TaintFlow,
    CallGraph,
    HIRTrace,
    PointsTo,
    LiveVars,
  ]
  // count==1 here: the ONE deliberate build; run_all must add ZERO more
  let results = match reg.run_all(requested, world) {
    Ok(r) => r
    Err(e) => {
      inspect(e, content="")
      return
    }
  }
  // all five analyses ran
  inspect(results.contains(TaintFlow), content="true")
  inspect(results.contains(CallGraph), content="true")
  inspect(results.contains(HIRTrace), content="true")
  inspect(results.contains(PointsTo), content="true")
  inspect(results.contains(LiveVars), content="true")
  // THE E3 invariant: exactly ONE world build served the whole pipeline
  // (previously TaintFlow and CallGraph each reloaded internally: 3 total)
  inspect(world_loads.count, content="1")
}

///|
test "e3_shells_still_build_their_own_world" {
  // compatibility shells keep their load (CLI callers rely on them)
  let root = make_t6_fixture()
  world_loads.count = 0
  let _ = scan_project(root, Config::default())
  inspect(world_loads.count, content="1")
  let _ = run_call_graph(root, Config::default())
  inspect(world_loads.count, content="2")
  let _ = run_ir_stats(root, Config::default())
  inspect(world_loads.count, content="3")
}
