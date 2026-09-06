// T6.1+T6.2 thin: analysis registry with dependency scheduling.
//
// Tai-e alignment: analyses declare identity + dependencies; the registry
// schedules them in topological order, memoizes results, and exposes one
// result map — CLIs request analyses instead of calling engines directly.
//
// Thin-slice boundary (documented, widened in T6.2 full scope): the
// adapters reuse the existing whole-project entrypoints unchanged
// (scan_project / run_call_graph / per-trace helpers), so each adapter may
// re-walk the project through load_program_world — the single fact source
// stays load_program_world; no engine internals are duplicated here.

///|
pub(all) enum AnalysisId {
  TaintFlow
  CallGraph
  PointsTo
  LiveVars
} derive(Eq, Hash, Debug)

///|
pub fn AnalysisId::display(self : AnalysisId) -> String {
  match self {
    TaintFlow => "taint-flow"
    CallGraph => "call-graph"
    PointsTo => "points-to"
    LiveVars => "live-vars"
  }
}

// ── whole-world aggregate results for the per-trace analyses ──────────────

///|
pub(all) struct PTWorldSummary {
  fn_count : Int
  constraint_count : Int
  nodes_with_pts : Int
}

///|
pub(all) struct LiveWorldSummary {
  fn_count : Int
  total_decls : Int
  dead : Int
}

///|
pub(all) enum AnalysisResult {
  TaintFlowR(ScanResult)
  CallGraphR(CallGraph)
  PointsToR(PTWorldSummary)
  LiveVarsR(LiveWorldSummary)
}

///|
pub(all) struct AnalysisSpec {
  id : AnalysisId
  deps : Array[AnalysisId]
  run : (ProgramWorld) -> AnalysisResult
}

///|
pub(all) struct AnalysisRegistry {
  specs : Map[AnalysisId, AnalysisSpec]
}

///|
pub fn AnalysisRegistry::new() -> AnalysisRegistry {
  { specs: Map([]), }
}

///|
pub fn AnalysisRegistry::register(
  self : AnalysisRegistry,
  spec : AnalysisSpec,
) -> Unit {
  self.specs[spec.id] = spec
}

///|
pub fn AnalysisRegistry::plan(
  self : AnalysisRegistry,
  requested : Array[AnalysisId],
) -> Result[Array[AnalysisId], String] {
  // 1. dependency closure (worklist) — unknown ids raise immediately
  let closure : Array[AnalysisId] = []
  fn push_unique(arr : Array[AnalysisId], id : AnalysisId) -> Unit {
    if !arr.contains(id) {
      arr.push(id)
    }
  }
  let queue : Array[AnalysisId] = []
  for id in requested {
    push_unique(queue, id)
  }
  let mut qi = 0
  while qi < queue.length() {
    let id = queue[qi]
    qi += 1
    push_unique(closure, id)
    match self.specs.get(id) {
      Some(spec) =>
        for d in spec.deps {
          push_unique(queue, d)
        }
      None => return Err("unknown analysis id: " + id.display())
    }
  }
  // 2. topological order: iterative ready-pass (analyses are few)
  let order : Array[AnalysisId] = []
  let mut remaining = closure.copy()
  while remaining.length() > 0 {
    let mut advanced = false
    let next : Array[AnalysisId] = []
    for id in remaining {
      let spec = match self.specs.get(id) {
        Some(s) => s
        None => return Err("unknown analysis id: " + id.display())
      }
      let ready = spec.deps.all(fn(d) { order.contains(d) })
      if ready {
        order.push(id)
        advanced = true
      } else {
        next.push(id)
      }
    }
    if !advanced {
      return Err(
        "dependency cycle among analyses (unresolvable: " +
        remaining[0].display() +
        ")",
      )
    }
    remaining = next
  }
  Ok(order)
}

///|
pub fn AnalysisRegistry::run_all(
  self : AnalysisRegistry,
  requested : Array[AnalysisId],
  world : ProgramWorld,
) -> Result[Map[AnalysisId, AnalysisResult], String] {
  let order = match self.plan(requested) {
    Ok(o) => o
    Err(e) => return Err(e)
  }
  // run each exactly once (memoized by construction) in dependency order
  let results : Map[AnalysisId, AnalysisResult] = Map([])
  for id in order {
    let spec = match self.specs.get(id) {
      Some(s) => s
      None => return Err("unknown analysis id: " + id.display())
    }
    let runner = spec.run
    results[id] = runner(world)
  }
  Ok(results)
}

// ── default registry: wrap the four existing capabilities ────────────────

///|
pub fn default_registry(conservative_alias? : Bool = false) -> AnalysisRegistry {
  let reg = AnalysisRegistry::new()
  reg.register({
    id: TaintFlow,
    deps: [],
    run: fn(w) {
      // adapter reuses the whole-project entrypoint unchanged (scan
      // reloads its own ProgramWorld internally with with_symbols=false)
      TaintFlowR(scan_project(w.root, w.config))
    },
  })
  reg.register({
    id: CallGraph,
    deps: [],
    run: fn(w) {
      CallGraphR(run_call_graph(w.root, w.config, conservative_alias~))
    },
  })
  reg.register({
    id: PointsTo,
    deps: [],
    run: fn(w) { PointsToR(pt_world_summary(w)) },
  })
  reg.register({
    id: LiveVars,
    deps: [],
    run: fn(w) { LiveVarsR(live_world_summary(w)) },
  })
  reg
}

// aggregate: per-trace points-to over every module function

///|
fn pt_world_summary(world : ProgramWorld) -> PTWorldSummary {
  let mut fn_count = 0
  let mut constraint_count = 0
  let mut nodes_with_pts = 0
  for pkgf in world.packages {
    for file in pkgf.files {
      let source = @fs.read_file_to_string(file) catch { _ => continue }
      let (impls, _) = @parser.parse_string(source, name=file)
      for pair in collect_fn_traces(impls, file, source) {
        fn_count += 1
        let constraints : Array[PTConstraint] = []
        constraints_from_trace(pair.1, constraints)
        constraint_count += constraints.length()
        let sol = solve_pt_constraints(constraints)
        nodes_with_pts += sol.pts.length()
      }
    }
  }
  { fn_count, constraint_count, nodes_with_pts, }
}

// aggregate: live-variable summaries over every module function

///|
fn live_world_summary(world : ProgramWorld) -> LiveWorldSummary {
  let mut fn_count = 0
  let mut total_decls = 0
  let mut dead = 0
  for pkgf in world.packages {
    for file in pkgf.files {
      let source = @fs.read_file_to_string(file) catch { _ => continue }
      let (impls, _) = @parser.parse_string(source, name=file)
      for pair in collect_fn_traces(impls, file, source) {
        fn_count += 1
        let summary = live_vars_of_trace(pair.1)
        total_decls += summary.total
        dead += summary.dead
      }
    }
  }
  { fn_count, total_decls, dead, }
}
