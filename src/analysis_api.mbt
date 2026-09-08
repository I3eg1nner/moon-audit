// T6.1+T6.2 thin: analysis registry with dependency scheduling.
//
// Tai-e alignment: analyses declare identity + dependencies; the registry
// schedules them in topological order, memoizes results, and exposes one
// result map — CLIs request analyses instead of calling engines directly.
//
// E3 single-world: adapters consume the ONE ProgramWorld passed to
// run_all via the world-parameterized entrypoints (scan_project_with_world
// / run_call_graph_with_world); no adapter reloads. world_loads counter is
// the audit hook (e3_* tests assert run_all holds it at one build).

///|
pub(all) enum AnalysisId {
  TaintFlow
  CallGraph
  HIRTrace
  PointsTo
  LiveVars
} derive(Eq, Hash, Debug)

///|
pub fn AnalysisId::display(self : AnalysisId) -> String {
  match self {
    TaintFlow => "taint-flow"
    CallGraph => "call-graph"
    PointsTo => "points-to"
    HIRTrace => "hir-trace"
    LiveVars => "live-vars"
  }
}

// ── whole-world aggregate results for the per-trace analyses ──────────────

///|
pub(all) struct PTFnReport {
  fn_name : String
  file : String
  constraints : Array[PTConstraint]
  sol : PTSolution
}

///|
pub(all) struct PTWorldSummary {
  fn_count : Int
  constraint_count : Int
  nodes_with_pts : Int
  cfg_fallback : Int // fns whose CFG build/validate failed (trace path)
  per_fn : Array[PTFnReport]
}

///|
pub(all) struct LiveFnReport {
  fn_name : String
  file : String
  summary : LiveVarsSummary
}

///|
pub(all) struct LiveWorldSummary {
  fn_count : Int
  total_decls : Int
  dead : Int
  cfg_fallback : Int // fns whose CFG build/validate failed (trace path)
  per_fn : Array[LiveFnReport]
}

///|
pub(all) enum AnalysisResult {
  TaintFlowR(ScanResult)
  CallGraphR(CallGraph)
  HIRTraceR(Array[(String, String, Array[Stmt])]) // fn, file, stmts
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
    id: HIRTrace,
    deps: [],
    run: fn(w) {
      // D1c: the shared statement layer as a registry product — dump
      // consumes this instead of re-collecting traces itself
      let out : Array[(String, String, Array[Stmt])] = []
      for pkgf in w.packages {
        for file in pkgf.files {
          let source = @fs.read_file_to_string(file) catch { _ => continue }
          let (impls, _) = @parser.parse_string(source, name=file)
          for pair in collect_fn_traces(impls, file, source) {
            out.push((pair.0, file, pair.1))
          }
        }
      }
      HIRTraceR(out)
    },
  })
  reg.register({
    id: TaintFlow,
    deps: [],
    run: fn(w) {
      // E3 single-world: consume the caller's world; no internal reload
      // (world_loads counter guards this — see e3_single_world tests)
      TaintFlowR(scan_project_with_world(w, w.config))
    },
  })
  reg.register({
    id: CallGraph,
    deps: [],
    run: fn(w) {
      // E3 single-world: the world's symbols already carry the alias
      // policy (callers build world and registry with the same flag);
      // conservative_alias param retained for API compat only
      ignore(conservative_alias)
      CallGraphR(run_call_graph_with_world(w))
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
  let mut cfg_fallback = 0
  let per_fn : Array[PTFnReport] = []
  for pkgf in world.packages {
    for file in pkgf.files {
      let source = @fs.read_file_to_string(file) catch { _ => continue }
      let (impls, _) = @parser.parse_string(source, name=file)
      let cfgs = collect_fn_cfgs(impls)
      let mut i = 0
      for pair in collect_fn_traces(impls, file, source) {
        fn_count += 1
        let constraints : Array[PTConstraint] = []
        // D1c guard (same as live-vars): CFG constraints only when the
        // bind streams agree; mismatch falls back to the trace numbers
        // (petgraph dump stays byte-equal; fallbacks counted+disclosed)
        let cfg_ok = i < cfgs.length() &&
          (match cfgs[i] {
            None => false
            Some(ir) => cfg_kill_keys(ir) == trace_kill_keys(pair.1)
          })
        if cfg_ok {
          constraints_from_cfg(cfgs[i].unwrap(), constraints)
        } else {
          cfg_fallback += 1
          constraints_from_trace(pair.1, constraints)
        }
        constraint_count += constraints.length()
        let sol = solve_pt_constraints(constraints)
        nodes_with_pts += sol.pts.length()
        per_fn.push({ fn_name: pair.0, file, constraints, sol, })
        i += 1
      }
    }
  }
  { fn_count, constraint_count, nodes_with_pts, cfg_fallback, per_fn, }
}
// aggregate: live-variable summaries over every module function

///|
fn live_world_summary(world : ProgramWorld) -> LiveWorldSummary {
  let mut fn_count = 0
  let mut total_decls = 0
  let mut dead = 0
  let mut cfg_fallback = 0
  let per_fn : Array[LiveFnReport] = []
  for pkgf in world.packages {
    for file in pkgf.files {
      let source = @fs.read_file_to_string(file) catch { _ => continue }
      let (impls, _) = @parser.parse_string(source, name=file)
      let cfgs = collect_fn_cfgs(impls)
      let mut i = 0
      for pair in collect_fn_traces(impls, file, source) {
        fn_count += 1
        // D1c guard: the CFG lowering and the taint-walk trace may emit
        // different bind streams; use block-level liveness ONLY when the
        // kill-key sets agree (numbers stay comparable to the trace path;
        // every mismatch falls back and is disclosed in cfg_fallback)
        let cfg_usable = i < cfgs.length() &&
          (match cfgs[i] {
            None => false
            Some(ir) => cfg_kill_keys(ir) == trace_kill_keys(pair.1)
          })
        let summary = if cfg_usable {
          live_vars_of_cfg(cfgs[i].unwrap())
        } else {
          cfg_fallback += 1
          live_vars_of_trace(pair.1)
        }
        total_decls += summary.total
        dead += summary.dead
        per_fn.push({ fn_name: pair.0, file, summary, })
        i += 1
      }
    }
  }
  { fn_count, total_decls, dead, cfg_fallback, per_fn, }
}
// sorted kill-key sets for the CFG/trace agreement guard

///|
pub fn cfg_kill_keys(ir : BlockIr) -> Array[String] {
  let keys : Array[String] = []
  for b in ir.blocks {
    for s in b.stmts {
      for k in stmt_kills(s) {
        keys.push(k)
      }
    }
  }
  keys.sort()
  keys
}

///|
pub fn trace_kill_keys(trace : Array[Stmt]) -> Array[String] {
  let keys : Array[String] = []
  for s in trace {
    for k in stmt_kills(s) {
      keys.push(k)
    }
  }
  keys.sort()
  keys
}

// one CFG per collected fn (parallel to collect_fn_traces order); None =
// build/validate failed (callers fall back to the trace path and count it)
