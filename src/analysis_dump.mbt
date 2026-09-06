// T6.4 thin + T4.5 evidence thin: analysis dump with provenance.
//
// `dump_analyses` exports the registry-driven analysis results as a set of
// text files: the analysis execution plan (dependency topological order),
// HIR traces, call-graph edges, points-to solutions and live-variable
// summaries. Each section carries its provenance (source file / fn name /
// model key) so a reviewer can trace WHY a fact exists — the T4.5 evidence
// thin slice.
//
// Thin-slice boundary (documented): provenance is section-level (fn header
// with source file) plus exact file:line for taint findings and iterations
// for points-to convergence; per-statement source spans are NOT yet in the
// HIR (Stmt has no loc) and stay a T6.4 full-scope item.

///|
pub fn dump_analyses(
  dir : String,
  root : String,
  config : Config,
  conservative_alias? : Bool = false,
) -> Unit {
  // create output dir level by level (create_dir is not recursive)
  let mut cur = ""
  for part in dir.split("/") {
    let seg = Show::to_string(part)
    if seg.length() == 0 {
      continue
    }
    if cur.length() == 0 {
      // preserve absoluteness: "/tmp/x" must not become relative "tmp/x"
      cur = if dir.has_prefix("/") { "/" + seg } else { seg }
    } else {
      cur = cur + "/" + seg
    }
    @fs.create_dir(cur) catch {
      _ => ()
    }
  }
  let world = load_program_world(root, config, conservative_alias~)
  let reg = default_registry(conservative_alias~)
  let requested : Array[AnalysisId] = [TaintFlow, CallGraph, PointsTo, LiveVars]
  // ── analysis-plan.txt: dependency topological order (T6.4) ──────────────
  let plan = match reg.plan(requested) {
    Ok(o) => o
    Err(e) => {
      write_dump(dir, "analysis-plan.txt", "plan error: " + e + "\n")
      return
    }
  }
  let plan_txt = StringBuilder()
  plan_txt.write_string(
    "# analysis execution plan (dependency topological order)\n",
  )
  plan_txt.write_string("# root: " + root + "\n")
  let mut step = 1
  for id in plan {
    let deps = match reg.specs.get(id) {
      Some(spec) => {
        let names : Array[String] = []
        for d in spec.deps {
          names.push(d.display())
        }
        names.join(", ")
      }
      None => ""
    }
    plan_txt.write_string(
      step.to_string() +
      ". " +
      id.display() +
      "  [deps: " +
      (if deps.length() > 0 { deps } else { "none" }) +
      "]\n",
    )
    step += 1
  }
  write_dump(dir, "analysis-plan.txt", plan_txt.to_string())
  // ── run all analyses through the registry ──────────────────────────────
  let results = match reg.run_all(requested, world) {
    Ok(r) => r
    Err(e) => {
      write_dump(dir, "run-error.txt", e + "\n")
      return
    }
  }
  // ── hir-traces.txt: per-fn HIR statements (provenance: fn @ file) ──────
  let hir = StringBuilder()
  hir.write_string("# HIR traces (shared statement layer, hir.mbt)\n")
  for pkgf in world.packages {
    for file in pkgf.files {
      let source = @fs.read_file_to_string(file) catch { _ => continue }
      let (impls, _) = @parser.parse_string(source, name=file)
      for pair in collect_fn_traces(impls, file, source) {
        hir.write_string("fn " + pair.0 + " @ " + file + "\n")
        for stmt in pair.1 {
          hir.write_string("  " + stmt.show() + "\n")
        }
      }
    }
  }
  write_dump(dir, "hir-traces.txt", hir.to_string())
  // ── taint-findings.txt: exact file:line provenance (T4.5 evidence) ─────
  let tf = StringBuilder()
  tf.write_string("# taint-flow findings (provenance: file:line + rule)\n")
  match results.get(TaintFlow) {
    Some(TaintFlowR(scan)) => {
      tf.write_string("files scanned: " + scan.files_scanned.to_string() + "\n")
      for f in scan.findings {
        tf.write_string(
          f.file +
          ":" +
          f.line.to_string() +
          "  " +
          rule_id_str(f.rule_id) +
          "  fp=" +
          f.fingerprint +
          "\n",
        )
      }
    }
    _ => tf.write_string("(no taint result)\n")
  }
  write_dump(dir, "taint-findings.txt", tf.to_string())
  // ── call-graph.txt: edges with caller provenance ───────────────────────
  let cg = StringBuilder()
  cg.write_string("# call graph (caller -> callee; provenance: caller)\n")
  match results.get(CallGraph) {
    Some(CallGraphR(g)) => {
      cg.write_string(
        "site totals: bound=" +
        g.bound_sites.to_string() +
        " candidate=" +
        g.candidate_sites.to_string() +
        " unresolved=" +
        g.unresolved_sites.to_string() +
        " pt-refined=" +
        g.pt_resolved_sites.to_string() +
        "\n\n[direct edges]\n",
      )
      for e in g.edges {
        cg.write_string(e + "\n")
      }
      cg.write_string("\n[dispatch edges (devirtualized)]\n")
      for e in g.dispatch_edges {
        cg.write_string(e + "\n")
      }
      cg.write_string("\n[unresolved]\n")
      for e in g.unresolved {
        cg.write_string(e + "\n")
      }
    }
    _ => cg.write_string("(no call-graph result)\n")
  }
  write_dump(dir, "call-graph.txt", cg.to_string())
  // ── points-to.txt: per-fn constraints + solutions ──────────────────────
  let pt = StringBuilder()
  pt.write_string("# points-to (per fn; provenance: fn @ file, sites)\n")
  for pkgf in world.packages {
    for file in pkgf.files {
      let source = @fs.read_file_to_string(file) catch { _ => continue }
      let (impls, _) = @parser.parse_string(source, name=file)
      for pair in collect_fn_traces(impls, file, source) {
        let constraints : Array[PTConstraint] = []
        constraints_from_trace(pair.1, constraints)
        if constraints.length() == 0 {
          continue
        }
        let sol = solve_pt_constraints(constraints)
        pt.write_string("fn " + pair.0 + " @ " + file + "\n")
        pt.write_string(
          "  constraints: " +
          constraints.length().to_string() +
          "  iterations: " +
          sol.iterations.to_string() +
          "  converged: " +
          (if sol.converged { "yes" } else { "NO (budget)" }) +
          "\n",
        )
        let mut nodes = 0
        sol.pts.each(fn(node, sites) {
          if sites.length() > 0 && nodes < 50 {
            let sites_txt : Array[String] = []
            sites.each(fn(s, _) { sites_txt.push(s) })
            pt.write_string(
              "  pts " +
              pt_node_show(node) +
              " -> " +
              sites_txt.join(", ") +
              "\n",
            )
            nodes += 1
          }
        })
      }
    }
  }
  write_dump(dir, "points-to.txt", pt.to_string())
  // ── live-vars.txt: per-fn summaries ────────────────────────────────────
  let lv = StringBuilder()
  lv.write_string("# live variables (per fn; provenance: fn @ file)\n")
  for pkgf in world.packages {
    for file in pkgf.files {
      let source = @fs.read_file_to_string(file) catch { _ => continue }
      let (impls, _) = @parser.parse_string(source, name=file)
      for pair in collect_fn_traces(impls, file, source) {
        let summary = live_vars_of_trace(pair.1)
        if summary.total == 0 {
          continue
        }
        lv.write_string(
          "fn " +
          pair.0 +
          " @ " +
          file +
          "  total=" +
          summary.total.to_string() +
          " live=" +
          summary.live.to_string() +
          " dead=" +
          summary.dead.to_string() +
          "\n",
        )
      }
    }
  }
  write_dump(dir, "live-vars.txt", lv.to_string())
}

///|
fn write_dump(dir : String, name : String, content : String) -> Unit {
  let p = @path.Path(dir).join(@path.Path(name)).0
  @fs.write_string_to_file(p, content) catch {
    _ => ()
  }
}
