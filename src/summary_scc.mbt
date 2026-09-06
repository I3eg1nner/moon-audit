// T4.2 thin: SCC-ordered iterative summary collection (replaces the fixed
// two-pass pre-collect/re-collect in scanner). Summary collection now
// CONSUMES callee summaries (ret_from + param_sinks transitivity, wired in
// taint_flow.mbt), so collection order matters: Tarjan SCC over the fn
// call graph gives a bottom-up (callee-first) order; SCCs with cycles
// (recursion) iterate to a fixpoint — the summary lattice (finite sets of
// param/sink/field facts under union) is monotone, so convergence is
// guaranteed; the budget (|SCC|+2 sweeps) is a safety valve whose
// exhaustion is counted and disclosed (not-converged != silent).

///|
pub(all) struct SummaryUnit {
  name : String // summary key (short name; methods keyed by method name)
  params : @list.List[@syntax.Parameter]?
  body : @syntax.Expr
  file : String
  line : Int
}

// ── unit extraction (mirrors collect_func_summaries_flow's item walk) ────

///|
pub fn extract_summary_units(
  impls : @list.List[@syntax.Impl],
  file : String,
) -> Array[SummaryUnit] {
  let units : Array[SummaryUnit] = []
  for item in impls {
    match item {
      TopFuncDef(fun_decl~, decl_body~, ..) => {
        let name = fun_decl.name.name
        match decl_body {
          DeclBody(expr=Function(func~, ..)) =>
            units.push({
              name,
              params: Some(func.parameters),
              body: func.body,
              file,
              line: fun_decl.loc.start.lnum,
            })
          DeclBody(expr=body) =>
            units.push({
              name,
              params: fun_decl.decl_params,
              body,
              file,
              line: fun_decl.loc.start.lnum,
            })
          _ => ()
        }
      }
      TopImpl(method_name~, params~, body~, ..) => {
        let name = method_name.name
        match body {
          DeclBody(expr=Function(func~, ..)) =>
            units.push({
              name,
              params: Some(func.parameters),
              body: func.body,
              file,
              line: method_name.loc.start.lnum,
            })
          DeclBody(expr=body) =>
            units.push({
              name,
              params: Some(params),
              body,
              file,
              line: method_name.loc.start.lnum,
            })
          _ => ()
        }
      }
      _ => ()
    }
  }
  units
}

// ── callee extraction (lightweight visitor per unit body) ────────────────

///|
priv struct CalleeCollector {
  callees : Array[String]
}

///|
impl @syntax.IterVisitor for CalleeCollector with fn visit_Expr_Apply(
  env,
  func~,
  args~,
  loc~,
) {
  ignore(args)
  ignore(loc)
  match func {
    Ident(id~, ..) =>
      match id.name {
        Ident(name~) => env.callees.push(name)
        Dot(id~, ..) => env.callees.push(id)
      }
    Method(type_name~, method_name~, ..) => {
      let tn = match type_name.name {
        Ident(name~) => name
        Dot(pkg~, id~) => pkg + "::" + id
      }
      env.callees.push(tn + "::" + method_name.name)
    }
    _ => ()
  }
  @syntax.IterVisitor::base(env).visit_Expr_Apply(func~, args~, loc~)
}

///|
impl @syntax.IterVisitor for CalleeCollector with fn visit_Expr_DotApply(
  env,
  self~,
  method_name~,
  args~,
  return_self~,
  loc~,
) {
  ignore(self)
  ignore(args)
  ignore(return_self)
  ignore(loc)
  // method form: summaries are keyed by the short method name (T1.4 will
  // qualify); record the short form so trait/method edges join the graph
  env.callees.push(method_name.name)
  @syntax.IterVisitor::base(env).visit_Expr_DotApply(
    self~,
    method_name~,
    args~,
    return_self~,
    loc~,
  )
}

///|
fn unit_callees(body : @syntax.Expr) -> Array[String] {
  let collector : CalleeCollector = { callees: [], }
  @syntax.IterVisitor::visit_Expr(collector, body)
  collector.callees
}

// ── Tarjan SCC (recursive; graphs are per-module fn sets, small) ─────────

///|
priv struct TarjanCtx {
  index : Map[String, Int]
  low : Map[String, Int]
  on_stack : Map[String, Bool]
  stack : Array[String]
  mut counter : Int
  sccs : Array[Array[String]] // emitted callee-first (reverse condensation)
}

///|
fn tarjan_scc(
  nodes : Array[String],
  adj : Map[String, Array[String]],
) -> Array[Array[String]] {
  let ctx : TarjanCtx = {
    index: Map([]),
    low: Map([]),
    on_stack: Map([]),
    stack: [],
    counter: 0,
    sccs: [],
  }
  for n in nodes {
    if !ctx.index.contains(n) {
      tarjan_visit(n, adj, ctx)
    }
  }
  ctx.sccs
}

///|
fn tarjan_visit(
  v : String,
  adj : Map[String, Array[String]],
  ctx : TarjanCtx,
) -> Unit {
  ctx.index[v] = ctx.counter
  ctx.low[v] = ctx.counter
  ctx.counter += 1
  ctx.stack.push(v)
  ctx.on_stack[v] = true
  match adj.get(v) {
    Some(callees) =>
      for w in callees {
        if !ctx.index.contains(w) {
          tarjan_visit(w, adj, ctx)
          // tree edge: low[v] = min(low[v], low[w]) — an overwrite here
          // loses the root identity and silently drops SCCs (probe: DAG
          // caller c was never emitted)
          let lw = or_int(ctx.low.get(w), or_int(ctx.low.get(v), 0))
          let lv = or_int(ctx.low.get(v), 0)
          if lw < lv {
            ctx.low[v] = lw
          }
        } else if or_bool(ctx.on_stack.get(w), false) {
          // back/cross edge within the stack: min with w's index
          let iw = or_int(ctx.index.get(w), or_int(ctx.low.get(v), 0))
          let lv2 = or_int(ctx.low.get(v), 0)
          if iw < lv2 {
            ctx.low[v] = iw
          }
        }
      }
    None => ()
  }
  if ctx.low.get(v) == ctx.index.get(v) {
    let scc : Array[String] = []
    let mut w = ""
    let mut ok = true
    while ok {
      let top = ctx.stack.pop()
      match top {
        Some(t) => {
          w = t
          ctx.on_stack[w] = false
          scc.push(w)
          ok = w != v
        }
        None => ok = false
      }
    }
    ctx.sccs.push(scc)
  }
}

///|
fn or_int(v : Int?, fallback : Int) -> Int {
  match v {
    Some(x) => x
    None => fallback
  }
}

///|
fn or_bool(v : Bool?, fallback : Bool) -> Bool {
  match v {
    Some(x) => x
    None => fallback
  }
}

// ── summary signature (fixpoint stability check) ─────────────────────────

///|
fn summary_signature(ictx : InterProceduralContext, name : String) -> String {
  match ictx.summaries.get(name) {
    Some(s) => {
      let parts : Array[String] = []
      let sink_keys : Array[String] = []
      s.param_sinks.each(fn(k, _) { sink_keys.push(k) })
      sink_keys.sort()
      parts.push("sinks=" + sink_keys.join(","))
      parts.push("ret=" + s.ret_from.join(","))
      let field_entries : Array[String] = []
      s.field_taint.each(fn(r, arr) {
        for pair in arr {
          field_entries.push(r + "." + pair.0 + "<-" + pair.1)
        }
      })
      field_entries.sort()
      parts.push("fields=" + field_entries.join(","))
      let fs_entries : Array[String] = []
      for pair in s.param_field_sinks {
        fs_entries.push(pair.0 + "." + pair.1)
      }
      fs_entries.sort()
      parts.push("fsinks=" + fs_entries.join(","))
      parts.join(";")
    }
    None => ""
  }
}

// ── driver ────────────────────────────────────────────────────────────────

///|
pub fn collect_summaries_scc(
  units : Array[SummaryUnit],
  ictx : InterProceduralContext,
) -> Unit {
  if units.length() == 0 {
    return
  }
  // node set + normalized adjacency (edges into non-collected fns dropped;
  // "Type::method" targets fall back to the short key)
  let node_set : Map[String, Bool] = Map([])
  for u in units {
    node_set[u.name] = true
  }
  let adj : Map[String, Array[String]] = Map([])
  for u in units {
    let edges : Array[String] = []
    for c in unit_callees(u.body) {
      if node_set.contains(c) {
        edges.push(c)
      } else {
        let idx = find_last(c, "::")
        if idx > 0 {
          let short = Show::to_string(c[idx + 2:])
          if node_set.contains(short) {
            edges.push(short)
          }
        }
      }
    }
    adj[u.name] = edges
  }
  let nodes : Array[String] = []
  for u in units {
    nodes.push(u.name)
  }
  // Tarjan emits SCCs callee-first: single pass over the emission order
  // processes every DAG dependency bottom-up; cyclic SCCs iterate to
  // fixpoint under the union lattice (budget |SCC|+2 sweeps).
  for scc in tarjan_scc(nodes, adj) {
    let self_loop = match adj.get(scc[0]) {
      Some(arr) => arr.contains(scc[0])
      None => false
    }
    let cyclic = scc.length() > 1 || self_loop
    if !cyclic {
      collect_one_unit(scc[0], units, ictx)
    } else {
      let budget = scc.length() + 2
      let mut sweeps = 0
      let mut converged = false
      while !converged && sweeps < budget {
        // snapshot signatures of this SCC before the sweep
        let before : Map[String, String] = Map([])
        for n in scc {
          before[n] = summary_signature(ictx, n)
        }
        for n in scc {
          collect_one_unit(n, units, ictx)
        }
        sweeps += 1
        converged = true
        for n in scc {
          if summary_signature(ictx, n) != or_sig(before.get(n)) {
            converged = false
          }
        }
      }
      if !converged {
        ictx.not_converged += 1
      }
    }
  }
}

///|

///|
fn or_sig(v : String?) -> String {
  match v {
    Some(s) => s
    None => ""
  }
}

///|
fn collect_one_unit(
  name : String,
  units : Array[SummaryUnit],
  ictx : InterProceduralContext,
) -> Unit {
  for u in units {
    if u.name == name {
      collect_summary_func(u.params, u.body, u.name, u.line, u.file, ictx)
      return
    }
  }
}
