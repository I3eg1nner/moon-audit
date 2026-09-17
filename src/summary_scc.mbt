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
  name : String // P0: qualified identity — "Type::method" or bare fn name
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
  pkg_root? : String = "", // R1 P0: project root for pkg-path derivation
) -> Array[SummaryUnit] {
  // R1 P0: package-qualified identity prevents cross-package collisions
  // (e.g. a/pick vs b/pick would share the bare name "pick")
  let pkg_path = derive_pkg_path(file, pkg_root~)
  let units : Array[SummaryUnit] = []
  for item in impls {
    match item {
      TopFuncDef(fun_decl~, decl_body~, ..) => {
        // P0: methods declared via "fn Type::method" get a qualified name;
        // R1: free functions also get pkg prefix
        let name = match fun_decl.type_name {
          Some(tn) => {
            let base = type_name_str_qual(tn) + "::" + fun_decl.name.name
            if pkg_path != "" {
              pkg_path + "::" + base
            } else {
              base
            }
          }
          None =>
            if pkg_path != "" {
              pkg_path + "::" + fun_decl.name.name
            } else {
              fun_decl.name.name
            }
        }
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
      TopImpl(self_ty~, method_name~, params~, body~, ..) => {
        // P0: methods keyed by "SelfTy::method" to prevent cross-type
        // summary collisions (e.g. First::pick vs Second::pick)
        let self_name = match self_ty {
          Some(t) => qual_type_str(t)
          None => "?"
        }
        let base = self_name + "::" + method_name.name
        let name = if pkg_path != "" { pkg_path + "::" + base } else { base }
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

// ── helpers for qualified naming (P0) ─────────────────────────────────────

///|
// R1 P0: derive a package path from the file path relative to the project
// root. e.g. root="/proj", file="/proj/a/a.mbt" → "a"; file="/proj/src/main.mbt" → "src"

///|
fn derive_pkg_path(file : String, pkg_root? : String = "") -> String {
  if pkg_root == "" {
    return "" // no root context: unqualified (backward compat)
  }
  let norm_file = canonical_dir(file)
  let norm_root = canonical_dir(pkg_root)
  let prefix = norm_root + "/"
  if norm_file.has_prefix(prefix) {
    let rel = Show::to_string(norm_file[prefix.length():])
    let idx = find_last_slash(rel)
    if idx > 0 {
      Show::to_string(rel[:idx])
    } else {
      "" // file is at root level
    }
  } else {
    "" // file outside root
  }
}

///|
fn find_last_slash(s : String) -> Int {
  let mut best = -1
  let mut i = 0
  while i < s.length() {
    if s[i] == 47 {
      // '/'
      best = i
    }
    i += 1
  }
  best
}

///|
fn type_name_str_qual(tn : @syntax.TypeName) -> String {
  match tn.name {
    Ident(name~) => name
    Dot(pkg~, id~) => pkg + "::" + id
  }
}

///|
fn qual_type_str(ty : @syntax.Type) -> String {
  match ty {
    Name(constr_id~, ..) =>
      match constr_id.id {
        Ident(name~) => name
        Dot(pkg~, id~) => pkg + "::" + id
      }
    Option(ty~, ..) => qual_type_str(ty)
    Any(..) => "?"
    Arrow(..) => "fn"
    Tuple(..) => "Tuple"
    Object(cid) =>
      match cid.id {
        Ident(name~) => name
        Dot(pkg~, id~) => pkg + "::" + id
      }
  }
}

// ── callee extraction (lightweight visitor per unit body) ────────────────

///|
priv struct CalleeCollector {
  callees : Array[String]
  pkg_path : String // R1 P0: for qualified callee names
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
        Ident(name~) =>
          if env.pkg_path != "" {
            env.callees.push(env.pkg_path + "::" + name)
          } else {
            env.callees.push(name)
          }
        Dot(id~, ..) =>
          if env.pkg_path != "" {
            env.callees.push(env.pkg_path + "::" + id)
          } else {
            env.callees.push(id)
          }
      }
    Method(type_name~, method_name~, ..) => {
      let tn = match type_name.name {
        Ident(name~) => name
        Dot(pkg~, id~) => pkg + "::" + id
      }
      if env.pkg_path != "" {
        env.callees.push(env.pkg_path + "::" + tn + "::" + method_name.name)
      } else {
        env.callees.push(tn + "::" + method_name.name)
      }
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
fn unit_callees(
  body : @syntax.Expr,
  pkg_path? : String = "", // R1 P0
) -> Array[String] {
  let collector : CalleeCollector = { callees: [], pkg_path, }
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
// R1 P0: find the common root from unit file paths (longest shared dir)

///|

///|
pub fn collect_summaries_scc(
  units : Array[SummaryUnit],
  ictx : InterProceduralContext,
  pkg_root? : String = "",
  strategy? : ContextStrategy = Insensitive,
  warn_unimplemented? : Bool = true,
) -> Unit {
  // T7.1: dispatch skeleton — Insensitive is the current behavior; other
  // strategies are announced but not yet implemented (warn, don't ignore)
  if warn_unimplemented && !strategy.is_implemented() {
    println(
      "moon-audit: warning: context strategy '" +
      strategy.name() +
      "' is not implemented; using insensitive baseline (no silent downgrade)",
    )
  }
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
    for c in unit_callees(u.body, pkg_path=derive_pkg_path(u.file, pkg_root~)) {
      if node_set.contains(c) {
        edges.push(c)
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
      collect_summary_func(u.params, u.body, u.name, u.line, u.file, ictx, "")
      return
    }
  }
}
