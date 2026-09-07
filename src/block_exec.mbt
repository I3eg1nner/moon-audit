// D1b: CFG block executor for the taint engine (hybrid deployment).
// Executes a D1a BlockIr with a block-level worklist:
//   - per-block state = decl/position facts (Map[String, Taint])
//   - successor propagation with fact-level join (taint_or, the shared
//     SecurityFact lattice view — same op the structured walk uses)
//   - convergence = no state change; visit cap with exhaustion counting
//     (T3b budget pattern)
// Sink semantics are REUSED, not duplicated: SinkStmt only ever enters a
// trace when the structured walk FIRED that finding (hir_emit_sink is
// called inside the tainted branch), so the block executor treats each
// SinkStmt(kind, temps) as one fired sink, re-checking that some carried
// temp is tainted (temp taints are recorded by the walk at emission).
// Control statements (Ret/Raise/Break/Continue/DeferReg) carry no decl
// effects; ordering comes from the CFG edges.
// Deployment (D1b hybrid): per function — build+validate CFG; if valid,
// execute blocks and compare fired sinks vs the AST path; identical ->
// cfg_executed, else cfg_divergent (AST findings kept, disclosed);
// build/validate failure -> ast_fallback. All three counters are
// disclosed in analysis-scope. D1c retires the comparison (block exec
// becomes the producer) once divergence is zero on the corpora.

///|
pub(all) struct CfgExecCounters {
  mut cfg_executed : Int
  mut ast_fallback : Int
  mut cfg_divergent : Int
  mut visits_capped : Int
}

///|
let cfg_exec : CfgExecCounters = {
  cfg_executed: 0,
  ast_fallback: 0,
  cfg_divergent: 0,
  visits_capped: 0,
}

///|
pub fn cfg_exec_reset() -> Unit {
  cfg_exec.cfg_executed = 0
  cfg_exec.ast_fallback = 0
  cfg_exec.cfg_divergent = 0
  cfg_exec.visits_capped = 0
}

///|
pub fn cfg_exec_stats() -> (Int, Int, Int, Int) {
  (
    cfg_exec.cfg_executed,
    cfg_exec.ast_fallback,
    cfg_exec.cfg_divergent,
    cfg_exec.visits_capped,
  )
}

///|
fn state_get(st : Map[String, Taint], k : String) -> Taint {
  match st.get(k) {
    Some(t) => t
    None => Clean
  }
}

///|
fn state_join_into(st : Map[String, Taint], other : Map[String, Taint]) -> Bool {
  // join other into st; returns true if st changed (monotone growth)
  let mut changed = false
  other.each(fn(k, v) {
    let old = state_get(st, k)
    let joined = taint_or(old, v)
    if joined != old {
      st[k] = joined
      changed = true
    }
  })
  changed
}

// per-statement transfer — PURE, shared entry point for any driver that
// executes BlockIr statements (block executor today; D1c consumers next)

///|
fn exec_stmt(
  s : Stmt,
  st : Map[String, Taint],
  temp_facts : Map[Int, Taint],
  fired : Array[String],
) -> Unit {
  match s {
    LetEvalTemp(_) => () // temp taints precomputed by the walk
    BindVar(key, rhs) =>
      match rhs {
        RTemp(t) =>
          st[key] = match temp_facts.get(t) {
            Some(v) => v
            None => Tainted // unknown temp: conservative
          }
        RWhole => st[key] = Tainted // no temp: conservative (divergence
        // will surface in the comparison instead of hiding it)
      }
    BindTuplePositions(key, temps) => {
      let mut i = 0
      while i < temps.length() {
        st[key + "|#tuple|" + i.to_string()] = match temp_facts.get(temps[i]) {
          Some(v) => v
          None => Tainted
        }
        i += 1
      }
    }
    BindCtorPositions(key, ctor, temps) => {
      let mut i = 0
      while i < temps.length() {
        st[key + "|" + ctor + "|" + i.to_string()] = match
          temp_facts.get(temps[i]) {
          Some(v) => v
          None => Tainted
        }
        i += 1
      }
    }
    CallStmt(target, temps) =>
      // sink classification reuses the same name predicate + positional
      // value-slot rule as the walk (receiver-first temps for methods:
      // temps[0]=recv, temps[1]=name arg, temps[2]=value; plain fn:
      // temps[0]=name, temps[1]=value)
      if is_header_setter(target) {
        let value_taint = if temps.length() > 2 {
          match temp_facts.get(temps[2]) {
            Some(v) => v
            None => Clean
          }
        } else if temps.length() > 1 {
          match temp_facts.get(temps[1]) {
            Some(v) => v
            None => Clean
          }
        } else {
          Clean
        }
        if is_tainted(value_taint) {
          fired.push("header:" + target)
        }
      }
    SinkStmt(kind, temps) => {
      // equivalence contract: this statement exists iff the walk fired;
      // re-check taint of at least one carried temp for independence
      let mut any_tainted = false
      for t in temps {
        match temp_facts.get(t) {
          Some(v) => if is_tainted(v) { any_tainted = true }
          None => any_tainted = true // unknown temp: keep fired
        }
      }
      if any_tainted {
        fired.push(kind)
      }
    }
    AssignStmt(key, t) =>
      st[key] = match temp_facts.get(t) {
        Some(v) => v
        None => Tainted
      }
    RetStmt(_) | RaiseStmt(_) | BreakStmt(_) | ContinueStmt | DeferReg(_) => () // control-only: ordering lives in the CFG edges
  }
}

///|
fn exec_block_ir(ir : BlockIr, temp_facts : Map[Int, Taint]) -> Array[String]? {
  // returns None when visit budget is exhausted (caller treats the
  // function as divergent: honest, never silently truncated)
  let n = ir.blocks.length()
  if n == 0 {
    return Some([])
  }
  let states : Array[Map[String, Taint]] = []
  for _ in 0..<n {
    states.push(Map([]))
  }
  let visited : Array[Int] = []
  for _ in 0..<n {
    visited.push(0)
  }
  let cap = 16 // per-block visit cap (T3b budget pattern)
  let queue : Array[Int] = [ir.entry]
  let out_fired : Array[String] = []
  while queue.length() > 0 {
    let b = match queue.pop() {
      Some(x) => x
      None => break
    }
    visited[b] += 1
    if visited[b] > cap {
      cfg_exec.visits_capped += 1
      return None
    }
    let st = states[b]
    let fired : Array[String] = []
    for s in ir.blocks[b].stmts {
      exec_stmt(s, st, temp_facts, fired)
    }
    // propagate to successors (join; re-enqueue on growth)
    for succ in ir.blocks[b].succs {
      let changed = state_join_into(states[succ], st)
      if changed || visited[succ] == 0 {
        queue.push(succ)
      }
    }
    for f in fired {
      out_fired.push(f)
    }
  }
  Some(out_fired)
}

///|
fn cfg_hybrid_classify(
  fn_name : String,
  body : @syntax.Expr,
  temp_facts : Map[Int, Taint],
  ast_kinds : Array[String],
) -> String {
  // returns "cfg" | "fallback" | "divergent" and bumps counters
  let ir = build_block_ir(fn_name, body)
  let problems = validate_cfg(ir)
  if problems.length() > 0 {
    cfg_exec.ast_fallback += 1
    return "fallback"
  }
  match exec_block_ir(ir, temp_facts) {
    None => {
      cfg_exec.cfg_divergent += 1
      "divergent"
    }
    Some(block_fired) => {
      let same = block_fired.length() == ast_kinds.length() &&
        block_fired.filter(fn(k) { ast_kinds.contains(k) }).length() ==
        block_fired.length()
      if same {
        cfg_exec.cfg_executed += 1
        "cfg"
      } else {
        cfg_exec.cfg_divergent += 1
        "divergent"
      }
    }
  }
}

// scanner-side suffix for analysis-scope (D1b disclosure)

///|
pub fn cfg_exec_scope_suffix() -> String {
  let s = cfg_exec_stats()
  "; cfg-executed=" +
  s.0.to_string() +
  "; ast-fallback=" +
  s.1.to_string() +
  "; cfg-divergent=" +
  s.2.to_string() +
  "; cfg-visits-capped=" +
  s.3.to_string() +
  "(measured, D1b hybrid: AST findings authoritative; block exec runs on every buildable CFG and is verified against the AST result per function)"
}
