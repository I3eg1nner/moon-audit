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
  mut widenings : Int // E1b: phase-2 restarts after conservative widening
  mut cfg_unconfirmed : Int // E1b: walk candidates not confirmed by executor
}

///|
let cfg_exec : CfgExecCounters = {
  cfg_executed: 0,
  ast_fallback: 0,
  cfg_divergent: 0,
  visits_capped: 0,
  widenings: 0,
  cfg_unconfirmed: 0,
}

///|
pub fn cfg_exec_reset() -> Unit {
  cfg_exec.cfg_executed = 0
  cfg_exec.ast_fallback = 0
  cfg_exec.cfg_divergent = 0
  cfg_exec.visits_capped = 0
  cfg_exec.widenings = 0
  cfg_exec.cfg_unconfirmed = 0
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

// E1b: widened-restart count for scope disclosure

///|
pub fn cfg_exec_widening_count() -> Int {
  cfg_exec.widenings
}

///|
pub fn cfg_exec_unconfirmed_count() -> Int {
  cfg_exec.cfg_unconfirmed
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
  fired : Array[(String, Int)],
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
    CallStmt(_, _) => ()
    // E1a: sink firing lives ONLY in SinkStmt (emitted by the builder with
    // the value-slot temps; CallStmt is a pure call — one firing semantics)
    SinkStmt(kind, temps, line) => {
      // E1b pairing mirror: the walk emits SinkStmt only for non-field-ref
      // findings (TaintedFieldRef is a summary re-check, not a local
      // firing), so the executor fires only when some value temp carries
      // a NON-field-ref taint
      let mut any_firable = false
      for t in temps {
        match temp_facts.get(t) {
          Some(v) =>
            if is_tainted(v) {
              match v {
                TaintedFieldRef(_, _) => ()
                _ => any_firable = true
              }
            }
          None => any_firable = true // unknown temp: keep fired
        }
      }
      if any_firable {
        // E1b: line-addressed firing, unique per (kind, line)
        let mut seen = false
        for e in fired {
          if e.0 == kind && e.1 == line {
            seen = true
            break
          }
        }
        if !seen {
          fired.push((kind, line))
        }
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
fn exec_block_ir(
  ir : BlockIr,
  temp_facts : Map[Int, Taint],
) -> Array[(String, Int)]? {
  // returns None only when even the E1b widening restart fails to
  // converge (phase 2 also hits the cap: caller keeps the AST result);
  // phase 1 cap -> conservative widening of every state key (Tainted
  // joins are absorbing, so a widened state cannot keep growing) + a
  // single restart with the visit counters cleared
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
  let out_fired : Array[(String, Int)] = []
  let mut phase = 0
  let mut queue : Array[Int] = [ir.entry]
  while queue.length() > 0 {
    let b = match queue.pop() {
      Some(x) => x
      None => break
    }
    visited[b] += 1
    if visited[b] > cap {
      cfg_exec.visits_capped += 1
      if phase == 0 {
        // E1b widening: top every existing fact, restart once
        cfg_exec.widenings += 1
        phase = 1
        for st in states {
          let keys : Array[String] = []
          st.each(fn(k, _) { keys.push(k) })
          for k in keys {
            st[k] = taint_or(or_clean_exec(st.get(k)), Tainted)
          }
        }
        for i in 0..<n {
          visited[i] = 0
        }
        queue = [ir.entry]
        continue
      }
      return None
    }
    let st = states[b]
    let fired : Array[(String, Int)] = []
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
fn or_clean_exec(t : Taint?) -> Taint {
  match t {
    Some(v) => v
    None => Clean
  }
}

// E1b execution-mode flag: default = CFG-authoritative (the executor
// confirms/refutes the walk's candidate findings); --cfg-verify = pure
// comparison mode (never filters; catches builder regressions)

///|
priv struct CfgMode {
  mut verify : Bool
}

///|
let cfg_mode : CfgMode = { verify: false, }

///|
pub fn set_cfg_verify_mode(b : Bool) -> Unit {
  cfg_mode.verify = b
}

///|
pub fn cfg_verify_mode() -> Bool {
  cfg_mode.verify
}

// E1b verdict: apply the executor's firing set to this function's
// candidate CWE-113 findings. Returns the number of findings REFUTED
// (dropped). In --cfg-verify mode nothing is ever dropped (comparison
// only). Per-kind deficit drives the drop count; CWE-116 output findings
// share the range but are not trace-pairable and are never dropped.

// E1b confirmation: walk candidates the executor did NOT fire. These are
// KEPT (a security tool must not drop a finding when builder coverage
// gaps — closure-inlined bodies, noraise arms, loop re-pass temp ids —
// are indistinguishable from a true refutation) and DISCLOSED via the
// cfg-unconfirmed counter; --cfg-verify additionally fails the scan
// (exit 2) on any unconfirmed candidate, gating builder regressions in
// CI. Drop-based refutation becomes safe only after the builder covers
// the full walk semantics (tracked as T2 remaining).

///|
pub fn executor_unconfirmed(
  ast_kinds : Array[(String, Int)],
  fired : Array[(String, Int)],
) -> Int {
  let mut n = 0
  for cand in ast_kinds {
    let mut hit = false
    for f in fired {
      if f.0 == cand.0 && f.1 == cand.1 {
        hit = true
        break
      }
    }
    if !hit {
      n += 1
    }
  }
  n
}

///|
pub fn cfg_hybrid_classify(
  fn_name : String,
  body : @syntax.Expr,
  temp_facts : Map[Int, Taint],
  ast_kinds : Array[(String, Int)],
  rules : TaintRuleset,
) -> String {
  // returns "cfg" | "fallback" | "divergent" and bumps counters.
  // E1b: default (authority) mode — when the executor fires FEWER sinks
  // than the walk, the excess candidates are REFUTED (dropped, counted);
  // --cfg-verify keeps the D1b comparison-only semantics.
  let ir = build_block_ir(fn_name, body, rules~)
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
      // E1b: set equality over unique (kind, line) — both sides deduped
      let mut all_in = true
      for e in block_fired {
        let mut hit = false
        for c in ast_kinds {
          if c.0 == e.0 && c.1 == e.1 {
            hit = true
            break
          }
        }
        if !hit {
          all_in = false
          break
        }
      }
      let same = block_fired.length() == ast_kinds.length() && all_in
      if same {
        cfg_exec.cfg_executed += 1
        "cfg"
      } else {
        cfg_exec.cfg_unconfirmed += executor_unconfirmed(ast_kinds, block_fired)
        cfg_exec.cfg_divergent += 1
        "divergent"
      }
    }
  }
}

// scanner-side suffix for analysis-scope (D1b disclosure)

///|
pub fn cfg_exec_scope_suffix() -> String {
  let mode = if cfg_mode.verify {
    "cfg-verify(strict comparison; any unconfirmed candidate fails the scan, exit 2)"
  } else {
    "cfg-authoritative(executor confirms/refutes walk candidates)"
  }
  "; cfg-executed=" +
  cfg_exec.cfg_executed.to_string() +
  "; ast-fallback=" +
  cfg_exec.ast_fallback.to_string() +
  "; cfg-divergent=" +
  cfg_exec.cfg_divergent.to_string() +
  "; cfg-unconfirmed=" +
  cfg_exec.cfg_unconfirmed.to_string() +
  "; cfg-widenings=" +
  cfg_exec.widenings.to_string() +
  "; cfg-visits-capped=" +
  cfg_exec.visits_capped.to_string() +
  "(measured, E1b: " +
  mode +
  ")"
}

// G1: structural unreachability analysis — returns the line numbers of
// SinkStmts that live in CFG blocks with NO path from the entry block.
// This is a purely structural property (graph reachability), independent
// of taint semantics: it identifies dead-code sinks the AST walk would
// conservatively report.

///|
pub fn cfg_unreachable_sink_lines(
  fn_name : String,
  body : @syntax.Expr,
  rules : TaintRuleset,
) -> Array[Int] {
  let ir = build_block_ir(fn_name, body, rules~)
  let n = ir.blocks.length()
  if n == 0 {
    return []
  }
  // BFS from entry to compute reachable set
  let reachable : Array[Bool] = []
  for _ in 0..<n {
    reachable.push(false)
  }
  let queue : Array[Int] = [ir.entry]
  reachable[ir.entry] = true
  while queue.length() > 0 {
    let b = match queue.pop() {
      Some(x) => x
      None => break
    }
    for succ in ir.blocks[b].succs {
      if !reachable[succ] {
        reachable[succ] = true
        queue.push(succ)
      }
    }
  }
  // collect SinkStmt lines in unreachable blocks
  let lines : Array[Int] = []
  for i in 0..<n {
    if !reachable[i] {
      for s in ir.blocks[i].stmts {
        match s {
          SinkStmt(_, _, line) => if !lines.contains(line) { lines.push(line) }
          _ => ()
        }
      }
    }
  }
  lines
}
