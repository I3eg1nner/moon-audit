// T3.4 thin: classic backward live-variable analysis on the SHARED HIR
// statement layer (hir.mbt Stmt). This is the "second analysis" proof for
// ROADMAP-T T3.4: the same IR that feeds the taint engine also feeds a
// textbook dataflow analysis, WITHOUT re-interpreting the AST.
// Static contract: this file must not call taint_flow.mbt functions — it
// consumes Array[Stmt] only (constants propagation / DCE stay out of scope).

///|
pub(all) struct LiveVarInfo {
  decl : String // decl key (scope id + name) or temp key ("t<id>")
  def_site : Int // first definition statement index (-1 = param-like)
  last_use : Int // last use statement index (-1 = never used)
}

///|
pub(all) struct LiveVarsSummary {
  infos : Array[LiveVarInfo]
  total : Int
  live : Int
  dead : Int
}

///|
pub fn LiveVarsSummary::dead_ratio(self : LiveVarsSummary) -> Int {
  if self.total == 0 {
    return 0
  }
  self.dead * 100 / self.total
}

// ── use/kill extraction per statement ────────────────────────────────────

// keys used (read) by a statement; temps live in the "t<id>" namespace

///|
fn stmt_uses(stmt : Stmt) -> Array[String] {
  match stmt {
    LetEvalTemp(_, _) => [] // temp defined here; arg eval is abstracted
    BindVar(_, RTemp(t)) => ["t" + t.to_string()]
    BindVar(_, RWhole) => []
    BindTuplePositions(_, temps) => temp_keys(temps)
    BindCtorPositions(_, _, temps) => temp_keys(temps)
    CallStmt(_, temps) => temp_keys(temps)
    SinkStmt(_, temps) => temp_keys(temps)
    AssignStmt(_, t) => ["t" + t.to_string()]
    // D1a control statements: only value-carrying ones use temps
    RetStmt(Some(t)) | BreakStmt(Some(t)) | RaiseStmt(t) =>
      ["t" + t.to_string()]
    RetStmt(None) | BreakStmt(None) | ContinueStmt | DeferReg(_) => []
  }
}

// keys killed (defined) by a statement

///|
fn stmt_kills(stmt : Stmt) -> Array[String] {
  match stmt {
    LetEvalTemp(t, _) => ["t" + t.to_string()]
    BindVar(decl, _) => [decl]
    BindTuplePositions(decl, _) => [decl]
    BindCtorPositions(decl, _, _) => [decl]
    CallStmt(_, _) => []
    SinkStmt(_, _) => []
    AssignStmt(decl, _) => [decl]
    // D1a control statements define no value keys
    RetStmt(_) | BreakStmt(_) | ContinueStmt | RaiseStmt(_) | DeferReg(_) => []
  }
}

///|
fn temp_keys(temps : Array[Int]) -> Array[String] {
  let keys : Array[String] = []
  for t in temps {
    keys.push("t" + t.to_string())
  }
  keys
}

// ── backward analysis ────────────────────────────────────────────────────

///|
pub fn live_vars_of_trace(trace : Array[Stmt]) -> LiveVarsSummary {
  // decl/temp key -> (def_site, last_use)
  let def_site : Map[String, Int] = Map([])
  let last_use : Map[String, Int] = Map([])
  // record definitions (first def wins; re-assign updates nothing for
  // the summary — classic thin slice: report per key)
  let mut i = 0
  for stmt in trace {
    for k in stmt_kills(stmt) {
      if !def_site.contains(k) {
        def_site[k] = i
      }
    }
    i += 1
  }
  // backward: a use at index i marks last_use only if not already marked
  // by a LATER index (we walk reverse, so first hit is the last use)
  let live_now : Map[String, Bool] = Map([]) // keys live at current point
  let mut j = trace.length() - 1
  while j >= 0 {
    let stmt = trace[j]
    // process kills THEN uses (backward: uses happen before the def of
    // the same statement kills — e.g. BindVar(decl, RTemp(t)) reads t
    // and writes decl: t stays live, decl is killed at this point)
    for k in stmt_kills(stmt) {
      live_now[k] = false // killed (defined) here
      if !last_use.contains(k) {
        // not used after this point; def site bookkeeping only
        ignore(k)
      }
    }
    for k in stmt_uses(stmt) {
      live_now[k] = true
      if !last_use.contains(k) {
        last_use[k] = j
      }
    }
    j -= 1
  }
  // summary
  let infos : Array[LiveVarInfo] = []
  let mut total = 0
  let mut live = 0
  let mut dead = 0
  def_site.each(fn(k, d) {
    let u = match last_use.get(k) {
      Some(v) => v
      None => -1
    }
    infos.push({ decl: k, def_site: d, last_use: u, })
    total += 1
    if u > d || (u >= 0 && d == -1) {
      live += 1
    } else {
      dead += 1 // never used, or used only at/ before its (re)definition
    }
  })
  { infos, total, live, dead, }
}

// ── driver-facing formatting ─────────────────────────────────────────────

///|
pub fn live_vars_line(summary : LiveVarsSummary) -> String {
  "decls(total=" +
  summary.total.to_string() +
  ", live=" +
  summary.live.to_string() +
  ", dead=" +
  summary.dead.to_string() +
  ", dead%=" +
  summary.dead_ratio().to_string() +
  ")"
}

///|
pub fn live_vars_examples(summary : LiveVarsSummary, max : Int) -> String {
  // show dead decls first (they are the actionable output)
  let parts : Array[String] = []
  let mut shown = 0
  for info in summary.infos {
    if info.last_use == -1 && shown < max {
      parts.push(
        info.decl + " (dead at def #" + info.def_site.to_string() + ")",
      )
      shown += 1
    }
  }
  if shown < max {
    for info in summary.infos {
      if info.last_use >= 0 && shown < max {
        parts.push(
          info.decl +
          " (def #" +
          info.def_site.to_string() +
          ", last use #" +
          info.last_use.to_string() +
          ")",
        )
        shown += 1
      }
    }
  }
  if parts.length() == 0 {
    "(no decls)"
  } else {
    parts.join("; ")
  }
}
