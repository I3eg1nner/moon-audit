// T4.3 thin (slice 1/2): points-to data layer — UNWIRED, zero behavior
// change. Constraint types + an Andersen-style worklist solver over
// monotone set union + a pure generator from the HIR statement layer
// (hir.mbt baseline Stmt variants only).
//
// Static contract (ROADMAP-T T4.3): this module must NOT import or
// replicate taint semantics — it only carries (var -> allocation-site)
// facts. Site naming follows the G4 heap model convention
// ("file:line" allocation sites; "fn@f.paramN" / "tN" / decl-key nodes).
//
// D2a: the Store/Load retrigger gap (gate14 P1) is CLOSED — PTStore is
// registered as a reader of BOTH its base var and its value var, and
// fstore growth wakes every PTLoad on that field (field-keyed index).
// Propagation is now demand-driven to a genuine fixpoint; budget
// exhaustion is disclosed via converged=false (same as T3b).
//
// Constraint semantics (subset-based, field-sensitive):
//   PTAlloc(v, s)      pts(v) ⊇ {s}
//   PTCopy(to, from)   pts(to) ⊇ pts(from)        (Subset; also encodes
//                      ParamToParam/ReturnOf via "fn@f.paramN" nodes)
//   PTStore(sv, f, vv) ∀s ∈ pts(sv): fstore(s,f) ⊇ pts(vv)
//   PTLoad(dv, sv, f)  ∀s ∈ pts(sv): pts(dv) ⊇ fstore(s,f)

///|
pub(all) enum PTConstraint {
  PTAlloc(String, String) // var, site
  PTCopy(String, String) // to, from (Subset)
  PTStore(String, String, String) // siteVar, field, valueVar
  PTLoad(String, String, String) // dstVar, siteVar, field
} derive(Debug)

///|
pub(all) struct PTSolution {
  pts : Map[String, Map[String, Bool]] // node -> site set
  fstore : Map[String, Map[String, Bool]] // "site|field" -> site set
  iterations : Int // applied constraint evaluations
  converged : Bool // false = budget exhausted (caller must disclose)
}

///|
pub fn PTSolution::pts_of(self : PTSolution, node : String) -> Array[String] {
  match self.pts.get(node) {
    Some(set) => {
      let out : Array[String] = []
      set.each(fn(k, _) { out.push(k) })
      out
    }
    None => []
  }
}

///|
pub fn PTSolution::fstore_of(
  self : PTSolution,
  site : String,
  field : String,
) -> Array[String] {
  match self.fstore.get(site + "|" + field) {
    Some(set) => {
      let out : Array[String] = []
      set.each(fn(k, _) { out.push(k) })
      out
    }
    None => []
  }
}

///|
pub fn PTSolution::contains(
  self : PTSolution,
  node : String,
  site : String,
) -> Bool {
  match self.pts.get(node) {
    Some(set) => set.contains(site)
    None => false
  }
}

// ── worklist solver ──────────────────────────────────────────────────────

///|
fn set_add(set : Map[String, Bool], site : String) -> Bool {
  // returns true if the set grew (drives the worklist)
  if set.contains(site) {
    false
  } else {
    set[site] = true
    true
  }
}

///|
fn set_union_into(dst : Map[String, Bool], src : Map[String, Bool]) -> Bool {
  let mut grew = false
  src.each(fn(k, _) { if set_add(dst, k) { grew = true } })
  grew
}

///|
fn ensure_set(
  table : Map[String, Map[String, Bool]],
  key : String,
) -> Map[String, Bool] {
  match table.get(key) {
    Some(s) => s
    None => {
      let s : Map[String, Bool] = Map([])
      table[key] = s
      s
    }
  }
}

///|
pub fn solve_pt_constraints(
  constraints : Array[PTConstraint],
  budget? : Int,
) -> PTSolution {
  let max_evals = match budget {
    Some(n) => n
    None => 10000
  }
  let sol : PTSolution = {
    pts: Map([]),
    fstore: Map([]),
    iterations: 0,
    converged: false,
  }
  // constraint index: node -> constraints that READ its points-to set
  let readers : Map[String, Array[Int]] = Map([])
  // D2a: field -> PTLoad constraint indices — fstore growth on a field
  // must re-run the loads of that field (gate14 P1 fix)
  let field_loads : Map[String, Array[Int]] = Map([])
  let allocs : Array[Int] = []
  for i, c in constraints {
    match c {
      PTAlloc(_, _) => allocs.push(i)
      PTCopy(to, from) => {
        let _ = to // 'to' is written, not read
        let arr = ensure_arr(readers, from)
        arr.push(i)
      }
      PTStore(sv, _, vv) => {
        // D2a: the store reads BOTH its base var (which sites) and its
        // value var (what to write) — register under both
        let arr = ensure_arr(readers, sv)
        arr.push(i)
        let varr = ensure_arr(readers, vv)
        varr.push(i)
      }
      PTLoad(_, sv, field) => {
        let arr = ensure_arr(readers, sv)
        arr.push(i)
        let larr = ensure_arr(field_loads, field)
        larr.push(i)
      }
    }
  }
  // seed allocations, mark their vars dirty
  let dirty : Array[String] = []
  for i in allocs {
    match constraints[i] {
      PTAlloc(v, s) => {
        let set = ensure_set(sol.pts, v)
        let _ = set_add(set, s)
        if !dirty.contains(v) {
          dirty.push(v)
        }
      }
      _ => ()
    }
  }
  // worklist: while a node's set grew, re-evaluate constraints reading it
  let mut evals = 0
  let mut exhausted = false
  while dirty.length() > 0 {
    if evals >= max_evals {
      exhausted = true
      break
    }
    let node = match dirty.pop() {
      Some(n) => n
      None => continue
    }
    let cs = match readers.get(node) {
      Some(arr) => arr
      None => continue
    }
    for ci in cs {
      evals += 1
      match constraints[ci] {
        PTCopy(to, from) => {
          let fset = ensure_set(sol.pts, from)
          let tset = ensure_set(sol.pts, to)
          if set_union_into(tset, fset) && !dirty.contains(to) {
            dirty.push(to)
          }
        }
        PTStore(sv, field, vv) => {
          // ∀s ∈ pts(sv): fstore(s,field) ⊇ pts(vv)
          let sites = ensure_set(sol.pts, sv)
          let vals = ensure_set(sol.pts, vv)
          let mut grew = false
          sites.each(fn(s, _) {
            let key = s + "|" + field
            let bucket = ensure_set(sol.fstore, key)
            if set_union_into(bucket, vals) {
              grew = true
            }
          })
          if grew {
            // D2a: fstore growth must wake every PTLoad on this field —
            // re-run them by marking their base vars dirty
            match field_loads.get(field) {
              Some(load_idxs) =>
                for li in load_idxs {
                  match constraints[li] {
                    PTLoad(_, lsv, _) =>
                      if !dirty.contains(lsv) {
                        dirty.push(lsv)
                      }
                    _ => ()
                  }
                }
              None => ()
            }
            // the store itself re-runs if vv's set grows further
            if !dirty.contains(vv) {
              dirty.push(vv)
            }
          }
        }
        PTLoad(dv, sv, field) => {
          // ∀s ∈ pts(sv): pts(dv) ⊇ fstore(s,field)
          let sites = ensure_set(sol.pts, sv)
          let dset = ensure_set(sol.pts, dv)
          let mut grew = false
          sites.each(fn(s, _) {
            let key = s + "|" + field
            let bucket = match sol.fstore.get(key) {
              Some(b) => b
              None => {
                let b : Map[String, Bool] = Map([])
                sol.fstore[key] = b
                b
              }
            }
            if set_union_into(dset, bucket) {
              grew = true
            }
          })
          if grew && !dirty.contains(dv) {
            dirty.push(dv)
          }
        }
        _ => ()
      }
    }
  }
  { ..sol, iterations: evals, converged: !exhausted, }
}

///|
fn ensure_arr(table : Map[String, Array[Int]], key : String) -> Array[Int] {
  match table.get(key) {
    Some(a) => a
    None => {
      let a : Array[Int] = []
      table[key] = a
      a
    }
  }
}

// ── generator: HIR statement traces → constraints (pure) ────────────────

///|
pub fn constraints_from_trace(
  trace : Array[Stmt],
  out : Array[PTConstraint],
) -> Unit {
  for stmt in trace {
    constraints_from_stmt(stmt, out)
  }
}

///|
fn constraints_from_stmt(stmt : Stmt, out : Array[PTConstraint]) -> Unit {
  match stmt {
    LetEvalTemp(_, _) => () // temp node exists implicitly
    BindVar(decl, RTemp(t)) => out.push(PTCopy(decl, "t" + t.to_string()))
    BindVar(_, RWhole) => ()
    BindTuplePositions(decl, temps) => {
      let mut i = 0
      for t in temps {
        out.push(PTCopy(decl + "|#tuple|" + i.to_string(), "t" + t.to_string()))
        i += 1
      }
    }
    BindCtorPositions(decl, ctor, temps) => {
      let mut i = 0
      for t in temps {
        out.push(
          PTCopy(decl + "|" + ctor + "|" + i.to_string(), "t" + t.to_string()),
        )
        i += 1
      }
    }
    CallStmt(target, temps) => {
      // ParamToParam (Subset variant): fn@target.param<i> ⊇ t<temps[i]>
      let mut i = 0
      for t in temps {
        out.push(
          PTCopy("fn@" + target + ".param" + i.to_string(), "t" + t.to_string()),
        )
        i += 1
      }
    }
    AssignStmt(decl, t) => out.push(PTCopy(decl, "t" + t.to_string()))
    // D1a control statements: no constraints at this slice (value
    // temps flow through existing PTCopy on their binding sites)
    RetStmt(_) | BreakStmt(_) | ContinueStmt | RaiseStmt(_) | DeferReg(_) => ()
    SinkStmt(_, _, _) => () // sinks carry no points-to facts
  }
}

// D1c: CFG consumption — same per-stmt emission over BlockIr blocks.
// Constraint sets are order-insensitive, so trace and cfg paths must
// produce IDENTICAL constraint sets for the same function (unit-locked).

///|
pub fn constraints_from_cfg(ir : BlockIr, out : Array[PTConstraint]) -> Unit {
  for block in ir.blocks {
    for stmt in block.stmts {
      constraints_from_stmt(stmt, out)
    }
  }
}

///|
pub fn pt_node_show(node : String) -> String {
  // decl keys carry "|#tuple|"/"|ctor|" position segments — keep readable
  node
}
