// T2.1+T2.3 thin: explicit statement-layer HIR skeleton.
// The taint engine's Apply/DotApply/Let paths lower through these
// statements; execution is hybrid — statements materialize temporaries
// (every argument evaluated EXACTLY ONCE by construction) and the flow
// walk re-injects them into the environment. ctx.hir_trace records the
// produced sequence so future milestones (T2.2 CFG, T3.3 worklist) can
// execute this IR directly instead of re-walking the AST.
// Design reference: docs/ir/ROADMAP-T.md T2.1 (eval order) and T2.3
// (structured value positions).

///|
pub(all) enum RhsKind {
  RTemp(Int) // temporary id
  RWhole // whole-expression taint (no temp materialized)
}

///|
pub(all) enum Stmt {
  LetEvalTemp(Int, Int) // temp id, arg index — evaluated ONCE
  BindVar(String, RhsKind) // decl key, rhs
  BindTuplePositions(String, Array[Int]) // decl key, temp ids
  BindCtorPositions(String, String, Array[Int]) // decl, ctor, temp ids
  CallStmt(String, Array[Int]) // target, arg temps (receiver first)
  SinkStmt(String, Array[Int]) // kind, temps
  AssignStmt(String, Int) // decl key, temp
}

///|
pub(all) enum ValuePos {
  PTuple(String, Int)
  PCtor(String, String, Int)
}

///|
pub fn ValuePos::key(self : ValuePos) -> String {
  match self {
    PTuple(decl, idx) => decl + "|#tuple|" + idx.to_string()
    PCtor(decl, ctor, idx) => decl + "|" + ctor + "|" + idx.to_string()
  }
}

///|
pub fn RhsKind::show(self : RhsKind) -> String {
  match self {
    RTemp(id) => "t" + id.to_string()
    RWhole => "whole"
  }
}

///|
pub fn Stmt::show(self : Stmt) -> String {
  match self {
    LetEvalTemp(temp_id, arg_idx) =>
      "t" + temp_id.to_string() + " := eval arg[" + arg_idx.to_string() + "]"
    BindVar(decl, rhs) => decl + " := " + rhs.show()
    BindTuplePositions(decl, temps) => {
      let parts : Array[String] = []
      let mut i = 0
      for t in temps {
        parts.push("(" + decl + ", " + i.to_string() + ")=t" + t.to_string())
        i += 1
      }
      "bind tuple positions " + parts.join(", ")
    }
    BindCtorPositions(decl, ctor, temps) => {
      let parts : Array[String] = []
      let mut i = 0
      for t in temps {
        parts.push(
          "(" +
          decl +
          ", " +
          ctor +
          ", " +
          i.to_string() +
          ")=t" +
          t.to_string(),
        )
        i += 1
      }
      "bind ctor positions " + parts.join(", ")
    }
    CallStmt(target, temps) => {
      let parts : Array[String] = []
      for t in temps {
        parts.push("t" + t.to_string())
      }
      target + "(" + parts.join(", ") + ")"
    }
    SinkStmt(kind, temps) => {
      let parts : Array[String] = []
      for t in temps {
        parts.push("t" + t.to_string())
      }
      "SINK " + kind + "(" + parts.join(", ") + ")"
    }
    AssignStmt(decl, temp_id) => decl + " <- t" + temp_id.to_string()
  }
}

///|
pub fn hir_trace_show(trace : Array[Stmt]) -> String {
  let lines : Array[String] = []
  for s in trace {
    lines.push(s.show())
  }
  lines.join("; ")
}

// ── position addressing (T2.3) ────────────────────────────────────────────
// struct_comps: decl key -> ctor name -> payload/component taints.
// "#tuple" is the tuple pseudo-constructor. Projections address components
// by (decl, ctor, idx) — replacing the old string-name-keyed tuple_comps.

///|
fn comps_set(
  ctx : FlowCtx,
  decl : String,
  ctor : String,
  comps : Array[Taint],
) -> Unit {
  match ctx.struct_comps.get(decl) {
    Some(m) => m[ctor] = comps
    None => {
      let m : Map[String, Array[Taint]] = Map([])
      m[ctor] = comps
      ctx.struct_comps[decl] = m
    }
  }
}

///|
fn comps_get(ctx : FlowCtx, decl : String, ctor : String, idx : Int) -> Taint? {
  match ctx.struct_comps.get(decl) {
    Some(m) =>
      match m.get(ctor) {
        Some(arr) =>
          if idx >= 0 && idx < arr.length() {
            Some(arr[idx])
          } else {
            None
          }
        None => None
      }
    None => None
  }
}

// fresh temp id (shared counter box: unique across branch copies)

///|
fn hir_fresh_temp(ctx : FlowCtx) -> Int {
  ctx.hir_temp_ctr[0] += 1
  ctx.hir_temp_ctr[0]
}
