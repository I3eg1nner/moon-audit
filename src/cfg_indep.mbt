// Section 4: Independent CFG executor — produces findings from BlockIr alone.
// Does NOT read temp_facts or any AST-walk-produced taint state.
// Supports: constants, var bind/assign, call (arg-taint + ret_from
// refinement via ictx summaries), branch fork/join, loops (iterate to
// fixpoint), return. SinkStmt triggers CWE-113 findings directly.

///|
pub fn exec_independent(
  ir : BlockIr,
  params : Array[(String, Taint)], // (param name, entry taint)
  rules : TaintRuleset,
  ictx : InterProceduralContext?,
) -> Array[Finding] {
  // independent env: param name -> taint (seeded from signature)
  let env : Map[String, Taint] = Map([])
  for pair in params {
    env[pair.0] = pair.1
  }
  // independent temp taints: computed from stmts, NOT from ir.temp_taints
  let temps : Map[Int, Taint] = Map([])
  let findings : Array[Finding] = []
  // entry fact for the walk: all params as source candidates
  // (simplified: taint = what the entry says, no AST dependency)

  // worklist-based block traversal with state merge
  // simplified for minimum viable: process blocks in order, join at
  // multi-predecessor points, loop headers iterate up to budget
  let block_envs : Map[Int, Map[String, Taint]] = Map([])

  // seed entry
  let entry_env : Map[String, Taint] = Map([])
  env.each(fn(k, v) { entry_env[k] = v })
  block_envs[ir.entry] = entry_env

  // iterate to fixpoint (simplified: bounded passes)
  let mut changed = true
  let mut passes = 0
  let max_passes = 8
  while changed && passes < max_passes {
    changed = false
    passes += 1
    // process each block in order
    for block in ir.blocks {
      // merge incoming envs
      let merged : Map[String, Taint] = Map([])
      let mut has_pred = false
      // find predecessors by scanning all blocks' succs
      for pred in ir.blocks {
        for s in pred.succs {
          if s == block.id {
            has_pred = true
            match block_envs.get(pred.id) {
              Some(pe) =>
                pe.each(fn(k, v) {
                  match merged.get(k) {
                    Some(existing) => merged[k] = taint_union_indep(existing, v)
                    None => merged[k] = v
                  }
                })
              None => ()
            }
          }
        }
      }
      // entry block: use its seeded env
      if block.id == ir.entry {
        entry_env.each(fn(k, v) { merged[k] = v })
      }
      if !has_pred && block.id != ir.entry {
        continue // unreachable
      }
      // execute stmts in this block
      let cur_env : Map[String, Taint] = Map([])
      merged.each(fn(k, v) { cur_env[k] = v })
      // check if env changed from previous pass
      let prev : Map[String, Taint]? = block_envs.get(block.id)
      match prev {
        Some(p) =>
          p.each(fn(k, v) {
            let cur = cur_env.get(k)
            match cur {
              Some(c) => if !taint_eq_indep(c, v) { changed = true }
              None => changed = true
            }
          })
        None => changed = true
      }
      cur_env.each(fn(k, v) {
        match prev {
          Some(p) =>
            match p.get(k) {
              Some(pv) => if !taint_eq_indep(v, pv) { changed = true }
              None => changed = true
            }
          None => ()
        }
      })
      block_envs[block.id] = cur_env
      // process statements
      for stmt in block.stmts {
        exec_stmt_indep(stmt, cur_env, temps, rules, ictx, findings, ir)
      }
    }
  }
  findings
}

///|
fn taint_union_indep(a : Taint, b : Taint) -> Taint {
  if a == b {
    return a
  }
  match (a, b) {
    (Clean, t) => t
    (t, Clean) => t
    _ => Tainted
  }
}

///|
fn taint_eq_indep(a : Taint, b : Taint) -> Bool {
  a == b
}

///|
fn exec_stmt_indep(
  stmt : Stmt,
  env : Map[String, Taint],
  temps : Map[Int, Taint],
  rules : TaintRuleset,
  ictx : InterProceduralContext?,
  findings : Array[Finding],
  ir : BlockIr,
) -> Unit {
  match stmt {
    LetEvalTemp(temp_id, _arg_idx) =>
      // evaluate the referenced expression from expr_refs
      match ir.expr_refs.get(temp_id) {
        Some(expr) => {
          let t = eval_expr_indep(expr, env, rules, ictx)
          temps[temp_id] = t
        }
        None => temps[temp_id] = Tainted // conservative
      }
    BindVar(name, RTemp(tid)) => env[name] = or_tainted_indep(temps.get(tid))
    BindVar(name, RWhole) => env[name] = Tainted
    BindTuplePositions(name, tids) => {
      // conservative: any tainted component → whole tuple tainted
      let mut any = false
      for tid in tids {
        match temps.get(tid) {
          Some(Tainted) | Some(TaintedParam(_)) | Some(TaintedFieldRef(_, _)) =>
            any = true
          _ => ()
        }
      }
      env[name] = if any { Tainted } else { Clean }
    }
    BindCtorPositions(name, _, tids) => {
      let mut any = false
      for tid in tids {
        match temps.get(tid) {
          Some(Tainted) | Some(TaintedParam(_)) | Some(TaintedFieldRef(_, _)) =>
            any = true
          _ => ()
        }
      }
      env[name] = if any { Tainted } else { Clean }
    }
    CallStmt(target, arg_tids) => {
      // evaluate args if not yet evaluated
      for tid in arg_tids {
        if !temps.contains(tid) {
          match ir.expr_refs.get(tid) {
            Some(expr) => temps[tid] = eval_expr_indep(expr, env, rules, ictx)
            None => temps[tid] = Tainted
          }
        }
      }
      // source hit → result tainted
      if rules.source_hit(target) {
        for tid in arg_tids {
          temps[tid] = Tainted
        }
      }
      // sink hit → check value arg taint
      if rules.header_sink_hit(target) {
        let slot = rules.sink_value_slot(target)
        let value_idx = match slot {
          Some(i) => i + 1 // receiver is arg 0, value is arg (slot+1)
          None => 1 // default: second positional arg
        }
        if value_idx < arg_tids.length() {
          let vt = or_tainted_indep(temps.get(arg_tids[value_idx]))
          if vt != Clean {
            findings.push(
              make_indep_finding("CWE-113/crlf-injection", vt, ir.fn_name),
            )
          }
        }
      }
      // ret_from refinement: if ictx has a summary for target, use it
      match ictx {
        Some(ctx) =>
          match ctx.summaries.get(target) {
            Some(summary) => {
              // conservative: if any param is in ret_from and tainted,
              // result is tainted
              let mut tainted_ret = false
              for pn in summary.ret_from {
                match env.get(pn) {
                  Some(Tainted) | Some(TaintedParam(_)) => tainted_ret = true
                  _ => ()
                }
                // also check if any arg temp matches this param
                for tid in arg_tids {
                  match temps.get(tid) {
                    Some(Tainted) => if pn == target { tainted_ret = true }
                    Some(TaintedParam(p)) =>
                      if p == pn || pn == target {
                        tainted_ret = true
                      }
                    _ => ()
                  }
                }
              }
              // store result: taint the first temp after args (if any)
              // For simplicity: if tainted_ret, mark a virtual result
              if tainted_ret {
                // mark the call result in env under a virtual key
                env["__ret__" + target] = Tainted
              } else {
                env["__ret__" + target] = Clean
              }
            }
            None => ()
          }
        None => ()
      }
    }
    SinkStmt(kind, arg_tids, line) =>
      // check all args: if any tainted → finding
      for tid in arg_tids {
        let t = or_tainted_indep(temps.get(tid))
        if t != Clean {
          findings.push(
            make_indep_finding(
              if kind == "output" {
                "CWE-116/tainted-output"
              } else {
                "CWE-113/crlf-injection"
              },
              t,
              ir.fn_name + ":" + line.to_string(),
            ),
          )
        }
      }
    AssignStmt(name, tid) => env[name] = or_tainted_indep(temps.get(tid))
    RetStmt(Some(_)) => ()
    RetStmt(None) => ()
    RaiseStmt(_) => ()
    BreakStmt(_) => ()
    ContinueStmt => ()
    DeferReg(_) => ()
  }
}

///|
fn or_tainted_indep(v : Taint?) -> Taint {
  match v {
    Some(t) => t
    None => Tainted
  }
}

///|
fn eval_expr_indep(
  expr : @syntax.Expr,
  env : Map[String, Taint],
  rules : TaintRuleset,
  ictx : InterProceduralContext?,
) -> Taint {
  match expr {
    Constant(..) => Clean
    Unit(..) => Clean
    Ident(id~, ..) => {
      let name = match id.name {
        Ident(name~) => name
        Dot(..) => return Clean
      }
      or_tainted_indep(env.get(name))
    }
    Method(..) => Clean
    Infix(lhs~, rhs~, ..) => {
      let lt = eval_expr_indep(lhs, env, rules, ictx)
      let rt = eval_expr_indep(rhs, env, rules, ictx)
      taint_union_indep(lt, rt)
    }
    Interp(..) => Tainted // interpolation: conservative
    BytesInterp(..) => Tainted
    _ => Clean // conservative for unsupported: Clean (simplified subset)
  }
}

///|
fn make_indep_finding(
  rule_id_str : String,
  _t : Taint,
  location : String,
) -> Finding {
  let slash = "/"
  let mut idx = -1
  let mut i = 0
  while i <= rule_id_str.length() - slash.length() {
    if rule_id_str[i:i + slash.length()] == slash {
      idx = i
    }
    i += 1
  }
  let cwe_str = if idx > 0 {
    Show::to_string(rule_id_str[:idx]).replace(old="CWE-", new="")
  } else {
    "0"
  }
  let cwe = parse_int_safe(cwe_str)
  let variant = if idx > 0 {
    Show::to_string(rule_id_str[idx + 1:])
  } else {
    "unknown"
  }
  {
    rule_id: { cwe, variant, },
    severity: Error,
    confidence: Medium,
    message: "Independent CFG executor: tainted value reached sink at " +
    location,
    file: "<independent>",
    line: 0,
    column: 0,
    end_line: 0,
    end_column: 0,
    snippet: "",
    fingerprint: "indep_" + rule_id_str + "_" + location,
  }
}

///|
fn parse_int_safe(s : String) -> Int {
  let mut result = 0
  for c in s {
    let d = c.to_int() - 48
    if d >= 0 && d <= 9 {
      result = result * 10 + d
    } else {
      return 0
    }
  }
  result
}
