// D1a: BlockIr CFG builder unit tests (pure data layer, unwired).

///|
fn build_src(src : String, name : String) -> BlockIr {
  let (impls, _) = @parser.parse_string(src, name="t.mbt")
  for item in impls {
    match item {
      TopFuncDef(decl_body~, ..) =>
        match decl_body {
          DeclBody(expr=body) => {
            let ir = build_block_ir(name, body)
            return ir
          }
          _ => ()
        }
      _ => ()
    }
  }
  abort("no TopFuncDef with body in snippet")
}

///|
test "d1a_straight_line_single_block" {
  let ir = build_src(
    "pub fn f(r : R, v : String) -> Unit { r.set_header(\"X\", v) }", "f",
  )
  // entry block holds the call: one arg temp + CallStmt
  let entry = ir.blocks[ir.entry]
  inspect(entry.succs.length(), content="1")
  inspect(entry.succs[0], content="1")
  let mut call_count = 0
  let mut eval_count = 0
  for s in entry.stmts {
    match s {
      CallStmt(_, _) => call_count += 1
      LetEvalTemp(_, _) => eval_count += 1
      _ => ()
    }
  }
  inspect(call_count, content="1")
  inspect(eval_count, content="2") // two args ("X", v), receiver opaque
  // exits empty, validate clean
  inspect(validate_cfg(ir).length(), content="0")
}

///|
test "d1a_if_fork_join" {
  let ir = build_src(
    "pub fn f(c : Bool, a : R) -> Unit { if c { a.x() } else { a.y() } }", "f",
  )
  // condition block has two successors (then, else)
  let entry = ir.blocks[ir.entry]
  inspect(entry.succs.length(), content="2")
  // both branch blocks reach the join block (shared successor)
  let s0 = ir.blocks[entry.succs[0]].succs
  let s1 = ir.blocks[entry.succs[1]].succs
  let joined = s0.length() > 0 &&
    s1.length() > 0 &&
    s0[s0.length() - 1] == s1[s1.length() - 1]
  inspect(joined, content="true")
  inspect(validate_cfg(ir).length(), content="0")
}

///|
test "d1a_while_back_edge" {
  let ir = build_src(
    "pub fn f(n : Int, a : R) -> Unit { while n > 0 { a.tick() } }", "f",
  )
  // find the loop header: a block whose successors include a block that
  // eventually links back to it
  let mut header = -1
  let mut body = -1
  for b in ir.blocks {
    // a loop HEADER has >=2 successors (body + after); only then accept
    // the pair (b, s) where s links back to b — avoids the reverse
    // (body, header) false pair from mutual adjacency
    if b.succs.length() < 2 {
      continue
    }
    for s in b.succs {
      if ir.blocks[s].succs.contains(b.id) &&
        b.id != ir.normal_exit &&
        b.id != ir.error_exit {
        header = b.id
        body = s
      }
    }
  }
  inspect(header >= 0, content="true")
  // header branches to body AND after; body links back to header
  let hsuccs = ir.blocks[header].succs
  inspect(hsuccs.length() >= 2, content="true")
  inspect(ir.blocks[body].succs.contains(header), content="true")
  inspect(validate_cfg(ir).length(), content="0")
}

///|
test "d1a_try_three_exits" {
  let ir = build_src(
    "pub fn f(a : R) -> Unit { try { a.x() } catch { e => ignore(e) } }", "f",
  )
  // body-end carries BOTH the error edge (catch head) and the normal
  // edge (join) — the D1a approximation of three-exit semantics
  let entry = ir.blocks[ir.entry]
  inspect(entry.succs.length(), content="1")
  let body_id = entry.succs[0]
  let bsuccs = ir.blocks[body_id].succs
  // D1a approximation: body-end carries BOTH edges — error (catch head,
  // first succ) and normal (join, last succ); both paths reach normal_exit
  inspect(bsuccs.length() >= 2, content="true")
  let catch_id = bsuccs[0]
  let join_id = bsuccs[bsuccs.length() - 1]
  // every path from body end reaches normal exit (validate + reachability
  // already prove it structurally); assert join is a shared successor of
  // the catch chain end
  let catch_succs = ir.blocks[catch_id].succs
  inspect(
    catch_succs.length() > 0 && catch_succs[catch_succs.length() - 1] == join_id,
    content="true",
  )
  inspect(validate_cfg(ir).length(), content="0")
}
