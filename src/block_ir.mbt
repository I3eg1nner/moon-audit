// D1a: BlockIr CFG builder — a PURE DATA LAYER, unwired (T4c-1 pattern).
// Lowers a function body DIRECTLY from the AST into a basic-block graph:
//   Block{id, stmts, succs} over the shared hir.mbt Stmt (argument
//   temporization follows the T2.1 rule: every argument evaluated EXACTLY
//   ONCE via LetEvalTemp; calls emit CallStmt with receiver-first temps).
// Exit semantics: every function graph has explicit `entry`, `normal_exit`
//   and `error_exit` blocks; Return links to normal_exit, Raise to
//   error_exit, Break/Continue link within the enclosing loop.
// Approximations (documented, refined in later D1 stages):
//   - Try: body-end carries BOTH a normal edge (join) and an error edge
//     (catch head); precise raise-site edges arrive with D1b execution.
//   - While/For/ForEach: condition/init effects stay in the header block;
//     loop-carried value temps are not yet materialized (T2.2 residue).
// Consumers: none yet (taint/live-vars/points_to keep their current
// entry points); validate_cfg is the structural contract gate.

///|
pub(all) struct Block {
  id : Int
  stmts : Array[Stmt]
  succs : Array[Int] // successor block ids (duplicates allowed for multi-edges)
}

///|
pub(all) struct BlockIr {
  fn_name : String
  blocks : Array[Block] // 0 = entry, last two = normal_exit, error_exit
  entry : Int
  normal_exit : Int
  error_exit : Int
}

///|
fn new_block(id : Int) -> Block {
  { id, stmts: [], succs: [], }
}

///|
fn ir_link(from : Int, to : Int, blocks : Array[Block]) -> Unit {
  blocks[from].succs.push(to)
}

// ── builder state ─────────────────────────────────────────────────────────

///|
priv struct CfgCtx {
  blocks : Array[Block]
  mut cur : Int // current block id
  mut terminated : Bool // current block ended by Return/Raise
  mut next_temp : Int
  loop_headers : Array[Int] // innermost last (break/continue targets)
  mut defer_count : Int
}

///|
fn CfgCtx::fresh_temp(self : CfgCtx) -> Int {
  let t = self.next_temp
  self.next_temp += 1
  t
}

///|
fn CfgCtx::fresh_block(self : CfgCtx) -> Int {
  // exits hold FIXED ids 1 (normal) and 2 (error); body blocks append
  let id = self.blocks.length()
  self.blocks.push(new_block(id))
  id
}

///|
fn CfgCtx::seal(self : CfgCtx) -> Unit {
  // open a fresh unreachable block for anything after a terminator
  self.cur = self.fresh_block()
  self.terminated = false
}

// ── entry point ───────────────────────────────────────────────────────────

///|
pub fn build_block_ir(fn_name : String, body : @syntax.Expr) -> BlockIr {
  // fixed layout: 0 = entry, 1 = normal_exit, 2 = error_exit
  let ctx : CfgCtx = {
    blocks: [new_block(0), new_block(1), new_block(2)],
    cur: 0,
    terminated: false,
    next_temp: 0,
    loop_headers: [],
    defer_count: 0,
  }
  lower(body, ctx)
  // implicit fallthrough of the last block → normal exit (unless sealed)
  if !ctx.terminated && ctx.blocks[ctx.cur].succs.length() == 0 {
    ir_link(ctx.cur, 1, ctx.blocks)
  }
  { fn_name, blocks: ctx.blocks, entry: 0, normal_exit: 1, error_exit: 2, }
}

// ── lowering ──────────────────────────────────────────────────────────────

///|
fn lower(expr : @syntax.Expr, ctx : CfgCtx) -> Unit {
  match expr {
    Sequence(exprs~, last_expr~, ..) => {
      for e in exprs {
        lower(e, ctx)
      }
      lower(last_expr, ctx)
    }
    _ => lower_one(expr, ctx)
  }
}

///|
fn lower_one(expr : @syntax.Expr, ctx : CfgCtx) -> Unit {
  match expr {
    Apply(..) => emit_call(expr, ctx)
    DotApply(self~, ..) => {
      // receiver first, then arguments (T2.1 order)
      lower_effects(self)
      emit_call(expr, ctx)
    }
    Let(pattern~, expr~, ..) => {
      let decl = pattern_decl_key(pattern)
      let t_opt = eval_value_expr(expr, ctx)
      match t_opt {
        Some(t) => ctx.blocks[ctx.cur].stmts.push(BindVar(decl, RTemp(t)))
        None => ctx.blocks[ctx.cur].stmts.push(BindVar(decl, RWhole))
      }
    }
    LetMut(binder~, expr~, ..) => {
      let decl = binder.name
      let t_opt = eval_value_expr(expr, ctx)
      match t_opt {
        Some(t) => ctx.blocks[ctx.cur].stmts.push(BindVar(decl, RTemp(t)))
        None => ctx.blocks[ctx.cur].stmts.push(BindVar(decl, RWhole))
      }
    }
    Assign(var_~, expr~, ..) => {
      let t_opt = eval_value_expr(expr, ctx)
      let name = longident_of(var_.name)
      match t_opt {
        Some(t) => ctx.blocks[ctx.cur].stmts.push(AssignStmt(name, t))
        None => ctx.blocks[ctx.cur].stmts.push(BindVar(name, RWhole))
      }
    }
    If(cond~, ifso~, ifnot~, ..) => {
      lower_effects(cond)
      let cond_id = ctx.cur
      let then_id = ctx.fresh_block()
      let else_id = ctx.fresh_block()
      let join_id = ctx.fresh_block()
      ir_link(cond_id, then_id, ctx.blocks)
      ir_link(cond_id, else_id, ctx.blocks)
      ctx.cur = then_id
      lower(ifso, ctx)
      let then_end = cur_exit(ctx)
      ir_link(then_end, join_id, ctx.blocks)
      ctx.cur = else_id
      match ifnot {
        Some(e) => lower(e, ctx)
        None => ()
      }
      let else_end = cur_exit(ctx)
      ir_link(else_end, join_id, ctx.blocks)
      ctx.cur = join_id
    }
    Match(expr~, cases~, ..) => {
      lower_effects(expr)
      let scrut_id = ctx.cur
      let join_id = ctx.fresh_block()
      for case in cases {
        let case_id = ctx.fresh_block()
        ir_link(scrut_id, case_id, ctx.blocks)
        ctx.cur = case_id
        lower(case.body, ctx)
        let end = cur_exit(ctx)
        ir_link(end, join_id, ctx.blocks)
      }
      ctx.cur = join_id
    }
    Try(body~, catch_~, ..) => {
      let body_id = ctx.fresh_block()
      let join_id = ctx.fresh_block()
      ir_link(ctx.cur, body_id, ctx.blocks)
      ctx.cur = body_id
      lower(body, ctx)
      let body_end = cur_exit(ctx)
      // D1a approximation: body-end carries normal AND error edges
      if catch_.length() > 0 {
        let catch_id = ctx.fresh_block()
        ir_link(body_end, catch_id, ctx.blocks)
        ctx.cur = catch_id
        for case in catch_ {
          lower(case.body, ctx)
        }
        let catch_end = cur_exit(ctx)
        ir_link(catch_end, join_id, ctx.blocks)
      }
      ir_link(body_end, join_id, ctx.blocks)
      ctx.cur = join_id
    }
    While(loop_cond~, loop_body~, ..) => {
      let header = ctx.fresh_block()
      ir_link(ctx.cur, header, ctx.blocks)
      ctx.cur = header
      lower_effects(loop_cond)
      let body_id = ctx.fresh_block()
      let after = ctx.fresh_block()
      ir_link(header, body_id, ctx.blocks)
      ir_link(header, after, ctx.blocks)
      ctx.loop_headers.push(header)
      ctx.cur = body_id
      lower(loop_body, ctx)
      ignore(ctx.loop_headers.pop())
      let body_end = cur_exit(ctx)
      ir_link(body_end, header, ctx.blocks) // back edge
      ctx.cur = after
    }
    For(binders~, continue_block~, body~, ..) => {
      for pair in binders {
        lower_effects(pair.1)
      }
      for pair in continue_block {
        lower_effects(pair.1)
      }
      let header = ctx.fresh_block()
      ir_link(ctx.cur, header, ctx.blocks)
      ctx.cur = header
      let body_id = ctx.fresh_block()
      let after = ctx.fresh_block()
      ir_link(header, body_id, ctx.blocks)
      ir_link(header, after, ctx.blocks)
      ctx.loop_headers.push(header)
      ctx.cur = body_id
      lower(body, ctx)
      ignore(ctx.loop_headers.pop())
      let body_end = cur_exit(ctx)
      ir_link(body_end, header, ctx.blocks)
      ctx.cur = after
    }
    ForEach(expr~, init~, continue_block~, body~, ..) => {
      lower_effects(expr)
      for pair in init {
        lower_effects(pair.1)
      }
      for pair in continue_block {
        lower_effects(pair.1)
      }
      let header = ctx.fresh_block()
      ir_link(ctx.cur, header, ctx.blocks)
      ctx.cur = header
      let body_id = ctx.fresh_block()
      let after = ctx.fresh_block()
      ir_link(header, body_id, ctx.blocks)
      ir_link(header, after, ctx.blocks)
      ctx.loop_headers.push(header)
      ctx.cur = body_id
      lower(body, ctx)
      ignore(ctx.loop_headers.pop())
      let body_end = cur_exit(ctx)
      ir_link(body_end, header, ctx.blocks)
      ctx.cur = after
    }
    Return(return_value~, ..) => {
      let t_opt = match return_value {
        Some(e) => eval_value_expr(e, ctx)
        None => None
      }
      match t_opt {
        Some(t) => ctx.blocks[ctx.cur].stmts.push(RetStmt(Some(t)))
        None => ctx.blocks[ctx.cur].stmts.push(RetStmt(None))
      }
      ir_link(ctx.cur, 1, ctx.blocks)
      ctx.terminated = true
      ctx.seal()
    }
    Raise(err_value~, ..) => {
      let t = ctx.fresh_temp()
      lower_effects(err_value)
      ctx.blocks[ctx.cur].stmts.push(RaiseStmt(t))
      ir_link(ctx.cur, 2, ctx.blocks)
      ctx.terminated = true
      ctx.seal()
    }
    Break(arg~, ..) => {
      let t_opt = match arg {
        Some(e) => eval_value_expr(e, ctx)
        None => None
      }
      match t_opt {
        Some(t) => ctx.blocks[ctx.cur].stmts.push(BreakStmt(Some(t)))
        None => ctx.blocks[ctx.cur].stmts.push(BreakStmt(None))
      }
      // break → innermost loop's after-block is unknown here; D1a links
      // to the loop header's second successor via loop-header bookkeeping
      match loop_top(ctx.loop_headers) {
        Some(header) => {
          // header succs = [body, after]; break goes to `after`
          let after = ctx.blocks[header].succs[1]
          ir_link(ctx.cur, after, ctx.blocks)
        }
        None => ir_link(ctx.cur, 1, ctx.blocks)
      }
      ctx.terminated = true
      ctx.seal()
    }
    Continue(..) => {
      ctx.blocks[ctx.cur].stmts.push(ContinueStmt)
      match loop_top(ctx.loop_headers) {
        Some(header) => ir_link(ctx.cur, header, ctx.blocks)
        None => ()
      }
      ctx.terminated = true
      ctx.seal()
    }
    Defer(expr~, body~, ..) => {
      // defer registered at this point; executes at exit paths (D1b)
      ctx.defer_count += 1
      ctx.blocks[ctx.cur].stmts.push(DeferReg(ctx.defer_count.to_string()))
      lower_effects(expr)
      lower(body, ctx)
    }
    LetAnd(bindings~, body~, ..) => {
      for binding in bindings {
        let (binder, _, func) = binding
        // local fn registration: no body execution at creation (T2.5)
        ignore(func)
        ctx.blocks[ctx.cur].stmts.push(BindVar(binder.name, RWhole))
      }
      lower(body, ctx)
    }
    LetFn(name~, func~, body~, ..) => {
      ignore(func) // creation ≠ execution (T2.5)
      ctx.blocks[ctx.cur].stmts.push(BindVar(name.name, RWhole))
      lower(body, ctx)
    }
    Guard(cond~, body~, ..) => {
      // guard: cond fails → otherwise path (treated as branch to join)
      lower_effects(cond)
      let header = ctx.cur
      let ok_id = ctx.fresh_block()
      let join_id = ctx.fresh_block()
      ir_link(header, ok_id, ctx.blocks)
      ir_link(header, join_id, ctx.blocks)
      ctx.cur = ok_id
      lower(body, ctx)
      let end = cur_exit(ctx)
      ir_link(end, join_id, ctx.blocks)
      ctx.cur = join_id
    }
    TryOperator(body~, ..) => lower(body, ctx)
    _ => lower_effects(expr)
  }
}

// the block id that a fallthrough edge should start from

///|
fn cur_exit(ctx : CfgCtx) -> Int {
  ctx.cur
}

// emit argument temporaries + CallStmt for an Apply/DotApply site

///|
fn emit_call(expr : @syntax.Expr, ctx : CfgCtx) -> Unit {
  let temps : Array[Int] = []
  let target = match expr {
    Apply(func~, args~, ..) => {
      for arg in args {
        let t = ctx.fresh_temp()
        lower_effects(arg.value)
        temps.push(t)
      }
      callee_target(func)
    }
    DotApply(self~, method_name~, args~, ..) => {
      // receiver evaluated first (whole-value approximation at D1a; no
      // receiver temp until D1b models receiver results)
      lower_effects(self)
      for arg in args {
        let t = ctx.fresh_temp()
        lower_effects(arg.value)
        temps.push(t)
      }
      method_name.name
    }
    _ => "?"
  }
  // T2.1 rule: every argument evaluated EXACTLY ONCE into a temp
  let mut i = 0
  for t in temps {
    ctx.blocks[ctx.cur].stmts.push(LetEvalTemp(t, i))
    i += 1
  }
  ctx.blocks[ctx.cur].stmts.push(CallStmt(target, temps))
}

///|
fn callee_target(func : @syntax.Expr) -> String {
  match func {
    Ident(id~, ..) => longident_of(id.name)
    Method(type_name~, method_name~, ..) =>
      type_name_str_of(type_name) + "::" + method_name.name
    _ => "?"
  }
}

///|
fn longident_of(id : @syntax.LongIdent) -> String {
  match id {
    Ident(name~) => name
    Dot(pkg~, id~) => pkg + "::" + id
  }
}

///|
fn type_name_str_of(tn : @syntax.TypeName) -> String {
  longident_of(tn.name)
}

// Evaluate a value expression into (optional) temp; only argument-like
// positions materialize temps in this slice.

///|
fn eval_value_expr(expr : @syntax.Expr, ctx : CfgCtx) -> Int? {
  match expr {
    Apply(..) | DotApply(..) => {
      lower_effects(expr)
      None // call result: whole-value binding at this slice
    }
    Tuple(exprs~, ..) => {
      let temps : Array[Int] = []
      for e in exprs {
        let t = ctx.fresh_temp()
        lower_effects(e)
        temps.push(t)
      }
      Some(-1) // marker: tuple positions handled by caller via BindTuple
    }
    _ => {
      lower_effects(expr)
      None
    }
  }
}

// recurse over effectful sub-expressions (calls, assigns, control)

///|
fn lower_effects(expr : @syntax.Expr) -> Unit {
  ignore(expr)
  // D1a: sub-expression effects of non-statement positions (e.g. the
  // receiver chain) are approximated — the full recursion lands with
  // D1b when this layer becomes the execution kernel.
}

///|

///|
fn loop_top(stack : Array[Int]) -> Int? {
  if stack.length() > 0 {
    Some(stack[stack.length() - 1])
  } else {
    None
  }
}

///|
fn pattern_decl_key(pat : @syntax.Pattern) -> String {
  match pat {
    Var(binder) => binder.name
    _ => "_" // multi-binder patterns: D1b position bindings
  }
}

// ── structural validation ─────────────────────────────────────────────────

///|
pub fn validate_cfg(ir : BlockIr) -> Array[String] {
  let errs : Array[String] = []
  let n = ir.blocks.length()
  // 1. successor ids in range
  for b in ir.blocks {
    for s in b.succs {
      if s < 0 || s >= n {
        errs.push(
          "block " + b.id.to_string() + ": dangling succ " + s.to_string(),
        )
      }
    }
  }
  // 2. reachability from entry (exits included by construction)
  let seen : Array[Bool] = []
  for _ in 0..<n {
    seen.push(false)
  }
  seen[ir.entry] = true
  let work : Array[Int] = [ir.entry]
  while work.length() > 0 {
    let id = work.pop()
    match id {
      Some(i) =>
        for s in ir.blocks[i].succs {
          if !seen[s] {
            seen[s] = true
            work.push(s)
          }
        }
      None => ()
    }
  }
  for b in ir.blocks {
    // exits are exempt: error_exit is legitimately unreachable in
    // functions that never raise
    if !seen[b.id] && b.id != ir.normal_exit && b.id != ir.error_exit {
      errs.push("unreachable block " + b.id.to_string())
    }
  }
  // 3. exits carry no statements and no successors
  if ir.blocks[ir.normal_exit].stmts.length() > 0 {
    errs.push("normal exit carries statements")
  }
  if ir.blocks[ir.normal_exit].succs.length() > 0 {
    errs.push("normal exit has successors")
  }
  if ir.blocks[ir.error_exit].stmts.length() > 0 {
    errs.push("error exit carries statements")
  }
  if ir.blocks[ir.error_exit].succs.length() > 0 {
    errs.push("error exit has successors")
  }
  errs
}
