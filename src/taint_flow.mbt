// M2: flow-sensitive intra-procedural taint engine.
// Structured CFG walk (branch fork/join) over the official AST — the
// "HIR-lite" layer. Replaces textual heuristics with dataflow facts:
//   - taint state per variable, ordered by control flow
//   - branch merge (union) for if/match/try
//   - guard/validation refinement: validated vars become clean in the
//     taken branch (the key precision upgrade over the old rule)

///|
priv enum Taint {
  Clean
  Tainted // tainted, origin unknown (env/param/callback)
  TaintedParam(String) // tainted, originated from this fn parameter
} derive(Eq)

///|
fn taint_or(a : Taint, b : Taint) -> Taint {
  match (a, b) {
    (Clean, b) => b
    (a, Clean) => a
    (TaintedParam(p), _) => TaintedParam(p)
    (_, TaintedParam(p)) => TaintedParam(p)
    _ => Tainted
  }
}

///|
fn is_tainted(t : Taint) -> Bool {
  t != Clean
}

///|
priv struct FlowCtx {
  env : Map[String, Taint]
  findings : Array[Finding]
  file : String
  source : String
  severity : Severity
  mut record_sinks : Array[String]? // M3 summary recording channel
}

///|
fn FlowCtx::copy(self : FlowCtx) -> FlowCtx {
  let env : Map[String, Taint] = Map([])
  self.env.each(fn(k, v) { env[k] = v })
  { ..self, env, }
}

// ── entry: analyze one top-level function ─────────────────────────────────

///|
pub fn run_flow_taint_func(
  params : @list.List[@syntax.Parameter]?,
  body : @syntax.Expr,
  file : String,
  source : String,
  severity : Severity,
  findings : Array[Finding],
) -> Unit {
  let ctx : FlowCtx = {
    env: Map([]),
    findings,
    file,
    source,
    severity,
    record_sinks: None,
  }
  // callback/closure parameters conservatively tainted (framework-supplied
  // input, e.g. middleware `fn(event, next)`)
  match params {
    Some(ps) =>
      for param in ps {
        match param {
          Positional(binder~, ..)
          | Labelled(binder~, ..)
          | Optional(binder~, ..)
          | QuestionOptional(binder~, ..) => ctx.env[binder.name] = Tainted
          DiscardPositional(..) => ()
        }
      }
    None => ()
  }
  let _ = flow(body, ctx)
}

///|
pub fn run_flow_taint_func_top(
  body : @syntax.Expr,
  file : String,
  source : String,
  severity : Severity,
  findings : Array[Finding],
) -> Unit {
  let ctx : FlowCtx = {
    env: Map([]),
    findings,
    file,
    source,
    severity,
    record_sinks: None,
  }
  let _ = flow(body, ctx)
}

// ── structured walk ───────────────────────────────────────────────────────

///|
fn flow(expr : @syntax.Expr, ctx : FlowCtx) -> Taint {
  match expr {
    Constant(..) | Unit(..) | Hole(..) => Clean
    MultilineString(elems~, ..) => {
      let mut t = Clean
      for elem in elems {
        match elem {
          Interp(list) =>
            for ie in list {
              match ie {
                Expr(expr~, ..) => t = taint_or(t, flow(expr, ctx))
                _ => ()
              }
            }
          _ => ()
        }
      }
      t
    }
    Interp(elems~, ..) => {
      let mut t = Clean
      for elem in elems {
        match elem {
          Expr(expr~, ..) => t = taint_or(t, flow(expr, ctx))
          // lexer-level holes (simple identifiers) are stored as raw
          // source: any interpolation hole is dynamic content
          Source(src) => {
            let s = src.source.trim()
            if s.length() > 0 {
              let c0 = s[0]
              let ua : UInt16 = 65
              let uz : UInt16 = 90
              if c0 >= ua && c0 <= uz {
                t = taint_or(t, Clean) // constant identifier (e.g. MaxAge)
              } else {
                t = taint_or(t, Tainted)
              }
            } else {
              t = taint_or(t, Tainted)
            }
          }
          _ => ()
        }
      }
      t
    }
    BytesInterp(..) => Clean
    Ident(id~, ..) => {
      let name = longident_str(id.name)
      or_clean(ctx.env.get(name))
    }
    Method(..) => Clean
    Apply(func~, args~, ..) => {
      let arg_taint = flow_args(args, ctx)
      let ret = match apply_func_name(func) {
        Some(name) => {
          if is_header_setter(name) {
            let value_taint = header_value_taint(args, ctx)
            if is_tainted(value_taint) {
              report_cwe113(ctx, expr, value_taint)
            }
          }
          if is_sanitize_call_name(name) {
            Clean
          } else {
            match classify_source_method(name) {
              Some(_) => Tainted
              None => arg_taint
            }
          }
        }
        None => arg_taint
      }
      let _ = flow(func, ctx)
      ret
    }
    DotApply(self~, method_name~, args~, ..) => {
      let recv_taint = flow(self, ctx)
      let arg_taint = flow_args(args, ctx)
      let combined = taint_or(recv_taint, arg_taint)
      let mname = method_name.name
      let ret = if is_header_setter(mname) {
        // only the header VALUE (positional 1 / labelled `value`) matters;
        // the header NAME slot and the response receiver are expected to
        // carry request-derived state
        let value_taint = header_value_taint(args, ctx)
        if is_tainted(value_taint) {
          report_cwe113(ctx, expr, value_taint)
        }
        Clean
      } else if is_sanitize_call_name(mname) || is_crlf_strip_call(mname, args) {
        Clean
      } else {
        match classify_source_method(mname) {
          Some(_) => Tainted
          None => combined
        }
      }
      ret
    }
    Infix(lhs~, rhs~, ..) => taint_or(flow(lhs, ctx), flow(rhs, ctx))
    Unary(expr~, ..) => flow(expr, ctx)
    Array(exprs~, ..) => fold_taint(exprs, ctx)
    ArraySpread(elems~, ..) => {
      let mut t = Clean
      for elem in elems {
        match elem {
          Regular(e) => t = taint_or(t, flow(e, ctx))
          Spread(expr~, ..) => t = taint_or(t, flow(expr, ctx))
        }
      }
      t
    }
    ArrayGet(array~, index~, ..) => {
      let t = flow(array, ctx)
      let _ = flow(index, ctx)
      t
    }
    ArrayGetSlice(array~, start_index~, end_index~, ..) => {
      let t = flow(array, ctx)
      let _ = start_index.map(fn(e) { flow(e, ctx) })
      let _ = end_index.map(fn(e) { flow(e, ctx) })
      t
    }
    ArraySet(array~, index~, value~, ..) => {
      let _ = flow(array, ctx)
      let _ = flow(index, ctx)
      flow(value, ctx)
    }
    ArrayAugmentedSet(array~, index~, value~, ..) => {
      let _ = flow(array, ctx)
      let _ = flow(index, ctx)
      flow(value, ctx)
    }
    ListComprehension(guard_~, body~, ..) => {
      let mut t = Clean
      let _ = guard_.map(fn(e) { t = taint_or(t, flow(e, ctx)) })
      taint_or(t, flow(body, ctx))
    }
    Constraint(expr~, ..) => flow(expr, ctx)
    Constr(..) => Clean
    LabelledBlock(body~, ..) => flow(body, ctx)
    While(loop_cond~, loop_body~, ..) => {
      let _ = flow(loop_cond, ctx)
      let _ = flow(loop_body, ctx)
      Clean
    }
    Function(func~, ..) => {
      // closure params: conservatively tainted (framework-supplied input)
      let saved : Array[String] = []
      for param in func.parameters {
        match param {
          Positional(binder~, ..)
          | Labelled(binder~, ..)
          | Optional(binder~, ..)
          | QuestionOptional(binder~, ..) => {
            saved.push(binder.name)
            ctx.env[binder.name] = Tainted
          }
          DiscardPositional(..) => ()
        }
      }
      let _ = flow(func.body, ctx)
      for name in saved {
        ctx.env[name] = Clean
      }
      Clean
    }
    If(cond~, ifso~, ifnot~, ..) => {
      let _ = flow(cond, ctx)
      let refined = validated_var(cond)
      let then_ctx = ctx.copy()
      match refined {
        Some(name) => then_ctx.env[name] = Clean
        None => ()
      }
      let _ = flow(ifso, then_ctx)
      let else_ctx = ctx.copy()
      let _ = ifnot.map(fn(e) { flow(e, else_ctx) })
      merge_env(ctx, then_ctx, else_ctx)
      Clean
    }
    Guard(cond~, body~, ..) => {
      // guard COND else OTHERWISE; BODY runs when cond holds
      let _ = flow(cond, ctx)
      let refined = validated_var(cond)
      match refined {
        Some(name) => ctx.env[name] = Clean
        None => ()
      }
      flow(body, ctx)
    }
    Is(expr~, ..) => {
      let _ = flow(expr, ctx)
      Clean
    }
    RegexMatch(expr~, bindings~, ..) => {
      let _ = flow(expr, ctx)
      // captures derived from the matched input
      match flow(expr, ctx) {
        t => {
          for binding in bindings {
            match binding.1 {
              Some(binder) => ctx.env[binder.name] = t
              None => ctx.env[binding.0.name] = t
            }
          }
          Clean
        }
      }
    }
    Defer(expr~, body~, ..) => {
      let _ = flow(expr, ctx)
      flow(body, ctx)
    }
    LetFn(func~, body~, ..) => {
      let _ = flow(Function(func~, loc=dummy_flow_loc()), ctx)
      flow(body, ctx)
    }
    LetAnd(bindings~, body~, ..) => {
      let mut t = Clean
      for binding in bindings {
        let (_, _, func) = binding
        t = taint_or(t, flow(Function(func~, loc=dummy_flow_loc()), ctx))
      }
      taint_or(t, flow(body, ctx))
    }
    Let(pattern~, expr~, body~, ..) => {
      let t = flow(expr, ctx)
      bind_pattern_taint(pattern, t, ctx)
      flow(body, ctx)
    }
    LetMut(binder~, expr~, body~, ..) => {
      let t = flow(expr, ctx)
      ctx.env[binder.name] = t
      flow(body, ctx)
    }
    Sequence(exprs~, last_expr~, ..) => {
      for e in exprs {
        let _ = flow(e, ctx)
      }
      flow(last_expr, ctx)
    }
    Tuple(exprs~, ..) => fold_taint(exprs, ctx)
    Record(fields~, ..) => {
      let mut t = Clean
      for field in fields {
        t = taint_or(t, flow(field.expr, ctx))
      }
      t
    }
    RecordUpdate(record~, fields~, ..) => {
      let mut t = flow(record, ctx)
      for field in fields {
        t = taint_or(t, flow(field.expr, ctx))
      }
      t
    }
    Field(record~, ..) => {
      // field access is a configuration/derived read, not user input
      // (parity with the legacy rule; M3 refines with type-aware policy)
      let _ = flow(record, ctx)
      Clean
    }
    As(expr~, ..) => flow(expr, ctx)
    Mutate(record~, field~, ..) => {
      let _ = flow(record, ctx)
      flow(field, ctx)
    }
    Match(expr~, cases~, ..) => {
      let scrut = flow(expr, ctx)
      let branch_envs : Array[FlowCtx] = []
      for case in cases {
        let case_ctx = ctx.copy()
        bind_pattern_taint(case.pattern, scrut, case_ctx)
        // constant patterns refine: `x is Some(...)`, literals
        let _ = case.guard_.map(fn(e) { flow(e, case_ctx) })
        let _ = flow(case.body, case_ctx)
        branch_envs.push(case_ctx)
      }
      merge_envs(ctx, branch_envs)
      Clean
    }
    LexMatch(expr~, cases~, ..) => {
      let t = flow(expr, ctx)
      for case in cases {
        let _ = flow(case.body, ctx)
      }
      t
    }
    LexScan(expr~, cases~, ..) => {
      let t = flow(expr, ctx)
      for case in cases {
        let _ = flow(case.body, ctx)
      }
      t
    }
    Pipe(lhs~, rhs~, ..) => taint_or(flow(lhs, ctx), flow(rhs, ctx))
    RevPipe(lhs~, rhs~, ..) => taint_or(flow(lhs, ctx), flow(rhs, ctx))
    Assign(var_~, expr~, ..) => {
      let t = flow(expr, ctx)
      ctx.env[longident_str(var_.name)] = t
      Clean
    }
    Return(return_value~, ..) => {
      let _ = return_value.map(fn(e) { flow(e, ctx) })
      Clean
    }
    Raise(err_value~, ..) => {
      let _ = flow(err_value, ctx)
      Clean
    }
    Quantifier(body~, ..) => flow(body, ctx)
    Implies(lhs~, rhs~, ..) => {
      let _ = flow(lhs, ctx)
      flow(rhs, ctx)
    }
    ProofAssert(..) => Clean
    ProofLet(expr~, ..) => flow(expr, ctx)
    Break(arg~, ..) => {
      let _ = arg.map(fn(e) { flow(e, ctx) })
      Clean
    }
    Continue(..) => Clean
    For(binders~, continue_block~, body~, ..) => {
      for pair in binders {
        let _ = flow(pair.1, ctx)
      }
      for pair in continue_block {
        let _ = flow(pair.1, ctx)
      }
      let _ = flow(body, ctx)
      Clean
    }
    ForEach(binders~, expr~, init~, continue_block~, body~, ..) => {
      let t = flow(expr, ctx)
      for b in binders {
        match b {
          Some(binder) => ctx.env[binder.name] = t
          None => ()
        }
      }
      for pair in init {
        let _ = flow(pair.1, ctx)
      }
      for pair in continue_block {
        let _ = flow(pair.1, ctx)
      }
      let _ = flow(body, ctx)
      Clean
    }
    Try(body~, catch_~, ..) => {
      let _ = flow(body, ctx)
      for case in catch_ {
        let _ = flow(case.body, ctx)
      }
      Clean
    }
    TryOperator(body~, ..) => flow(body, ctx)
    Map(elems~, ..) => {
      let mut t = Clean
      for elem in elems {
        t = taint_or(t, flow(elem.expr, ctx))
      }
      t
    }
    Group(expr~, ..) => flow(expr, ctx)
    TemplateWriting(expr~, template~, ..) => {
      let _ = flow(expr, ctx)
      flow(template, ctx)
    }
    StaticAssert(..) => Clean
  }
}

///|
fn dummy_flow_loc() -> @basic.Location {
  {
    start: { fname: "", lnum: 0, bol: 0, cnum: 0 },
    end: { fname: "", lnum: 0, bol: 0, cnum: 0 },
  }
}

///|
fn or_clean(t : Taint?) -> Taint {
  match t {
    Some(v) => v
    None => Clean
  }
}

///|
fn flow_args(args : @list.List[@syntax.Argument], ctx : FlowCtx) -> Taint {
  let mut t = Clean
  for arg in args {
    t = taint_or(t, flow(arg.value, ctx))
  }
  t
}

///|
fn fold_taint(exprs : @list.List[@syntax.Expr], ctx : FlowCtx) -> Taint {
  let mut t = Clean
  for e in exprs {
    t = taint_or(t, flow(e, ctx))
  }
  t
}

///|
fn bind_pattern_taint(pat : @syntax.Pattern, t : Taint, ctx : FlowCtx) -> Unit {
  match pat {
    Any(..) => ()
    Var(binder) => ctx.env[binder.name] = t
    Alias(pat~, alias_~, ..) => {
      bind_pattern_taint(pat, t, ctx)
      ctx.env[alias_.name] = t
    }
    Constraint(pat~, ..) => bind_pattern_taint(pat, t, ctx)
    Tuple(pats~, ..) =>
      for p in pats {
        bind_pattern_taint(p, t, ctx)
      }
    Constr(args~, ..) =>
      match args {
        Some(list) =>
          for arg in list {
            bind_pattern_taint(arg.pat, t, ctx)
          }
        None => ()
      }
    SpecialConstr(binder~, args~, ..) => {
      ctx.env[binder.name] = t
      for arg in args {
        bind_pattern_taint(arg.pat, t, ctx)
      }
    }
    Record(fields~, ..) =>
      for fp in fields {
        bind_pattern_taint(fp.pattern, t, ctx)
      }
    Or(pat1~, pat2~, ..) => {
      bind_pattern_taint(pat1, t, ctx)
      bind_pattern_taint(pat2, t, ctx)
    }
    With(pat~, ..) => bind_pattern_taint(pat, t, ctx)
    Array(pats~, ..) =>
      match pats {
        Closed(list) =>
          for ap in list {
            match ap {
              Pattern(p) => bind_pattern_taint(p, t, ctx)
              _ => ()
            }
          }
        Open(before, after, _) => {
          for ap in before {
            match ap {
              Pattern(p) => bind_pattern_taint(p, t, ctx)
              _ => ()
            }
          }
          for ap in after {
            match ap {
              Pattern(p) => bind_pattern_taint(p, t, ctx)
              _ => ()
            }
          }
        }
      }
    Constant(..) | Map(..) | Range(..) => ()
  }
}

// union-merge branch states back into ctx

///|
fn merge_env(ctx : FlowCtx, a : FlowCtx, b : FlowCtx) -> Unit {
  let keys : Array[String] = []
  a.env.each(fn(k, _) { keys.push(k) })
  b.env.each(fn(k, _) { keys.push(k) })
  for k in keys {
    ctx.env[k] = taint_or(or_clean(a.env.get(k)), or_clean(b.env.get(k)))
  }
}

///|
fn merge_envs(ctx : FlowCtx, branches : Array[FlowCtx]) -> Unit {
  if branches.length() == 0 {
    return
  }
  let keys : Array[String] = []
  for br in branches {
    br.env.each(fn(k, _) { keys.push(k) })
  }
  for k in keys {
    let mut t = Clean
    for br in branches {
      t = taint_or(t, or_clean(br.env.get(k)))
    }
    ctx.env[k] = t
  }
}

// taint of the header VALUE argument only (parity with the legacy rule)

///|
fn header_value_taint(
  args : @list.List[@syntax.Argument],
  ctx : FlowCtx,
) -> Taint {
  let mut pos_idx = 0
  let mut result = Clean
  for arg in args {
    match arg.kind {
      Labelled(label) =>
        if label.name == "value" {
          result = taint_or(result, flow(arg.value, ctx))
        }
      LabelledPun(label) =>
        if label.name == "value" {
          result = taint_or(result, flow(arg.value, ctx))
        }
      LabelledOption(label~, ..) =>
        if label.name == "value" {
          result = taint_or(result, flow(arg.value, ctx))
        }
      LabelledOptionPun(label~, ..) =>
        if label.name == "value" {
          result = taint_or(result, flow(arg.value, ctx))
        }
      _ => {
        if pos_idx == 1 {
          result = taint_or(result, flow(arg.value, ctx))
        }
        pos_idx += 1
      }
    }
  }
  result
}

// `x.replace_all(old="\r", new="")` strips CRLF: a sanitizer

///|
fn is_crlf_strip_call(
  mname : String,
  args : @list.List[@syntax.Argument],
) -> Bool {
  if mname != "replace_all" && mname != "replace" && mname != "remove" {
    return false
  }
  let mut has_crlf_arg = false
  for arg in args {
    match arg.value {
      Constant(c=String(s), ..) => if is_crlf_like(s) { has_crlf_arg = true }
      _ => ()
    }
  }
  has_crlf_arg
}

// ── guard/validation refinement ───────────────────────────────────────────

///|
fn is_false_const(e : @syntax.Expr) -> Bool {
  match e {
    Constant(c=Bool(false), ..) => true
    _ => false
  }
}

// If cond validates a variable (e.g. `x.contains("\r") == false`,
// `!x.has_crlf()`, `x =~ re"[a-z]+"`), the taken branch may treat it clean.

///|
fn validated_var(cond : @syntax.Expr) -> String? {
  match cond {
    Unary(expr~, ..) => validated_var_positive(expr)
    // `x.contains(...) == false` style
    Infix(lhs~, rhs~, ..) => {
      // `x.contains(..) == false` / `false == x.contains(..)`
      let lfalse = is_false_const(lhs)
      let rfalse = is_false_const(rhs)
      if lfalse {
        validated_var_positive(rhs)
      } else if rfalse {
        validated_var_positive(lhs)
      } else {
        validated_var_positive(cond)
      }
    }
    _ => validated_var_positive(cond)
  }
}

// positive validation form: the tested variable is the receiver/arg

///|
fn validated_var_positive(expr : @syntax.Expr) -> String? {
  match expr {
    DotApply(self~, method_name~, ..) => {
      let m = method_name.name
      if is_validation_method(m) || m == "view" {
        flow_var_name(self)
      } else {
        None
      }
    }
    Apply(func~, args~, ..) =>
      match apply_func_name(func) {
        Some(name) =>
          if is_validation_method(name) {
            let mut found : String? = None
            for arg in args {
              match flow_var_name(arg.value) {
                Some(n) => {
                  found = Some(n)
                  break
                }
                None => ()
              }
            }
            found
          } else {
            None
          }
        None => None
      }
    RegexMatch(expr~, ..) => flow_var_name(expr)
    Is(expr~, ..) => flow_var_name(expr)
    _ => None
  }
}

///|
fn is_validation_method(name : String) -> Bool {
  match name {
    "contains"
    | "has_prefix"
    | "has_suffix"
    | "is_ascii"
    | "is_alnum"
    | "is_digit"
    | "is_lower"
    | "is_upper"
    | "is_whitespace"
    | "is_valid"
    | "validate"
    | "check"
    | "sanitized"
    | "is_safe"
    | "starts_with"
    | "ends_with" => true
    _ => false
  }
}

///|
fn flow_var_name(expr : @syntax.Expr) -> String? {
  match expr {
    Ident(id~, ..) =>
      match id.name {
        Ident(name~) => Some(name)
        Dot(..) => None
      }
    Field(record~, ..) => flow_var_name(record)
    _ => None
  }
}

// ── sink reporting ────────────────────────────────────────────────────────

///|
fn report_cwe113(ctx : FlowCtx, expr : @syntax.Expr, t : Taint) -> Unit {
  let origin = match t {
    TaintedParam(p) => " (via parameter `" + p + "`)"
    _ => ""
  }
  ctx.findings.push(
    make_finding(
      { cwe: 113, variant: "crlf-injection" },
      ctx.severity,
      Medium,
      "Response header set with tainted value without CRLF sanitization" +
      origin +
      ". Attacker can inject \\r\\n to split the HTTP response, enabling session fixation or XSS.",
      ctx.file,
      ctx.source,
      expr.loc(),
    ),
  )
}

// ── M3: structural function summaries from the flow engine ───────────────
// Replaces the text-scanning Phase 1 of taint_interprocedural.mbt while
// keeping the InterProceduralContext API unchanged (scanner phase 2 and
// run_cross_func_taint keep working as-is).

///|
pub fn collect_func_summaries_flow(
  impls : @list.List[@syntax.Impl],
  file : String,
  ictx : InterProceduralContext,
) -> Unit {
  for item in impls {
    match item {
      TopFuncDef(fun_decl~, decl_body~, ..) => {
        let name = fun_decl.name.name
        let params : Array[String] = []
        let pnames : Array[String] = []
        match fun_decl.decl_params {
          Some(ps) =>
            for p in ps {
              match p {
                Positional(binder~, ..)
                | Labelled(binder~, ..)
                | Optional(binder~, ..)
                | QuestionOptional(binder~, ..) => pnames.push(binder.name)
                DiscardPositional(..) => ()
              }
            }
          None => ()
        }
        match decl_body {
          DeclBody(expr=Function(func~, ..)) =>
            collect_summary_func(
              Some(func.parameters),
              func.body,
              name,
              fun_decl.loc.start.lnum,
              file,
              ictx,
            )
          DeclBody(expr=body) => {
            for p in pnames {
              params.push(p)
            }
            collect_summary_func(
              fun_decl.decl_params,
              body,
              name,
              fun_decl.loc.start.lnum,
              file,
              ictx,
            )
          }
          _ => ()
        }
      }
      TopImpl(method_name~, params~, body~, ..) =>
        match body {
          DeclBody(expr=Function(func~, ..)) =>
            collect_summary_func(
              Some(func.parameters),
              func.body,
              method_name.name,
              method_name.loc.start.lnum,
              file,
              ictx,
            )
          DeclBody(expr=body) =>
            collect_summary_func(
              Some(params),
              body,
              method_name.name,
              method_name.loc.start.lnum,
              file,
              ictx,
            )
          _ => ()
        }
      _ => ()
    }
  }
}

///|
fn collect_summary_func(
  params : @list.List[@syntax.Parameter]?,
  body : @syntax.Expr,
  name : String,
  line : Int,
  file : String,
  ictx : InterProceduralContext,
) -> Unit {
  let param_names : Array[String] = []
  let sinks : Array[String] = []
  let ctx : FlowCtx = {
    env: Map([]),
    findings: [],
    file,
    source: "",
    severity: Info,
    record_sinks: None,
  }
  match params {
    Some(ps) =>
      for p in ps {
        match p {
          Positional(binder~, ..)
          | Labelled(binder~, ..)
          | Optional(binder~, ..)
          | QuestionOptional(binder~, ..) => {
            param_names.push(binder.name)
            ctx.env[binder.name] = TaintedParam(binder.name)
          }
          DiscardPositional(..) => ()
        }
      }
    None => ()
  }
  record_param_sinks(body, ctx, sinks)
  if sinks.length() > 0 {
    let param_sinks : Map[String, Array[TaintSink]] = Map([])
    // header sinks recorded for every param that reached a sink
    let header_arr : Array[TaintSink] = [HeaderValue]
    for pn in param_names {
      param_sinks[pn] = header_arr.copy()
    }
    ictx.summaries[name] = {
      name,
      file,
      line,
      params: param_names,
      param_sinks,
    }
  }
}

// walk collecting which params reach header sinks (M3 slice: HeaderValue;
// M4 extends to return/field flows)

///|
fn record_param_sinks(
  expr : @syntax.Expr,
  ctx : FlowCtx,
  sinks : Array[String],
) -> Unit {
  // reuse flow(), side-recording param->sink on header reports
  ctx.record_sinks = Some(sinks)
  let _ = flow_with_sink_recording(expr, ctx)
}

///|
fn flow_with_sink_recording(expr : @syntax.Expr, ctx : FlowCtx) -> Taint {
  match expr {
    DotApply(self~, method_name~, args~) => {
      if is_header_setter(method_name.name) {
        let value_taint = header_value_taint(args, ctx)
        match value_taint {
          TaintedParam(p) =>
            match ctx.record_sinks {
              Some(arr) => {
                let key = p + "|HeaderValue"
                if !arr.contains(key) {
                  arr.push(key)
                }
              }
              None => ()
            }
          _ => ()
        }
      }
      flow(expr, ctx)
    }
    Apply(func~, args~) => {
      match apply_func_name(func) {
        Some(name) =>
          if is_header_setter(name) {
            let value_taint = header_value_taint(args, ctx)
            match value_taint {
              TaintedParam(p) =>
                match ctx.record_sinks {
                  Some(arr) => {
                    let key = p + "|HeaderValue"
                    if !arr.contains(key) {
                      arr.push(key)
                    }
                  }
                  None => ()
                }
              _ => ()
            }
          }
        None => ()
      }
      flow(expr, ctx)
    }
    _ => flow(expr, ctx)
  }
}
