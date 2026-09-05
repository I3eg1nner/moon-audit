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
  // field read of a param-typed receiver: taint is CONDITIONAL on the
  // caller actually passing an object with a tainted field — no local
  // finding; recorded as a param-field summary and re-checked at call sites
  TaintedFieldRef(String, String) // (param, field)
} derive(Eq)

///|
fn taint_or(a : Taint, b : Taint) -> Taint {
  match (a, b) {
    (Clean, b) => b
    (a, Clean) => a
    (TaintedParam(p), TaintedParam(q)) =>
      if p == q {
        TaintedParam(p)
      } else {
        Tainted // mixed provenance: keep taint, drop single-param attribution
      }
    (TaintedFieldRef(p, f), TaintedFieldRef(q, g)) =>
      if p == q && f == g {
        TaintedFieldRef(p, f)
      } else {
        Tainted
      }
    (_, TaintedFieldRef(_, _)) | (TaintedFieldRef(_, _), _) => Tainted
    (_, TaintedParam(p)) => TaintedParam(p)
    (TaintedParam(p), _) => TaintedParam(p)
    _ => Tainted
  }
}

///|
fn is_tainted(t : Taint) -> Bool {
  t != Clean
}

// serialize taint env for loop fixpoint comparison

///|
fn env_fingerprint(ctx : FlowCtx) -> String {
  let keys : Array[String] = []
  ctx.env.each(fn(k, _) { keys.push(k) })
  keys.sort()
  let sb = StringBuilder()
  for k in keys {
    sb.write_string(k)
    sb.write_char(':')
    match ctx.env.get(k) {
      Some(Clean) => sb.write_char('C')
      Some(Tainted) => sb.write_char('T')
      Some(TaintedParam(p)) => {
        sb.write_char('P')
        sb.write_string(p)
      }
      Some(TaintedFieldRef(p, f)) => {
        sb.write_char('F')
        sb.write_string(p)
        sb.write_char('.')
        sb.write_string(f)
      }
      None => sb.write_char('_')
    }
    sb.write_char(';')
  }
  sb.to_string()
}

// iterate a loop body to a taint fixpoint (cap 3 passes)

///|
fn flow_to_fixpoint(e : @syntax.Expr, ctx : FlowCtx) -> Unit {
  let mut prev = env_fingerprint(ctx)
  let mut i = 0
  while i < 3 {
    let _ = flow(e, ctx)
    let cur = env_fingerprint(ctx)
    if cur == prev {
      break
    }
    prev = cur
    i += 1
  }
}

///|
priv struct FlowCtx {
  env : Map[String, Taint]
  findings : Array[Finding]
  file : String
  source : String
  severity : Severity
  mut record_sinks : Array[String]? // M3 summary recording channel
  mut record_returns : Array[String]? // P3: params flowing to return value
  mut record_fields : Array[String]? // P3: "r|field|src-param" field writes
  ictx : InterProceduralContext? // P3: summaries consumed at call sites
  // bounded heap slice (M4-lite): var -> alloc-site id ("file:line")
  sites : Map[String, String]
  // alloc-site -> field -> taint; SHARED across branch copies on purpose:
  // field facts are monotone (taint only grows), so branch joins are sound
  heap : Map[String, Map[String, Taint]]
  // site of the literal just evaluated, consumed at the next binding point
  mut alloc_result : String?
  // param-field sink recording channel ("param|field") for summaries
  mut record_field_sinks : Array[String]?
  taint_rules : TaintRuleset // project DSL entries (ADD to built-ins)
  // CWE-116/tainted-output gate: fires only from DSL/lib-model Output sinks;
  // default enabled (no builtin sink carries kind Output, so projects
  // without a model/config are unaffected)
  output_sinks_enabled : Bool
}

///|
fn FlowCtx::copy(self : FlowCtx) -> FlowCtx {
  let env : Map[String, Taint] = Map([])
  self.env.each(fn(k, v) { env[k] = v })
  let sites : Map[String, String] = Map([])
  self.sites.each(fn(k, v) { sites[k] = v })
  // heap/record channels are Map/Array references: shared by design
  { ..self, env, sites, alloc_result: None, }
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
  ictx? : InterProceduralContext,
  rules? : TaintRuleset,
  output_sinks_enabled? : Bool,
) -> Unit {
  let ctx : FlowCtx = {
    env: Map([]),
    findings,
    file,
    source,
    severity,
    record_sinks: None,
    record_returns: None,
    record_fields: None,
    sites: Map([]),
    heap: Map([]),
    alloc_result: None,
    record_field_sinks: None,
    ictx,
    taint_rules: match rules {
      Some(r) => r
      None => TaintRuleset::empty()
    },
    output_sinks_enabled: match output_sinks_enabled {
      Some(b) => b
      None => true
    },
  }
  // fn parameters carry param provenance: direct param flow reaches
  // sinks (report), but field access on a param is a config-like read
  // (Clean) — provenance-aware field propagation (review counterexample)
  match params {
    Some(ps) =>
      for param in ps {
        match param {
          Positional(binder~, ..)
          | Labelled(binder~, ..)
          | Optional(binder~, ..)
          | QuestionOptional(binder~, ..) =>
            ctx.env[binder.name] = TaintedParam(binder.name)
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
  rules? : TaintRuleset,
  output_sinks_enabled? : Bool,
) -> Unit {
  let ctx : FlowCtx = {
    env: Map([]),
    findings,
    file,
    source,
    severity,
    record_sinks: None,
    record_returns: None,
    record_fields: None,
    sites: Map([]),
    heap: Map([]),
    alloc_result: None,
    record_field_sinks: None,
    ictx: None,
    taint_rules: match rules {
      Some(r) => r
      None => TaintRuleset::empty()
    },
    output_sinks_enabled: match output_sinks_enabled {
      Some(b) => b
      None => true
    },
  }
  let _ = flow(body, ctx)
}

// ── bounded heap helpers ──────────────────────────────────────────────────

// site for a binding RHS: fresh literal site (consumed) or alias of a var

///|
fn resolve_binding_site(expr : @syntax.Expr, ctx : FlowCtx) -> String? {
  let fresh = ctx.alloc_result
  ctx.alloc_result = None
  match fresh {
    Some(s) => Some(s)
    None =>
      match expr {
        Ident(id~, ..) =>
          match id.name {
            Ident(name~) => ctx.sites.get(name)
            Dot(..) => None
          }
        Field(record~, ..) =>
          // o.g.h chain: inherit the base object's site (path-insensitive)
          resolve_binding_site(record, ctx)
        _ => None
      }
  }
}

// bind an alloc-site to a pattern's simple Var binders

///|
fn bind_site_to_pattern(
  pat : @syntax.Pattern,
  site : String?,
  ctx : FlowCtx,
) -> Unit {
  match (pat, site) {
    (Var(binder), Some(s)) => ctx.sites[binder.name] = s
    (Alias(pat~, alias_~, ..), Some(s)) => {
      bind_site_to_pattern(pat, site, ctx)
      ctx.sites[alias_.name] = s
    }
    _ => ()
  }
}

// field taint of a heap object; None = no fact for this site/field

///|
fn heap_read(ctx : FlowCtx, site : String, field : String) -> Taint? {
  match ctx.heap.get(site) {
    Some(fm) => fm.get(field)
    None => None
  }
}

///|
fn heap_write(ctx : FlowCtx, site : String, field : String, t : Taint) -> Unit {
  match ctx.heap.get(site) {
    Some(fm) => fm[field] = t
    None => {
      let fm : Map[String, Taint] = Map([])
      fm[field] = t
      ctx.heap[site] = fm
    }
  }
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
      let arg_taint_arr = flow_args_taints(args, ctx)
      let mut arg_taint = Clean
      for t in arg_taint_arr {
        arg_taint = taint_or(arg_taint, t)
      }
      // P3: consume field-write summaries — if the callee writes a tainted
      // param into a field of another param, the receiver argument becomes
      // tainted in the caller (source-derived provenance so later field
      // reads propagate per the provenance-aware Field rule)
      apply_field_taint_side_effect(func, args, ctx, arg_taint_arr)
      // M4-lite: conditional field sinks — callee reads `param.field`
      // into a sink; confirm against this caller's heap field facts
      apply_param_field_sinks(func, args, ctx, expr)
      let ret = match apply_func_name(func) {
        Some(name) => {
          let is_sink = is_header_setter(name) ||
            ctx.taint_rules.header_sink_hit(name)
          if is_sink {
            let slot = or_slot(ctx.taint_rules.sink_value_slot(name))
            let value_taint = header_value_taint(args, ctx, slot)
            if is_tainted(value_taint) {
              report_cwe113(ctx, expr, value_taint)
            }
          }
          if ctx.output_sinks_enabled && ctx.taint_rules.output_sink_hit(name) {
            let slot = or_slot(ctx.taint_rules.output_sink_slot(name))
            let value_taint = header_value_taint(args, ctx, slot)
            if is_tainted(value_taint) {
              report_output_sink(ctx, expr, value_taint, name)
            }
          }
          if is_sanitize_call_name(name) || ctx.taint_rules.sanitizer_hit(name) {
            Clean
          } else {
            match classify_source_method(name) {
              Some(_) => Tainted
              None =>
                if ctx.taint_rules.source_hit(name) {
                  Tainted
                } else {
                  arg_taint
                }
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
      let is_sink = is_header_setter(mname) ||
        ctx.taint_rules.header_sink_hit(mname)
      let ret = if is_sink {
        // only the header VALUE (positional 1 / labelled `value`, or the
        // DSL value_slot) matters; the header NAME slot and the response
        // receiver are expected to carry request-derived state
        let slot = or_slot(ctx.taint_rules.sink_value_slot(mname))
        let value_taint = header_value_taint(args, ctx, slot)
        if is_tainted(value_taint) {
          report_cwe113(ctx, expr, value_taint)
        }
        Clean
      } else if ctx.output_sinks_enabled &&
        ctx.taint_rules.output_sink_hit(mname) {
        // output channel sink (lib model / DSL kind "Output") -> CWE-116
        let slot = or_slot(ctx.taint_rules.output_sink_slot(mname))
        let value_taint = header_value_taint(args, ctx, slot)
        if is_tainted(value_taint) {
          report_output_sink(ctx, expr, value_taint, mname)
        }
        Clean
      } else if is_sanitize_call_name(mname) ||
        ctx.taint_rules.sanitizer_hit(mname) ||
        is_crlf_strip_chain(mname, args, self) {
        Clean
      } else {
        match classify_source_method(mname) {
          Some(_) => Tainted
          None =>
            if ctx.taint_rules.source_hit(mname) {
              Tainted
            } else {
              combined
            }
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
      // fixpoint: taint written in iteration N must be visible to the
      // sink executed in iteration N+1 (review counterexample b)
      flow_to_fixpoint(loop_body, ctx)
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
      let then_t = flow(ifso, then_ctx)
      let else_ctx = ctx.copy()
      let else_t = match ifnot {
        Some(e) => flow(e, else_ctx)
        None => Clean
      }
      merge_env(ctx, then_ctx, else_ctx)
      taint_or(then_t, else_t)
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
      // defer semantics: BODY runs first; the deferred expression runs on
      // the exit path (review counterexample — order was previously reversed)
      let t = flow(body, ctx)
      let _ = flow(expr, ctx)
      t
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
      // value-structure contract: tuple destructuring binds positionally so
      // (tainted, "safe") keeps the second component clean (third review)
      bind_let_taint(pattern, expr, ctx)
      bind_site_to_pattern(pattern, resolve_binding_site(expr, ctx), ctx)
      flow(body, ctx)
    }
    LetMut(binder~, expr~, body~, ..) => {
      let t = flow(expr, ctx)
      ctx.env[binder.name] = t
      match resolve_binding_site(expr, ctx) {
        Some(s) => ctx.sites[binder.name] = s
        None => ()
      }
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
      // allocation site: record per-field taint at construction
      let site = ctx.file + ":" + expr.loc().start.lnum.to_string()
      let fm : Map[String, Taint] = Map([])
      let mut t = Clean
      for field in fields {
        let ft = flow(field.expr, ctx)
        fm[field.label.name] = ft
        t = taint_or(t, ft)
      }
      ctx.heap[site] = fm
      ctx.alloc_result = Some(site)
      t
    }
    RecordUpdate(record~, fields~, ..) => {
      let mut t = flow(record, ctx)
      for field in fields {
        t = taint_or(t, flow(field.expr, ctx))
      }
      t
    }
    Field(record~, accessor~, ..) =>
      // precedence 1: heap read — receiver var with a known alloc-site
      //   (field facts from construction and Mutate writes)
      // precedence 2: provenance-aware fallback (review counterexample a):
      //   receiver tainted FROM A SOURCE  -> field carries the taint
      //   receiver tainted AS A DIRECT PARAM (config-like) -> field read
      //     is CONDITIONAL: no local finding (legacy parity, test c), but
      //     recorded as (param, field) for call-site re-check
      match accessor {
        Label(l) => {
          let heap_hit : Taint? = match flow_var_name(record) {
            Some(v) =>
              match ctx.sites.get(v) {
                Some(s) => heap_read(ctx, s, l.name)
                None => None
              }
            None => None
          }
          // merge: heap fact AND provenance fallback both apply —
          // e.g. a clean-at-construction field later tainted via a
          // field-write summary keeps its taint (P3 test parity)
          let fallback : Taint = {
            let t = flow(record, ctx)
            match t {
              Tainted => Tainted
              TaintedParam(p) => TaintedFieldRef(p, l.name)
              Clean => Clean
              TaintedFieldRef(_, _) => t
            }
          }
          match heap_hit {
            Some(ft) => taint_or(ft, fallback)
            None => fallback
          }
        }
        _ => flow(record, ctx)
      }
    As(expr~, ..) => flow(expr, ctx)
    Mutate(record~, accessor~, field~, ..) => {
      // P3: field-write summary event — `r.f = value` where value carries
      // param provenance p records "r|f|p" (approximation: base var only,
      // no alias tracking — documented in CONTEXT)
      let base = flow_var_name(record)
      let ft = flow(field, ctx)
      // bounded heap: record the field fact on the receiver's alloc-site
      match base {
        Some(v) =>
          match ctx.sites.get(v) {
            Some(s) =>
              match accessor {
                Label(l) => heap_write(ctx, s, l.name, ft)
                _ => ()
              }
            None => ()
          }
        None => ()
      }
      match (base, ft) {
        (Some(r), TaintedParam(p)) =>
          match ctx.record_fields {
            Some(arr) => {
              let entry = r + "|" + accessor_label(accessor) + "|" + p
              if !arr.contains(entry) {
                arr.push(entry)
              }
            }
            None => ()
          }
        _ => ()
      }
      let _ = flow(record, ctx)
      ft
    }
    Match(expr~, cases~, ..) => {
      let scrut = flow(expr, ctx)
      let branch_envs : Array[FlowCtx] = []
      let mut result = Clean
      for case in cases {
        let case_ctx = ctx.copy()
        bind_pattern_taint(case.pattern, scrut, case_ctx)
        // constant patterns refine: `x is Some(...)`, literals
        let _ = case.guard_.map(fn(e) { flow(e, case_ctx) })
        result = taint_or(result, flow(case.body, case_ctx))
        branch_envs.push(case_ctx)
      }
      merge_envs(ctx, branch_envs)
      result
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
      let name = longident_str(var_.name)
      ctx.env[name] = t
      match resolve_binding_site(expr, ctx) {
        Some(s) => ctx.sites[name] = s
        None => () // stale site kept: bounded approximation (documented)
      }
      Clean
    }
    Return(return_value~, ..) => {
      match return_value {
        Some(e) => {
          let t = flow(e, ctx)
          // P3: record param provenance flowing into the return value
          match t {
            TaintedParam(p) =>
              match ctx.record_returns {
                Some(arr) => if !arr.contains(p) { arr.push(p) }
                None => ()
              }
            _ => ()
          }
        }
        None => ()
      }
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
      flow_to_fixpoint(body, ctx)
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
      flow_to_fixpoint(body, ctx)
      Clean
    }
    Try(body~, catch_~, try_else~, ..) => {
      // Error-flow contract: body, catches, and the noraise arm are separate
      // exit states that MERGE (third review). Catches observe the pre-raise
      // state (approximated by the post-body env); the error payload may
      // carry body-derived data (conservative: body result ∪ any body taint).
      let body_ctx = ctx.copy()
      let body_t = flow(body, body_ctx)
      let err_t = taint_or(body_t, env_any_taint(body_ctx))
      let branch_envs : Array[FlowCtx] = [body_ctx]
      let mut result = body_t
      for case in catch_ {
        let case_ctx = ctx.copy()
        merge_env(case_ctx, body_ctx, case_ctx) // entry ∪ post-body state
        bind_pattern_taint(case.pattern, err_t, case_ctx)
        let t = flow(case.body, case_ctx)
        result = taint_or(result, t)
        branch_envs.push(case_ctx)
      }
      match try_else {
        Some(arms) =>
          for case in arms {
            // noraise arm binds the SUCCESS value and runs on the happy path
            let arm_ctx = ctx.copy()
            merge_env(arm_ctx, body_ctx, arm_ctx)
            bind_pattern_taint(case.pattern, body_t, arm_ctx)
            let t = flow(case.body, arm_ctx)
            result = taint_or(result, t)
            branch_envs.push(arm_ctx)
          }
        None => ()
      }
      merge_envs(ctx, branch_envs)
      result
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
    start: { fname: "", lnum: 0, bol: 0, cnum: 0, },
    end: { fname: "", lnum: 0, bol: 0, cnum: 0, },
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

// per-argument taints in argument order (single flow pass, no re-visits)

///|
fn flow_args_taints(
  args : @list.List[@syntax.Argument],
  ctx : FlowCtx,
) -> Array[Taint] {
  let arr : Array[Taint] = []
  for arg in args {
    arr.push(flow(arg.value, ctx))
  }
  arr
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
// Positional tuple binding: (tainted, "safe") binds per component so the
// clean component stays clean; mismatched shapes fall back to whole-taint

///|
fn bind_let_taint(
  pattern : @syntax.Pattern,
  expr : @syntax.Expr,
  ctx : FlowCtx,
) -> Unit {
  match (pattern, expr) {
    (Tuple(pats~, ..), Tuple(exprs~, ..)) => {
      let parr = pats.to_array()
      let earr = exprs.to_array()
      if parr.length() == earr.length() {
        let mut i = 0
        while i < parr.length() {
          let ct = flow(earr[i], ctx)
          bind_pattern_taint(parr[i], ct, ctx)
          i += 1
        }
      } else {
        let t = flow(expr, ctx)
        bind_pattern_taint(pattern, t, ctx)
      }
    }
    _ => {
      let t = flow(expr, ctx)
      bind_pattern_taint(pattern, t, ctx)
    }
  }
}

// conservative aggregate: Tainted if any tracked var is tainted in the state
// (used for error payloads that may carry body-derived data)

///|
fn env_any_taint(ctx : FlowCtx) -> Taint {
  let mut any = Clean
  ctx.env.each(fn(_k, v) { if v != Clean { any = Tainted } })
  any
}

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
  value_slot : Int,
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
        if pos_idx == value_slot {
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
fn is_crlf_strip_chain(
  mname : String,
  args : @list.List[@syntax.Argument],
  recv : @syntax.Expr,
) -> Bool {
  let (cr, lf, crlf) = crlf_strip_coverage(mname, args, recv)
  crlf || (cr && lf)
}

// coverage triples of a strip chain: (removed

///|
fn crlf_strip_coverage(
  mname : String,
  args : @list.List[@syntax.Argument],
  recv : @syntax.Expr,
) -> (Bool, Bool, Bool) {
  if mname != "replace_all" {
    return (false, false, false)
  }
  let mut has_cr = false
  let mut has_lf = false
  let mut has_crlf = false
  // STRICT argument roles: only the OLD slot (labelled `old` or positional
  // 0) removes content; CRLF in the NEW slot INTRODUCES the danger and
  // poisons the chain (never a sanitizer).
  let mut pos = 0
  let mut poisoned = false
  for arg in args {
    let is_old_slot = match arg.kind {
      Labelled(label) => label.name == "old"
      _ => pos == 0 // positional: first arg is the searched pattern
    }
    let is_new_slot = match arg.kind {
      Labelled(label) => label.name == "new"
      _ => pos == 1
    }
    match arg.value {
      Constant(c=String(s), ..) => {
        let cr = s == "\\r" || s == "\r"
        let lf = s == "\\n" || s == "\n"
        let crlf = s == "\\r\\n" || s == "\r\n"
        if is_new_slot && (cr || lf || crlf) {
          poisoned = true
        }
        if is_old_slot {
          if crlf {
            has_crlf = true
          }
          if cr {
            has_cr = true
          }
          if lf {
            has_lf = true
          }
        }
      }
      _ => ()
    }
    pos += 1
  }
  if poisoned {
    return (false, false, false)
  }
  match recv {
    DotApply(self~, method_name~, args~, ..) => {
      let (r_cr, r_lf, r_crlf) = crlf_strip_coverage(
        method_name.name,
        args,
        self,
      )
      (has_cr || r_cr, has_lf || r_lf, has_crlf || r_crlf)
    }
    _ => (has_cr, has_lf, has_crlf)
  }
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
  // STRICT polarity: the taken branch is clean ONLY when the condition
  // asserts safety:
  //   - whitelist validator holds:      x.is_ascii(), x =~ re"[...]"
  //   - dangerous content ABSENT:       !x.contains(CRLF), x.contains(CRLF) == false
  // `x.contains(CRLF)` (positive) = danger IS present: not clean.
  // `!x.is_ascii()` (negated whitelist): not clean.
  match cond {
    Unary(op~, expr~, ..) =>
      if is_not_op(op) {
        dangerous_contains_var(expr)
      } else {
        None
      }
    Infix(op~, lhs~, rhs~, ..) =>
      if is_eq_op(op) {
        if is_false_const(lhs) {
          dangerous_contains_var(rhs)
        } else if is_false_const(rhs) {
          dangerous_contains_var(lhs)
        } else {
          None
        }
      } else {
        None
      }
    RegexMatch(expr~, ..) => flow_var_name(expr)
    DotApply(self~, method_name~, ..) =>
      if is_whitelist_validator(method_name.name) {
        flow_var_name(self)
      } else {
        None
      }
    _ => None
  }
}

// `x.contains(CRLF literal)`: var whose DANGEROUS content is tested
// (clean only under negation)

///|
fn dangerous_contains_var(expr : @syntax.Expr) -> String? {
  match expr {
    DotApply(self~, method_name~, ..) => {
      let m = method_name.name
      if (m == "contains" || m == "has_prefix" || m == "has_suffix") &&
        args_have_crlf_literal(expr) {
        flow_var_name(self)
      } else {
        None
      }
    }
    _ => None
  }
}

///|
fn args_have_crlf_literal(e : @syntax.Expr) -> Bool {
  match e {
    DotApply(args~, ..) => {
      let mut found = false
      for arg in args {
        match arg.value {
          // NOTE: parser Constant strings hold RAW source text, so CRLF
          // appears as the 2-char escape sequences, not control bytes
          Constant(c=String(s), ..) =>
            if s.contains("\\r") ||
              s.contains("\\n") ||
              s.contains("\r") ||
              s.contains("\n") {
              found = true
            }
          _ => ()
        }
      }
      found
    }
    _ => false
  }
}

///|
fn is_not_op(v : @syntax.Var) -> Bool {
  match v.name {
    Ident(name~) => name == "not" || name == "!"
    Dot(..) => false
  }
}

///|
fn is_eq_op(v : @syntax.Var) -> Bool {
  match v.name {
    Ident(name~) => name == "=="
    Dot(..) => false
  }
}

// whitelist validators: passing implies the value is safe for headers

///|
fn is_whitelist_validator(name : String) -> Bool {
  match name {
    "is_ascii"
    | "is_alnum"
    | "is_digit"
    | "is_lower"
    | "is_upper"
    | "is_whitespace"
    | "is_valid"
    | "validate"
    | "sanitized"
    | "is_safe" => true
    _ => false
  }
}

// positive validation form: the tested variable is the receiver/arg

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
// field label of a Mutate accessor ("?" for non-label forms)

///|
fn accessor_label(accessor : @syntax.Accessor) -> String {
  match accessor {
    Label(l) => l.name
    _ => "?"
  }
}

///|
fn param_index(params : Array[String], name : String) -> Int? {
  let mut found : Int? = None
  for i in 0..<params.length() {
    if params[i] == name && found == None {
      found = Some(i)
    }
  }
  found
}

// P3: call-site consumption of field-write summaries.
// If summary says callee writes taint from param p into a field of param r,
// and the caller passes a tainted value at p's position, then the variable
// passed at r's position becomes tainted (source-derived provenance).
// arg_taints are the single-pass flow results in argument order.

///|
fn apply_param_field_sinks(
  func : @syntax.Expr,
  args : @list.List[@syntax.Argument],
  ctx : FlowCtx,
  call_expr : @syntax.Expr,
) -> Unit {
  let ictx = match ctx.ictx {
    Some(i) => i
    None => return
  }
  let name = match apply_func_name(func) {
    Some(n) => n
    None => return
  }
  let summary = match ictx.summaries.get(name) {
    Some(s) => s
    None => return
  }
  if summary.param_field_sinks.length() == 0 {
    return
  }
  // positional param index -> argument expression (bounded: positional
  // args only; labelled lookups follow the same convention as
  // apply_field_taint_side_effect)
  let arg_exprs : Array[@syntax.Expr?] = []
  let mut pos = 0
  for arg in args {
    match arg.kind {
      Labelled(_)
      | LabelledPun(_)
      | LabelledOption(..)
      | LabelledOptionPun(..) => arg_exprs.push(None)
      _ => {
        ignore(pos)
        arg_exprs.push(Some(arg.value))
        pos += 1
      }
    }
  }
  for pair in summary.param_field_sinks {
    let (p, f) = pair
    let pi = match param_index(summary.params, p) {
      Some(i) => i
      None => continue
    }
    let arg_e = match (pi < arg_exprs.length(), arg_exprs[pi]) {
      (true, Some(e)) => e
      _ => continue
    }
    // bounded heap lookup: simple var argument with a known alloc-site
    match flow_var_name(arg_e) {
      Some(v) =>
        match ctx.sites.get(v) {
          Some(s) =>
            match heap_read(ctx, s, f) {
              Some(ft) =>
                // conditional taint CONFIRMED by the caller's heap fact
                match ft {
                  TaintedFieldRef(_, _) => () // still conditional: skip
                  _ => if is_tainted(ft) { report_cwe113(ctx, call_expr, ft) }
                }
              None => ()
            }
          None => ()
        }
      None => ()
    }
  }
}

///|
fn apply_field_taint_side_effect(
  func : @syntax.Expr,
  args : @list.List[@syntax.Argument],
  ctx : FlowCtx,
  arg_taints : Array[Taint],
) -> Unit {
  let ictx = match ctx.ictx {
    Some(i) => i
    None => return
  }
  let name = match apply_func_name(func) {
    Some(n) => n
    None => return
  }
  let summary = match ictx.summaries.get(name) {
    Some(s) => s
    None => return
  }
  if summary.field_taint.length() == 0 {
    return
  }
  // argument-order index -> param index (labelled match by name,
  // positional by param order)
  let arg_param_idx : Array[Int?] = []
  let mut pos = 0
  let mut i = 0
  for arg in args {
    let pidx = match arg.kind {
      Labelled(l) | LabelledPun(l) => param_index(summary.params, l.name)
      _ => if pos < summary.params.length() { Some(pos) } else { None }
    }
    arg_param_idx.push(pidx)
    match arg.kind {
      Labelled(_)
      | LabelledPun(_)
      | LabelledOption(..)
      | LabelledOptionPun(..) => ()
      _ => pos += 1
    }
    i += 1
  }
  ignore(i)
  // taint per param position (from the precomputed single-pass taints)
  let taint_at : Array[Taint] = []
  let var_at : Array[String?] = []
  let mut n = 0
  while n < summary.params.length() {
    taint_at.push(Clean)
    var_at.push(None)
    n += 1
  }
  let mut ai = 0
  for arg in args {
    match arg_param_idx[ai] {
      Some(pi) =>
        if pi < taint_at.length() && ai < arg_taints.length() {
          taint_at[pi] = arg_taints[ai]
          var_at[pi] = flow_var_name(arg.value)
        }
      None => ()
    }
    ai += 1
  }
  summary.field_taint.each(fn(recv_param, entries) {
    match param_index(summary.params, recv_param) {
      Some(ri) => {
        // any tainted source-param argument triggers the field write
        let mut triggered = false
        for entry in entries {
          match param_index(summary.params, entry.1) {
            Some(si) =>
              if si < taint_at.length() && is_tainted(taint_at[si]) {
                triggered = true
              }
            None => ()
          }
        }
        if triggered && ri < var_at.length() {
          match var_at[ri] {
            Some(var_name) => {
              let cur = or_clean_taint(ctx.env.get(var_name))
              ctx.env[var_name] = taint_or(cur, Tainted)
            }
            None => ()
          }
        }
      }
      None => ()
    }
  })
}

///|
fn or_clean_taint(t : Taint?) -> Taint {
  match t {
    Some(v) => v
    None => Clean
  }
}

///|
fn report_output_sink(
  ctx : FlowCtx,
  expr : @syntax.Expr,
  t : Taint,
  sink_name : String,
) -> Unit {
  let origin = match t {
    TaintedParam(p) => " (via parameter `" + p + "`)"
    _ => ""
  }
  ctx.findings.push(
    make_finding(
      { cwe: 116, variant: "tainted-output", },
      ctx.severity,
      Medium,
      "Tainted data written to output channel `" +
      sink_name +
      "` without neutralization" +
      origin +
      ". User-controlled content that reaches an FFI/network output can enable injection attacks.",
      ctx.file,
      ctx.source,
      expr.loc(),
    ),
  )
}

///|
fn report_cwe113(ctx : FlowCtx, expr : @syntax.Expr, t : Taint) -> Unit {
  let origin = match t {
    TaintedParam(p) => " (via parameter `" + p + "`)"
    _ => ""
  }
  // conditional field-ref sink: NO local finding (config-like read);
  // record (param, field) for call-site re-check via summaries
  match t {
    TaintedFieldRef(p, f) => {
      match ctx.record_field_sinks {
        Some(arr) => {
          let entry = p + "|" + f
          if !arr.contains(entry) {
            arr.push(entry)
          }
        }
        None => ()
      }
      return
    }
    _ => ()
  }
  // M3 summary event: record which parameter reached a header sink
  match t {
    TaintedParam(p) =>
      match ctx.record_sinks {
        Some(arr) => if !arr.contains(p) { arr.push(p) }
        None => ()
      }
    _ => ()
  }
  ctx.findings.push(
    make_finding(
      { cwe: 113, variant: "crlf-injection", },
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
  rules? : TaintRuleset,
) -> Unit {
  ignore(rules) // summaries use built-in classification; DSL affects rule scan only
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
  let returns : Array[String] = []
  let fields : Array[String] = []
  let field_sinks : Array[String] = [] // "param|field" conditional sinks
  let ctx : FlowCtx = {
    env: Map([]),
    findings: [],
    file,
    source: "",
    severity: Info,
    record_sinks: None,
    record_returns: None,
    record_fields: None,
    sites: Map([]),
    heap: Map([]),
    alloc_result: None,
    record_field_sinks: None,
    ictx: None,
    taint_rules: TaintRuleset::empty(),
    output_sinks_enabled: true,
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
  let final_taint = record_param_sinks(
    body, ctx, sinks, returns, field_sinks, fields,
  )
  // final-expression return taint (expression-oriented bodies): a body
  // whose value carries param provenance means "param flows to return"
  match final_taint {
    TaintedParam(p) =>
      if param_names.contains(p) && !returns.contains(p) {
        returns.push(p)
      }
    _ => ()
  }
  // dedup return channel against param set
  let ret_from : Array[String] = []
  for p in returns {
    if param_names.contains(p) && !ret_from.contains(p) {
      ret_from.push(p)
    }
  }
  // precise sink mapping: ONLY parameters that actually reached a sink
  let param_sinks : Map[String, Array[TaintSink]] = Map([])
  for pn in sinks {
    if param_names.contains(pn) && !param_sinks.contains(pn) {
      param_sinks[pn] = [HeaderValue]
    }
  }
  // field writes: recorded as "r|field|src-param" strings
  let field_taint : Map[String, Array[(String, String)]] = Map([])
  for entry in fields {
    let first_bar = find_bar(entry)
    let second_bar = find_bar_from(entry, first_bar + 1)
    if first_bar > 0 && second_bar > first_bar {
      let r = Show::to_string(entry[:first_bar])
      let fname = Show::to_string(entry[first_bar + 1:second_bar])
      let src = Show::to_string(entry[second_bar + 1:])
      if param_names.contains(r) && param_names.contains(src) {
        match field_taint.get(r) {
          Some(arr) => {
            let pair = (fname, src)
            if !arr.contains(pair) {
              arr.push(pair)
            }
          }
          None => field_taint[r] = [(fname, src)]
        }
      }
    }
  }
  // conditional field sinks: "param|field" -> (param, field) pairs
  let param_field_sinks : Array[(String, String)] = []
  for entry in field_sinks {
    let bar = find_bar(entry)
    if bar > 0 {
      let p = Show::to_string(entry[:bar])
      let f = Show::to_string(entry[bar + 1:])
      if param_names.contains(p) {
        let pair = (p, f)
        if !param_field_sinks.contains(pair) {
          param_field_sinks.push(pair)
        }
      }
    }
  }
  if param_sinks.length() > 0 ||
    ret_from.length() > 0 ||
    field_taint.length() > 0 ||
    param_field_sinks.length() > 0 {
    ictx.summaries[name] = {
      name,
      file,
      line,
      params: param_names,
      param_sinks,
      ret_from,
      field_taint,
      param_field_sinks,
    }
  }
}

// walk collecting which params reach header sinks (M3 slice: HeaderValue;
// P3 adds return-value and field-write recording channels)

///|
fn record_param_sinks(
  expr : @syntax.Expr,
  ctx : FlowCtx,
  sinks : Array[String],
  returns : Array[String],
  field_sinks : Array[String],
  fields : Array[String],
) -> Taint {
  ctx.record_sinks = Some(sinks)
  ctx.record_returns = Some(returns)
  ctx.record_fields = Some(fields)
  ctx.record_field_sinks = Some(field_sinks)
  let final_taint = flow(expr, ctx)
  ctx.record_sinks = None
  ctx.record_returns = None
  ctx.record_fields = None
  ctx.record_field_sinks = None
  final_taint
}

// byte offset helpers for "r|field|p" entries

///|
fn find_bar(s : String) -> Int {
  find_bar_from(s, 0)
}

///|
fn find_bar_from(s : String, from : Int) -> Int {
  let mut i = from
  while i < s.length() {
    if s[i] == '|' {
      return i
    }
    i += 1
  }
  -1
}
