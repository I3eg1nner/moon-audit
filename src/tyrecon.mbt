// M1 type-reconstruction spike: local type propagation over the official AST.
// Goal: measure how many call sites in a real project can be resolved without
// a full type checker (see docs/ir/PLAN.md milestone M1).
//
// Two passes per package:
//   Pass A (collect):  top-level symbols — fn return types, impl methods,
//                      type constructors, struct fields.
//   Pass B (infer):    per function, seed env from annotated params, then
//                      bottom-up local inference; record call-site stats.
//
// Known blind spots (by design, covered by later milestones):
//   - closures/callbacks receiving values from framework dispatch (M2)
//   - trait objects / generic params receivers (M4 devirtualization)
//   - cross-package types used without local impl visible (import tables)

///|
pub(all) struct PkgSymbols {
  // T1.2 alias policy: conservative(true)=short_key fallback binds (legacy);
  // strict(false)=fallback miss counts as unresolved(reason=alias).
  mut alias_mode : Bool
  mut alias_unresolved : Int
  fn_exists : Map[String, Bool] // fn names defined in this package
  fn_ret : Map[String, IRType] // fn name -> annotated return type
  impl_methods : Map[String, String] // "SelfTy::method" -> trait path
  constructors : Map[String, String] // constructor name -> type name
  struct_fields : Map[String, Map[String, IRType]] // type -> field -> type
  constr_params : Map[String, Array[IRType]] // constructor -> payload types
  trait_params : Map[String, Array[IRType?]] // "Trait::m" -> declared param types
  fn_param_arrows : Map[String, Array[Array[IRType?]]] // fn -> per-param arrow arg types
  alias_arrows : Map[String, Array[IRType?]] // type alias -> arrow param types
  fn_sigs : Map[String, FnSig] // T1.3 unified signature model
  value_types : Map[String, IRType] // const/value name -> declared type (.mbti)
  globals : Map[String, IRType] // top-level `let x : T = ...` annotated globals
  lib_fn_ret : Map[String, IRType] // library-model return types (extern etc.)
  lib_callbacks : Map[String, Array[String]] // lib-model callback param placeholders
  trait_names : Map[String, Bool] // declared trait names (local + .mbti)
  type_params : Map[String, Bool] // generic params seen in this package
}

///|
pub fn PkgSymbols::new() -> PkgSymbols {
  let symbols : PkgSymbols = {
    alias_mode: true, // unit-test constructors keep legacy behavior
    alias_unresolved: 0,
    fn_exists: Map([]),
    fn_ret: Map([]),
    impl_methods: Map([]),
    constructors: Map([]),
    struct_fields: Map([]),
    constr_params: Map([]),
    trait_params: Map([]),
    fn_param_arrows: Map([]),
    alias_arrows: Map([]),
    fn_sigs: Map([]),
    value_types: Map([]),
    globals: Map([]),
    lib_fn_ret: Map([]),
    lib_callbacks: Map([]),
    trait_names: Map([]),
    type_params: Map([]),
  }
  // core trait method signatures (Show etc.) for impl param backfill —
  // seeded through the FnSig sole write points (never a direct table write)
  let show_sig : FnSig = {
    params: [
      {
        binder: "self",
        kind: "positional",
        has_default: false,
        ty: IRUnresolved,
        arrow_args: [],
      },
      {
        binder: "logger",
        kind: "positional",
        has_default: false,
        ty: IRConcrete("Logger", []),
        arrow_args: [],
      },
    ],
    generic_constraints: [],
    return_ty: IRUnit,
    error_effect: "none",
    is_async: false,
    entry: "internal",
  }
  store_fn_sig(symbols, "Show::output", show_sig)
  materialize_trait_from_sig(symbols, "Show::output")
  symbols
}

///|
pub(all) struct CallSiteStat {
  caller : String
  file : String
  line : Int
  recv_var : String // T4c-2: receiver variable name at dispatch sites
  recv_pt : Array[String] // T4c-2: receiver points-to TYPES (per-fn solve)
  kind : String // "static" | "receiver" | "higher"
  resolved : Bool
  target : String // best-known callee identity
  recv_ty : String // receiver type display (receiver calls)
}

///|
pub(all) struct IRStatsResult {
  mut files_scanned : Int
  mut funcs_scanned : Int
  mut total_calls : Int
  mut static_calls : Int
  mut static_resolved : Int
  mut receiver_calls : Int
  mut receiver_resolved : Int // receiver inferred to a concrete type
  mut receiver_dispatch : Int // trait object / type param receiver (M4)
  mut receiver_unknown : Int
  mut higher_calls : Int
  mut alias_unresolved : Int // T1.2: strict-mode short-key fallback misses
  mut pt_iterations : Int // D2b: interprocedural feedback rounds executed
  mut pt_not_converged : Bool // E2: worklist budget exhausted (disclosed)
  mut pt_carrier : PtCarrier? // E2: batch-mode cross-file slice/pending merge
  sites : Array[CallSiteStat]
}

///|
pub fn IRStatsResult::new() -> IRStatsResult {
  {
    files_scanned: 0,
    funcs_scanned: 0,
    total_calls: 0,
    static_calls: 0,
    static_resolved: 0,
    receiver_calls: 0,
    receiver_resolved: 0,
    receiver_dispatch: 0,
    receiver_unknown: 0,
    higher_calls: 0,
    alias_unresolved: 0,
    pt_iterations: 0,
    pt_not_converged: false,
    pt_carrier: None,
    sites: [],
  }
}

///|
pub fn IRStatsResult::combined_resolution(self : IRStatsResult) -> Int {
  if self.total_calls == 0 {
    return 0
  }
  (self.static_resolved + self.receiver_resolved) * 100 / self.total_calls
}

// ── Pass A: symbol collection ─────────────────────────────────────────────

///|
pub fn collect_symbols(
  impls : Array[@syntax.Impl],
  symbols : PkgSymbols,
) -> Unit {
  for item in impls {
    match item {
      TopFuncDef(fun_decl~, decl_body~, ..) => {
        let name = fun_decl.name.name
        symbols.fn_exists[name] = true
        // signature params live in decl_body's Func (decl_params may be None)
        let sig_params_opt : @list.List[@syntax.Parameter]? = match decl_body {
          DeclBody(expr=Function(func~, ..)) => Some(func.parameters)
          _ => fun_decl.decl_params
        }
        match sig_params_opt {
          Some(ps) =>
            collect_fn_sig(
              ps,
              name,
              symbols,
              fun_decl.return_type,
              fun_decl.error_type,
              fun_decl.is_async != None,
              fun_decl.quantifiers,
              fn_entry_kind(fun_decl.vis, decl_body),
            )
          None => ()
        }
        match fun_decl.return_type {
          Some(ty) => symbols.fn_ret[name] = type_to_ir(ty, symbols)
          None => ()
        }
        match fun_decl.type_name {
          Some(tn) => {
            let key = type_name_str(tn) + "::" + name
            symbols.fn_exists[key] = true
            match fun_decl.return_type {
              Some(ty) => symbols.fn_ret[key] = type_to_ir(ty, symbols)
              None => ()
            }
            match sig_params_opt {
              Some(ps) =>
                collect_fn_sig(
                  ps,
                  key,
                  symbols,
                  fun_decl.return_type,
                  fun_decl.error_type,
                  fun_decl.is_async != None,
                  fun_decl.quantifiers,
                  fn_entry_kind(fun_decl.vis, decl_body),
                )
              None => ()
            }
          }
          None => ()
        }
      }
      TopImpl(
        self_ty~,
        trait_~,
        method_name~,
        quantifiers~,
        params~,
        ret_ty~,
        err_ty~,
        body~,
        vis~,
        ..
      ) => {
        let self_ty_name = match self_ty {
          Some(t) => type_to_string(t)
          None => "?"
        }
        let key = self_ty_name + "::" + method_name.name
        symbols.impl_methods[key] = longident_str(trait_.name)
        symbols.fn_exists[key] = true
        collect_fn_sig(
          params,
          key,
          symbols,
          ret_ty,
          err_ty,
          false,
          quantifiers,
          fn_entry_kind(vis, body),
        )
        match ret_ty {
          Some(ty) => symbols.fn_ret[key] = type_to_ir(ty, symbols)
          None => ()
        }
      }
      TopTrait(decl) => {
        symbols.trait_names[decl.name.name] = true
        for m in decl.methods {
          let key = decl.name.name + "::" + m.name.name
          collect_fn_sig(
            m.params,
            key,
            symbols,
            m.return_type,
            m.error_type,
            m.is_async != None,
            m.quantifiers,
            "internal", // trait method declaration (no body)
          )
          // P1-2c: trait_params derived from the stored FnSig (sole write
          // point) — replaces the former parallel per-param recomputation
          materialize_trait_from_sig(symbols, key)
          match m.return_type {
            Some(t) => symbols.fn_ret[key] = type_to_ir(t, symbols)
            None => ()
          }
        }
      }
      TopUsing(names~, ..) =>
        // `using @pkg.{name, ...}`: unqualified aliases resolve statically
        for pair in names {
          let alias_name = pair.0.binder.name
          symbols.fn_exists[alias_name] = true
        }
      TopTypeDef(decl) => collect_type_decl(decl, symbols)
      TopLetDef(binder~, ty~, is_declare~, ..) => {
        // annotated top-level globals: `let ws_handler_map : Map[...] = ...`
        // — the type source for FFI binding-file receiver chains
        if !is_declare {
          match ty {
            Some(t) => symbols.globals[binder.name] = type_to_ir(t, symbols)
            None => ()
          }
        }
        match ty {
          Some(_) => symbols.fn_exists[binder.name] = true
          None => ()
        }
      }
      _ => ()
    }
  }
}

///|
fn collect_constrs(
  constrs : @list.List[@syntax.ConstrDecl],
  tycon : String,
  symbols : PkgSymbols,
) -> Unit {
  for c in constrs {
    symbols.constructors[c.name.name] = tycon
    match c.args {
      Some(params) => {
        let tys : Array[IRType] = []
        for param in params {
          tys.push(type_to_ir(param.ty, symbols))
        }
        symbols.constr_params[c.name.name] = tys
      }
      None => ()
    }
  }
}

///|
fn fn_entry_kind(vis : @syntax.Visibility, body : @syntax.DeclBody) -> String {
  match body {
    DeclStubs(_) => "ffi-extern"
    _ =>
      match vis {
        Pub(..) => "library-pub"
        _ => "internal"
      }
  }
}

///|
fn collect_type_decl(decl : @syntax.TypeDecl, symbols : PkgSymbols) -> Unit {
  let tycon = decl.tycon
  for param in decl.params {
    match param.name {
      Some(n) => symbols.type_params[n] = true
      None => ()
    }
  }
  match decl.components {
    Record(fields~) => {
      let field_map : Map[String, IRType] = Map([])
      for field in fields {
        field_map[field.name.label] = type_to_ir(field.ty, symbols)
      }
      symbols.struct_fields[tycon] = field_map
    }
    Variant(constrs) => collect_constrs(constrs, tycon, symbols)
    ExtensibleEnum(constrs) => collect_constrs(constrs, tycon, symbols)
    ExtendEnum(constructors~, ..) =>
      for c in constructors {
        symbols.constructors[c.name.name] = tycon
      }
    TupleStruct(_) => symbols.constructors[tycon] = tycon
    Alias(Arrow(args~, ..)) => {
      let tys : Array[IRType?] = []
      for aty in args {
        tys.push(Some(type_to_ir(aty, symbols)))
      }
      symbols.alias_arrows[tycon] = tys
    }
    Alias(_) | Error(_) | Abstract => ()
  }
}

// ── Pass B: inference ─────────────────────────────────────────────────────

///|
priv struct ScanCtx {
  symbols : PkgSymbols
  env : Map[String, IRType] // binder name -> type
  file : String
  stats : IRStatsResult
  // call-site closure backfill channel: set before visiting a Function arg
  pending_closure_hints : Array[IRType?]
  mut last_key : String // receiver key recorded by infer_dot_apply
  mut last_recv_ty : IRType // receiver parametric type (builtin callback hints)
  mut cur_fn : String // enclosing function name (call graph caller)
  pt_constraints : Array[PTConstraint] // per-fn accumulator (sliced at exit)
  pt_pending : Array[PTPending] // D2b: call-site ret/arg bindings consumed at file end
  pt_fn_slices : Array[PTFnSlice] // D2b: stored slices for the feedback fixpoint
  // M4-lite: var-name -> closure allocation site (params/body reference)
  closure_sites : Map[String, ClosureSite]
  mut pending_closure : String? // set by infer_apply, consumed by Apply arm
  // E2: moon.pkg import aliases (alias -> qualified package path)
  pkg_alias : Map[String, String]
}

// D2b: a call-site binding awaiting interprocedural consumption.
// "ret": callee summary ret-sites flow into caller var `var` (inject into
//        owner_fn's slice as PTAlloc). "arg": caller var `var`'s sites flow
//        into the callee's param node `param_node` (inject into callee's
//        slice) — the fn-sig-aligned actual-to-formal edge.

///|
pub(all) struct PTPending {
  kind : String // "ret" | "arg" | "argret"
  pvar : String
  callee : String
  param_node : String
  owner_fn : String
  site : String // "argret": the concrete arg site to inject
}

///|

///|
pub(all) struct PtCarrier {
  slices : Array[PTFnSlice]
  pendings : Array[PTPending]
}

///|
pub(all) struct PTFnSlice {
  fn_name : String
  constraints : Array[PTConstraint]
  site_start : Int
  site_end : Int
}

///|
priv struct ClosureSite {
  line : Int // allocation line (params_loc)
  params : @list.List[@syntax.Parameter]
  body : @syntax.Expr
  has_unannotated : Bool // body walk deferred until first call
  mut rescanned : Bool // one-shot lazy rescan guard
  // T2.5 captures: outer names referenced by the body (declaration-time
  // collection). shared = names whose object is FIELD-MUTATED in the body
  // (reference-shared); the rest are value-copied snapshots.
  captures : Array[String]
  shared_captures : Array[String]
  // declaration-time type snapshot: the rescan re-seeds captured variable
  // types so the body walk resolves receivers even when the call site sits
  // in a scope where the binding has since been shadowed/rebound
  capture_tys : Map[String, IRType]
}

///|
pub fn scan_package_calls(
  impls : Array[@syntax.Impl],
  file : String,
  symbols : PkgSymbols,
  stats : IRStatsResult,
  pkg_alias? : Map[String, String],
  pt_deferred? : Bool = false,
) -> Unit {
  collect_symbols(impls, symbols)
  let ctx : ScanCtx = {
    symbols,
    env: Map([]),
    file,
    stats,
    pending_closure_hints: [],
    last_key: "?",
    last_recv_ty: IRUnresolved,
    cur_fn: "<top>",
    pt_constraints: [],
    pt_pending: [],
    pt_fn_slices: [],
    closure_sites: Map([]),
    pending_closure: None,
    pkg_alias: match pkg_alias {
      Some(m) => m
      None => Map([])
    },
  }
  // seed annotated top-level globals into the env: FFI binding files keep
  // their state in globals (`let ws_handler_map : Map[...] = ...`)
  symbols.globals.each(fn(name, t) { ctx.env[name] = t })
  for item in impls {
    match item {
      TopFuncDef(fun_decl~, decl_body~, ..) => {
        // D2b: qualified caller identity — method-form decls ("fn
        // SelfTy::name") must match the call-site callee key so pt slices
        // and summaries line up ("HttpResponse::body", same as TopImpl)
        ctx.cur_fn = match fun_decl.type_name {
          Some(tn) => type_name_str(tn) + "::" + fun_decl.name.name
          None => fun_decl.name.name
        }
        match decl_body {
          DeclBody(expr=Function(func~, ..)) => {
            stats.funcs_scanned += 1
            scan_func_ctx(func, ctx)
          }
          DeclBody(expr=body) => {
            stats.funcs_scanned += 1
            match fun_decl.decl_params {
              Some(ps) => scan_params_body(ps, body, ctx)
              None => {
                let _ = infer_expr(body, ctx)
              }
            }
          }
          _ => ()
        }
      }
      TopImpl(self_ty~, trait_~, method_name~, params~, body~, ..) => {
        ctx.cur_fn = match self_ty {
          Some(t) => type_to_string(t) + "::" + method_name.name
          None => method_name.name
        }
        // trait-declared signature: backfill unannotated impl params
        let tkey = longident_str(trait_.name) + "::" + method_name.name
        let declared = sig_trait_params(ctx.symbols, tkey)
        let backfill : Array[IRType?] = match declared {
          Some(tys) => tys
          None => []
        }
        let self_ir = match self_ty {
          Some(t) => Some(type_to_ir(t, ctx.symbols))
          None => None
        }
        let hints : Array[IRType?] = []
        let mut i = 0
        for param in params {
          let hint : IRType? = match param {
            Positional(binder~, ty~) | Labelled(binder~, ty~) =>
              match ty {
                Some(_) => None // annotated: no hint needed
                None =>
                  if i == 0 && binder.name == "self" {
                    self_ir
                  } else if i < backfill.length() {
                    backfill[i]
                  } else {
                    None
                  }
              }
            _ => None
          }
          hints.push(hint)
          i += 1
        }
        match body {
          DeclBody(expr=Function(func~, ..)) => {
            stats.funcs_scanned += 1
            scan_params_body(func.parameters, func.body, ctx, hints~)
          }
          DeclBody(expr=body) => {
            stats.funcs_scanned += 1
            scan_params_body(params, body, ctx, hints~)
          }
          _ => ()
        }
      }
      TopExpr(expr~, ..) => {
        let _ = infer_expr(expr, ctx)
      }
      TopTest(expr~, ..) => {
        let _ = infer_expr(expr, ctx)
      }
      TopLetDef(expr~, ..) => {
        let _ = infer_expr(expr, ctx)
      }
      _ => ()
    }
  }
  // E2: batch mode (run_ir_stats/run_call_graph) defers the pt fixpoint
  // to the END of the whole scan — cross-FILE pendings (a caller in
  // not_found.mbt seeding `HttpResponse::body`'s &Responder param, whose
  // dispatch site lives in response.mbt) were previously dropped by the
  // per-file clear. The carrier merges slices+pendings across files and
  // pt_solve_batched runs the worklist once over all of them.
  if pt_deferred {
    pt_carrier_append(ctx, stats)
    return
  }
  pt_solve_all(ctx)
  ctx.pt_fn_slices.clear()
  ctx.pt_pending.clear()
}

///|
fn pt_carrier_append(ctx : ScanCtx, stats : IRStatsResult) -> Unit {
  match stats.pt_carrier {
    Some(car) => {
      for s in ctx.pt_fn_slices {
        car.slices.push(s)
      }
      for p in ctx.pt_pending {
        car.pendings.push(p)
      }
    }
    None => ()
  }
}

///|
pub fn pt_solve_batched(
  stats : IRStatsResult,
  strategy? : ContextStrategy = Insensitive,
) -> Unit {
  match stats.pt_carrier {
    Some(car) => {
      if car.slices.length() == 0 && car.pendings.length() == 0 {
        return
      }
      // merged solve context: slices/pendings from ALL files; symbols are
      // only needed for env typing during the walk (already done) — the
      // fixpoint itself only reads slices, pendings and stats.sites
      let ctx : ScanCtx = {
        symbols: PkgSymbols::new(),
        env: Map([]),
        file: "<batched>",
        stats,
        pending_closure_hints: [],
        last_key: "?",
        last_recv_ty: IRUnresolved,
        cur_fn: "<top>",
        pt_constraints: [],
        pt_pending: car.pendings,
        pt_fn_slices: car.slices,
        closure_sites: Map([]),
        pending_closure: None,
        pkg_alias: Map([]),
      }
      pt_solve_all(ctx, strategy~)
    }
    None => ()
  }
}

///|
fn scan_func_ctx(func : @syntax.Func, ctx : ScanCtx) -> Unit {
  scan_params_body(func.parameters, func.body, ctx)
}

///|
fn scan_params_body(
  params : @list.List[@syntax.Parameter],
  body : @syntax.Expr,
  ctx : ScanCtx,
  hints? : Array[IRType?],
) -> Unit {
  // T4c-2: remember slice boundaries before the walk
  let pt_constraints_start = ctx.pt_constraints.length()
  let sites_start = ctx.stats.sites.length()
  let saved : Array[(String, IRType)] = []
  let hint_arr : Array[IRType?] = match hints {
    Some(h) => h
    None => []
  }
  let mut i = 0
  for param in params {
    match param {
      Positional(binder~, ty~) => {
        bind_param_hinted(binder.name, ty, i, hint_arr, ctx, saved)
        // D2b: formal-param node — call sites alloc into it (fn-sig aligned)
        pt_copy_param(binder.name, ctx)
      }
      Labelled(binder~, ty~) => {
        bind_param_hinted(binder.name, ty, i, hint_arr, ctx, saved)
        pt_copy_param(binder.name, ctx)
      }
      Optional(binder~, default~, ty~) => {
        // T0.2(a): default-argument expressions are executable code —
        // their call sites must enter the analysis graph
        let _ = infer_expr(default, ctx)
        bind_param_hinted(binder.name, ty, i, hint_arr, ctx, saved)
        pt_copy_param(binder.name, ctx)
      }
      QuestionOptional(binder~, ty~) =>
        bind_param_hinted(binder.name, ty, i, hint_arr, ctx, saved)
      DiscardPositional(..) => ()
    }
    i += 1
  }
  let ret_t = infer_expr(body, ctx)
  // D2b: ret-node constraint (summary seed) + slice storage; the file-end
  // fixpoint (pt_solve_all) solves slices, builds summaries, consumes the
  // call-site pendings over feedback rounds, and fills dispatch recv_pt
  pt_emit_ret(body, ret_t, ctx)
  pt_store_slice(ctx, pt_constraints_start, sites_start)
  restore_env(saved, ctx)
}

///|
// ── M4-lite: closure allocation sites ─────────────────────────────────────

///|
fn closure_has_unannotated(params : @list.List[@syntax.Parameter]) -> Bool {
  let mut found = false
  for param in params {
    match param {
      Positional(ty~, ..) | Labelled(ty~, ..) =>
        match ty {
          None => found = true
          Some(_) => ()
        }
      _ => ()
    }
  }
  found
}

///|
fn register_closure(
  var_name : String,
  func : @syntax.Func,
  ctx : ScanCtx,
) -> Bool {
  // returns true when the body walk should be DEFERRED to the first call
  let unannotated = closure_has_unannotated(func.parameters)
  // T2.5: declaration-time capture collection (value-copy vs shared)
  let param_names : Array[String] = []
  for p in func.parameters {
    match p {
      Positional(binder~, ..)
      | Labelled(binder~, ..)
      | Optional(binder~, ..)
      | QuestionOptional(binder~, ..) => param_names.push(binder.name)
      DiscardPositional(..) => ()
    }
  }
  let idents : Array[String] = []
  collect_idents(func.body, idents)
  let muts : Array[String] = []
  collect_mutate_receivers(func.body, muts)
  let caps : Array[String] = []
  for n in idents {
    if !param_names.contains(n) && !caps.contains(n) {
      caps.push(n)
    }
  }
  let shared : Array[String] = []
  for n in muts {
    if caps.contains(n) && !shared.contains(n) {
      shared.push(n)
    }
  }
  let ctys : Map[String, IRType] = Map([])
  for n in caps {
    match ctx.env.get(n) {
      Some(t) => ctys[n] = t
      None => ()
    }
  }
  ctx.closure_sites[var_name] = {
    line: func.params_loc.start.lnum,
    params: func.parameters,
    body: func.body,
    has_unannotated: unannotated,
    rescanned: false,
    captures: caps,
    shared_captures: shared,
    capture_tys: ctys,
  }
  unannotated
}

///|
fn rescan_closure(
  name : String,
  args : @list.List[@syntax.Argument],
  ctx : ScanCtx,
) -> Unit {
  let site = match ctx.closure_sites.get(name) {
    Some(s) => s
    None => return
  }
  if site.rescanned {
    return // one-shot: first call site's argument types win
  }
  site.rescanned = true
  // T2.5: re-seed declaration-time capture types (R4/R3 scoping can have
  // shadowed the original binding between creation and this call site)
  for n in site.captures {
    match site.capture_tys.get(n) {
      Some(t) => if ctx.env.get(n) == None { ctx.env[n] = t }
      None => ()
    }
  }
  if !site.has_unannotated {
    return // body was already walked at allocation with known param types
  }
  // compute call-site argument types WITHOUT counting stats
  // (args are counted once by visit_args in the Apply arm)
  let arg_tys : Array[IRType] = []
  let s0 = snapshot_stats(ctx.stats)
  for arg in args {
    arg_tys.push(infer_expr(arg.value, ctx))
  }
  restore_stats(ctx.stats, s0)
  // walk the closure body once with backfilled param types (stats ON)
  let saved : Array[(String, IRType)] = []
  let mut i = 0
  for param in site.params {
    match param {
      Positional(binder~, ty~) | Labelled(binder~, ty~) => {
        saved.push((binder.name, or_unresolved(ctx.env.get(binder.name))))
        match ty {
          Some(t) => ctx.env[binder.name] = type_to_ir(t, ctx.symbols)
          None => {
            let at = if i < arg_tys.length() {
              arg_tys[i]
            } else {
              IRUnresolved
            }
            ctx.env[binder.name] = at
          }
        }
      }
      Optional(binder~, ty~, ..) | QuestionOptional(binder~, ty~) => {
        saved.push((binder.name, or_unresolved(ctx.env.get(binder.name))))
        match ty {
          Some(t) => ctx.env[binder.name] = type_to_ir(t, ctx.symbols)
          None => ctx.env[binder.name] = IRUnresolved
        }
      }
      DiscardPositional(..) => ()
    }
    i += 1
  }
  let _ = infer_expr(site.body, ctx)
  restore_env(saved, ctx)
}

///|
priv struct StatsSnapshot {
  files_scanned : Int
  funcs_scanned : Int
  total_calls : Int
  static_calls : Int
  static_resolved : Int
  receiver_calls : Int
  receiver_resolved : Int
  receiver_dispatch : Int
  receiver_unknown : Int
  higher_calls : Int
  sites_len : Int
}

///|
fn snapshot_stats(stats : IRStatsResult) -> StatsSnapshot {
  {
    files_scanned: stats.files_scanned,
    funcs_scanned: stats.funcs_scanned,
    total_calls: stats.total_calls,
    static_calls: stats.static_calls,
    static_resolved: stats.static_resolved,
    receiver_calls: stats.receiver_calls,
    receiver_resolved: stats.receiver_resolved,
    receiver_dispatch: stats.receiver_dispatch,
    receiver_unknown: stats.receiver_unknown,
    higher_calls: stats.higher_calls,
    sites_len: stats.sites.length(),
  }
}

///|
fn restore_stats(stats : IRStatsResult, snap : StatsSnapshot) -> Unit {
  stats.files_scanned = snap.files_scanned
  stats.funcs_scanned = snap.funcs_scanned
  stats.total_calls = snap.total_calls
  stats.static_calls = snap.static_calls
  stats.static_resolved = snap.static_resolved
  stats.receiver_calls = snap.receiver_calls
  stats.receiver_resolved = snap.receiver_resolved
  stats.receiver_dispatch = snap.receiver_dispatch
  stats.receiver_unknown = snap.receiver_unknown
  stats.higher_calls = snap.higher_calls
  while stats.sites.length() > snap.sites_len {
    let _ = stats.sites.pop()
  }
}

///|
fn bind_param_hinted(
  name : String,
  ty : @syntax.Type?,
  idx : Int,
  hints : Array[IRType?],
  ctx : ScanCtx,
  saved : Array[(String, IRType)],
) -> Unit {
  saved.push((name, or_unresolved(ctx.env.get(name))))
  match ty {
    Some(t) => ctx.env[name] = type_to_ir(t, ctx.symbols)
    None => {
      let hint : IRType? = if idx < hints.length() { hints[idx] } else { None }
      match hint {
        Some(t) => ctx.env[name] = t
        None => ctx.env[name] = IRUnresolved
      }
    }
  }
}

///|
fn bind_params(
  params : @list.List[@syntax.Parameter],
  ctx : ScanCtx,
  saved : Array[(String, IRType)],
) -> Unit {
  for param in params {
    match param {
      Positional(binder~, ty~) => bind_param(binder.name, ty, ctx, saved)
      Labelled(binder~, ty~) => bind_param(binder.name, ty, ctx, saved)
      Optional(binder~, ty~, ..) => bind_param(binder.name, ty, ctx, saved)
      QuestionOptional(binder~, ty~) => bind_param(binder.name, ty, ctx, saved)
      DiscardPositional(..) => ()
    }
  }
}

///|
fn bind_param(
  name : String,
  ty : @syntax.Type?,
  ctx : ScanCtx,
  saved : Array[(String, IRType)],
) -> Unit {
  saved.push((name, or_unresolved(ctx.env.get(name))))
  match ty {
    Some(t) => ctx.env[name] = type_to_ir(t, ctx.symbols)
    None => ctx.env[name] = IRUnresolved
  }
}

///|
fn or_unresolved(v : IRType?) -> IRType {
  match v {
    Some(t) => t
    None => IRUnresolved
  }
}

///|
fn restore_env(saved : Array[(String, IRType)], ctx : ScanCtx) -> Unit {
  for pair in saved {
    ctx.env[pair.0] = pair.1
  }
}

// ── Source-type conversion ────────────────────────────────────────────────

///|
pub fn type_to_ir(ty : @syntax.Type, symbols : PkgSymbols) -> IRType {
  match ty {
    Any(..) => IRUnresolved
    Arrow(..) => IRFn("?")
    Tuple(..) => IRConcrete("Tuple", [])
    Option(ty~, ..) => type_to_ir(ty, symbols)
    Object(cid) => {
      // `&Alpha` parses as Object(ConstrId(Ident("Alpha"))): a reference/
      // trait-object type. Map to IRTraitObj when Alpha is a declared trait
      // (local TopTrait or .mbti TraitSig); otherwise stay unresolved.
      let name = longident_str(cid.id)
      if symbols.trait_names.contains(name) {
        IRTraitObj(name)
      } else {
        IRUnresolved
      }
    }
    Name(constr_id~, tys~, ..) => {
      let name = longident_str(constr_id.id)
      if symbols.type_params.contains(name) {
        IRTypeParam(name)
        // keep generic args so element types survive (Array[String] etc.)
      } else if tys.length() > 0 {
        let args : Array[IRType] = []
        for ty in tys {
          args.push(type_to_ir(ty, symbols))
        }
        IRConcrete(name, args)
      } else {
        IRConcrete(name, [])
      }
    }
  }
}

///|
fn longident_str(id : @syntax.LongIdent) -> String {
  match id {
    Ident(name~) => name
    Dot(pkg~, id~) => pkg + "::" + id
  }
}

///|
fn type_name_str(tn : @syntax.TypeName) -> String {
  longident_str(tn.name)
}

///|
fn type_to_string(ty : @syntax.Type) -> String {
  match ty {
    Any(..) => "?"
    Arrow(..) => "fn"
    Tuple(..) => "Tuple"
    Option(ty~, ..) => type_to_string(ty)
    Object(cid) => longident_str(cid.id)
    Name(constr_id~, ..) => longident_str(constr_id.id)
  }
}

// ── Expression inference (bottom-up, local) ───────────────────────────────

///|
fn infer_expr(expr : @syntax.Expr, ctx : ScanCtx) -> IRType {
  match expr {
    Constant(c~, ..) => const_type(c)
    Unit(..) => IRUnit
    MultilineString(elems~, ..) => {
      for elem in elems {
        match elem {
          Interp(list) =>
            for ie in list {
              match ie {
                Expr(expr~, ..) => {
                  let _ = infer_expr(expr, ctx)
                }
                _ => ()
              }
            }
          _ => ()
        }
      }
      IRConcrete("String", [])
    }
    Interp(elems~, ..) => {
      for elem in elems {
        match elem {
          Expr(expr~, ..) => {
            let _ = infer_expr(expr, ctx)
          }
          _ => ()
        }
      }
      IRConcrete("String", [])
    }
    BytesInterp(..) => IRConcrete("Bytes", [])
    Ident(id~, ..) => lookup_ident(id.name, ctx)
    Method(type_name~, method_name~, ..) => {
      let key = type_name_str(type_name) + "::" + method_name.name
      or_unresolved(get_fn_ret(ctx.symbols, key))
    }
    Apply(func~, args~, ..) => {
      let ret = infer_apply(func, ctx)
      let key = callee_key(func)
      visit_args(args, key, ctx, 0)
      // closure call: lazy body rescan with call-site argument types
      match ctx.pending_closure {
        Some(cname) => {
          ctx.pending_closure = None
          rescan_closure(cname, args, ctx)
        }
        None => ()
      }
      ret
    }
    DotApply(self~, method_name~, args~, ..) => {
      let ret = infer_dot_apply(self, method_name.name, ctx)
      visit_args(args, ctx.last_key, ctx, 1) // slot 0 = receiver
      ret
    }
    Infix(lhs~, rhs~, ..) => {
      let lt = infer_expr(lhs, ctx)
      let rt = infer_expr(rhs, ctx)
      if is_stringy(lt) || is_stringy(rt) {
        IRConcrete("String", [])
      } else {
        // numeric arithmetic: Int/Double/UInt operands propagate their type
        // (prevents cascades like `(h1 * 16 + h2).to_byte()` losing Int)
        match (lt, rt) {
          (IRConcrete(n, _), _) =>
            if is_numeric_ty(n) {
              lt
            } else {
              numeric_join(lt, rt)
            }
          (_, IRConcrete(n, _)) =>
            if is_numeric_ty(n) {
              rt
            } else {
              numeric_join(lt, rt)
            }
          _ => IRUnresolved
        }
      }
    }
    Unary(expr~, ..) => infer_expr(expr, ctx)
    Array(exprs~, ..) => {
      let mut elem : IRType = IRUnresolved
      let mut first = true
      for e in exprs {
        let t = infer_expr(e, ctx)
        if first {
          elem = t
          first = false
        }
      }
      IRConcrete("Array", [elem])
    }
    ArraySpread(elems~, ..) => {
      for elem in elems {
        match elem {
          Regular(e) => {
            let _ = infer_expr(e, ctx)
          }
          Spread(expr~, ..) => {
            let _ = infer_expr(expr, ctx)
          }
        }
      }
      IRConcrete("Array", [])
    }
    ArrayGet(array~, index~, ..) => {
      let t = infer_expr(array, ctx)
      let _ = infer_expr(index, ctx)
      t
    }
    ArrayGetSlice(array~, start_index~, end_index~, ..) => {
      let t = infer_expr(array, ctx)
      let _ = start_index.map(fn(e) { infer_expr(e, ctx) })
      let _ = end_index.map(fn(e) { infer_expr(e, ctx) })
      t
    }
    ArraySet(array~, index~, value~, ..) => {
      let _ = infer_expr(array, ctx)
      let _ = infer_expr(index, ctx)
      let _ = infer_expr(value, ctx)
      IRUnit
    }
    ArrayAugmentedSet(array~, index~, value~, ..) => {
      let _ = infer_expr(array, ctx)
      let _ = infer_expr(index, ctx)
      let _ = infer_expr(value, ctx)
      IRUnit
    }
    ListComprehension(guard_~, body~, ..) => {
      let _ = guard_.map(fn(e) { infer_expr(e, ctx) })
      let _ = infer_expr(body, ctx)
      IRConcrete("Array", [])
    }
    Constraint(expr~, ty~, ..) => {
      let _ = infer_expr(expr, ctx)
      type_to_ir(ty, ctx.symbols)
    }
    Constr(constr~, ..) =>
      match ctx.symbols.constructors.get(constr.name.name) {
        Some(tyname) => IRConcrete(tyname, [])
        None => IRUnresolved
      }
    LabelledBlock(body~, ..) => infer_expr(body, ctx)
    While(loop_cond~, loop_body~, ..) => {
      let _ = infer_expr(loop_cond, ctx)
      let _ = infer_expr(loop_body, ctx)
      IRUnit
    }
    Function(func~, ..) => {
      let saved : Array[(String, IRType)] = []
      // consume call-site closure hints (see visit_args)
      let hints = ctx.pending_closure_hints.copy()
      ctx.pending_closure_hints.clear()
      let mut i = 0
      for param in func.parameters {
        match param {
          Positional(binder~, ty~) =>
            bind_param_hinted(binder.name, ty, i, hints, ctx, saved)
          Labelled(binder~, ty~) =>
            bind_param_hinted(binder.name, ty, i, hints, ctx, saved)
          Optional(binder~, default~, ty~) => {
            // T0.2(a): default-argument expressions enter the graph
            let _ = infer_expr(default, ctx)
            bind_param_hinted(binder.name, ty, i, hints, ctx, saved)
          }
          QuestionOptional(binder~, ty~) =>
            bind_param_hinted(binder.name, ty, i, hints, ctx, saved)
          DiscardPositional(..) => ()
        }
        i += 1
      }
      let _ = infer_expr(func.body, ctx)
      restore_env(saved, ctx)
      IRFn("$closure")
    }
    If(cond~, ifso~, ifnot~, ..) => {
      let _ = infer_expr(cond, ctx)
      let _ = ifnot.map(fn(e) { infer_expr(e, ctx) })
      infer_expr(ifso, ctx)
    }
    Guard(cond~, body~, ..) => {
      let _ = infer_expr(cond, ctx)
      infer_expr(body, ctx)
    }
    Is(expr~, pat~, ..) => {
      let t = infer_expr(expr, ctx)
      // `x is String(v)` binds v : String when the type-test constructor is a
      // builtin primitive test — the tested scrutinee type is not needed
      bind_is_pattern(pat, ctx)
      ignore(t)
      IRConcrete("Bool", [])
    }
    RegexMatch(expr~, bindings~, ..) => {
      let t = infer_expr(expr, ctx)
      // regex captures and `after=` remainders are strings
      for binding in bindings {
        match binding.1 {
          Some(binder) => ctx.env[binder.name] = IRConcrete("String", [])
          None =>
            // label-only binding (`as name`): bind by label name
            ctx.env[binding.0.name] = IRConcrete("String", [])
        }
      }
      match t {
        IRConcrete("String", _) | IRConcrete("StringView", _) =>
          IRConcrete("Bool", [])
        _ => IRUnresolved
      }
    }
    Defer(expr~, body~, ..) => {
      let _ = infer_expr(expr, ctx)
      infer_expr(body, ctx)
    }
    LetFn(name~, func~, body~, ..) => {
      // E2: register local fn as closure allocation site (mirror LetAnd):
      // unannotated bodies defer to first call site for param backfill
      let nm = name.name
      let defer_body = register_closure(nm, func, ctx)
      if !defer_body {
        scan_func_ctx(func, ctx)
      }
      let saved : Array[(String, IRType)] = []
      saved.push((nm, or_unresolved(ctx.env.get(nm))))
      ctx.env[nm] = IRFn(nm)
      let t = infer_expr(body, ctx)
      restore_env(saved, ctx)
      t
    }
    LetAnd(bindings~, body~, ..) => {
      let saved : Array[(String, IRType)] = []
      for binding in bindings {
        let (binder, ty, func) = binding
        let defer_body = register_closure(binder.name, func, ctx)
        if !defer_body {
          let fsaved : Array[(String, IRType)] = []
          bind_params(func.parameters, ctx, fsaved)
          let _ = infer_expr(func.body, ctx)
          restore_env(fsaved, ctx)
        }
        saved.push((binder.name, or_unresolved(ctx.env.get(binder.name))))
        match ty {
          Some(t) => ctx.env[binder.name] = type_to_ir(t, ctx.symbols)
          None => ctx.env[binder.name] = IRFn(binder.name)
        }
      }
      let t = infer_expr(body, ctx)
      restore_env(saved, ctx)
      t
    }
    Let(pattern~, expr~, body~, ..) => {
      // closure allocation site: `let h = fn(...) { ... }`
      let closure_case = match (pattern, expr) {
        (Var(binder), Function(func~, ..)) => {
          let defer_body = register_closure(binder.name, func, ctx)
          let t = if defer_body {
            IRFn("$defer") // body walked lazily at first call site
          } else {
            infer_expr(expr, ctx)
          }
          ctx.env[binder.name] = t
          true
        }
        _ => false
      }
      if !closure_case {
        let t = infer_expr(expr, ctx)
        bind_pattern(pattern, t, ctx)
        pt_emit_binding(pattern, expr, t, ctx)
      } else {
        // E2: closure-value bindings ALSO enter the pt graph — allocation
        // site for the closure object + "cap:<name>" stores for captured
        // outer idents (this branch bypasses pt_emit_binding above)
        match (pattern, expr) {
          (Var(binder), Function(func~, ..)) => {
            let v = binder.name
            let pname : Array[String] = []
            for p in func.parameters {
              match p {
                Positional(binder~, ..) => pname.push(binder.name)
                Labelled(binder~, ..) => pname.push(binder.name)
                Optional(binder~, ..) => pname.push(binder.name)
                QuestionOptional(binder~, ..) => pname.push(binder.name)
                DiscardPositional(..) => ()
              }
            }
            ctx.pt_constraints.push(PTAlloc(v, "$closure@" + v))
            let caps : Array[String] = []
            collect_idents(func.body, caps)
            for n in caps {
              if !pname.contains(n) &&
                ctx.env.contains(n) &&
                !pt_slice_has_store(ctx, v, "cap:" + n) {
                ctx.pt_constraints.push(PTStore(v, "cap:" + n, n))
              }
            }
          }
          _ => ()
        }
      }
      infer_expr(body, ctx)
    }
    LetMut(binder~, ty~, expr~, body~, ..) => {
      let t = infer_expr(expr, ctx)
      match ty {
        Some(t2) => ctx.env[binder.name] = type_to_ir(t2, ctx.symbols)
        None => ctx.env[binder.name] = t
      }
      pt_emit_binding(
        Var(binder),
        expr,
        ctx.env.get(binder.name) |> or_unresolved,
        ctx,
      )
      infer_expr(body, ctx)
    }
    Sequence(exprs~, last_expr~, ..) => {
      for e in exprs {
        let _ = infer_expr(e, ctx)
      }
      infer_expr(last_expr, ctx)
    }
    Tuple(exprs~, ..) => {
      let args : Array[IRType] = []
      for e in exprs {
        args.push(infer_expr(e, ctx))
      }
      IRConcrete("Tuple", args)
    }
    Record(type_name~, fields~, ..) => {
      for field in fields {
        let _ = infer_expr(field.expr, ctx)
      }
      match type_name {
        Some(tn) => IRConcrete(type_name_str(tn), [])
        None => IRUnresolved
      }
    }
    RecordUpdate(type_name~, record~, fields~, ..) => {
      let t = infer_expr(record, ctx)
      for field in fields {
        let _ = infer_expr(field.expr, ctx)
      }
      match type_name {
        Some(tn) => IRConcrete(type_name_str(tn), [])
        None => t
      }
    }
    Field(record~, accessor~, ..) => {
      let t = infer_expr(record, ctx)
      match (t, accessor) {
        (IRConcrete(name, _), Label(l)) =>
          match get_struct_fields(ctx.symbols, name) {
            Some(fields) =>
              match fields.get(l.name) {
                Some(ft) => ft
                None => IRUnresolved
              }
            None => IRUnresolved
          }
        _ => IRUnresolved
      }
    }
    As(expr~, trait_~, ..) => {
      let _ = infer_expr(expr, ctx)
      IRTraitObj(longident_str(trait_.name))
    }
    Mutate(record~, field~, ..) => {
      let _ = infer_expr(record, ctx)
      let _ = infer_expr(field, ctx)
      IRUnit
    }
    Match(expr~, cases~, ..) => {
      let scrut_ty = infer_expr(expr, ctx)
      let mut result_ty : IRType = IRUnresolved
      let mut first = true
      for case in cases {
        bind_pattern(case.pattern, scrut_ty, ctx)
        let _ = case.guard_.map(fn(e) { infer_expr(e, ctx) })
        let t = infer_expr(case.body, ctx)
        if first {
          result_ty = t
          first = false
        }
      }
      result_ty
    }
    LexMatch(expr~, cases~, ..) => {
      let _ = infer_expr(expr, ctx)
      for case in cases {
        let _ = infer_expr(case.body, ctx)
      }
      IRUnresolved
    }
    LexScan(expr~, cases~, ..) => {
      let _ = infer_expr(expr, ctx)
      for case in cases {
        let _ = infer_expr(case.body, ctx)
      }
      IRUnresolved
    }
    Pipe(lhs~, rhs~, ..) => {
      let _ = infer_expr(lhs, ctx)
      infer_expr(rhs, ctx)
    }
    RevPipe(lhs~, rhs~, ..) => {
      let _ = infer_expr(lhs, ctx)
      infer_expr(rhs, ctx)
    }
    Assign(var_~, expr~, ..) => {
      let t = infer_expr(expr, ctx)
      ctx.env[longident_str(var_.name)] = t
      IRUnit
    }
    Hole(..) => IRUnresolved
    Return(return_value~, ..) => {
      let _ = return_value.map(fn(e) { infer_expr(e, ctx) })
      IRUnit
    }
    Raise(err_value~, ..) => {
      let _ = infer_expr(err_value, ctx)
      IRUnit
    }
    Quantifier(binder~, binder_ty~, body~, ..) => {
      let saved : Array[(String, IRType)] = []
      saved.push((binder.name, or_unresolved(ctx.env.get(binder.name))))
      ctx.env[binder.name] = type_to_ir(binder_ty, ctx.symbols)
      let t = infer_expr(body, ctx)
      restore_env(saved, ctx)
      t
    }
    Implies(lhs~, rhs~, ..) => {
      let _ = infer_expr(lhs, ctx)
      infer_expr(rhs, ctx)
    }
    ProofAssert(..) => IRUnresolved
    ProofLet(expr~, ..) => infer_expr(expr, ctx)
    Break(arg~, ..) => {
      let _ = arg.map(fn(e) { infer_expr(e, ctx) })
      IRUnit
    }
    Continue(..) => IRUnit
    For(binders~, continue_block~, body~, ..) => {
      for pair in binders {
        let _ = infer_expr(pair.1, ctx)
      }
      for pair in continue_block {
        let _ = infer_expr(pair.1, ctx)
      }
      let _ = infer_expr(body, ctx)
      IRUnit
    }
    ForEach(binders~, expr~, init~, continue_block~, body~, ..) => {
      let iter_ty = infer_expr(expr, ctx)
      let ety = elem_type(iter_ty)
      // E2: minimal container model — iterating an Ident loads through the
      // "elem" pseudo-field (Array literal bindings store into it), so the
      // loop var inherits the elements' pointees
      match expr {
        Ident(id~, ..) =>
          match id.name {
            Ident(name~) => {
              let iter_name = name
              for b in binders {
                match b {
                  Some(binder) =>
                    ctx.pt_constraints.push(
                      PTLoad(binder.name, iter_name, "elem"),
                    )
                  None => ()
                }
              }
            }
            Dot(..) => ()
          }
        _ => ()
      }
      for b in binders {
        match b {
          Some(binder) => ctx.env[binder.name] = ety
          None => ()
        }
      }
      for pair in init {
        let _ = infer_expr(pair.1, ctx)
      }
      for pair in continue_block {
        let _ = infer_expr(pair.1, ctx)
      }
      let _ = infer_expr(body, ctx)
      IRUnit
    }
    Try(body~, catch_~, try_else~, ..) => {
      let t = infer_expr(body, ctx)
      for case in catch_ {
        let _ = infer_expr(case.body, ctx)
      }
      // noraise arm: runs on success; its pattern binds the SUCCESS value —
      // without this, calls inside the success branch never enter the call
      // graph (third review)
      match try_else {
        Some(arms) =>
          for case in arms {
            bind_pattern(case.pattern, t, ctx)
            let _ = infer_expr(case.body, ctx)
          }
        None => ()
      }
      t
    }
    TryOperator(body~, ..) => infer_expr(body, ctx)
    Map(..) => IRConcrete("Map", [])
    Group(expr~, ..) => infer_expr(expr, ctx)
    TemplateWriting(expr~, template~, ..) => {
      let _ = infer_expr(expr, ctx)
      infer_expr(template, ctx)
    }
    StaticAssert(..) => IRUnit
  }
}

///|

///|
fn const_type(c : @syntax.Constant) -> IRType {
  match c {
    Int(_) => IRConcrete("Int", [])
    UInt(_) => IRConcrete("UInt", [])
    Int64(_) => IRConcrete("Int64", [])
    UInt64(_) => IRConcrete("UInt64", [])
    Float(_) | Double(_) => IRConcrete("Double", [])
    String(_) => IRConcrete("String", [])
    Char(_) => IRConcrete("Char", [])
    Bytes(_) | Byte(_) => IRConcrete("Bytes", [])
    Bool(_) => IRConcrete("Bool", [])
    Regex(_) => IRConcrete("Regex", [])
    BigInt(_) => IRConcrete("BigInt", [])
  }
}

///|
fn lookup_ident(id : @syntax.LongIdent, ctx : ScanCtx) -> IRType {
  match id {
    Ident(name~) =>
      // local binding first, then .mbti-declared const/value types
      match ctx.env.get(name) {
        Some(t) => t
        None => or_unresolved(ctx.symbols.value_types.get(name))
      }
    Dot(..) => IRUnresolved
  }
}

// Bind pattern binders to a best-effort type.

///|
fn bind_pattern(pat : @syntax.Pattern, ty : IRType, ctx : ScanCtx) -> Unit {
  match pat {
    Any(..) => ()
    Var(binder) => ctx.env[binder.name] = ty
    Alias(pat~, alias_~, ..) => {
      bind_pattern(pat, ty, ctx)
      ctx.env[alias_.name] = ty
    }
    Constraint(pat~, ty~, ..) =>
      bind_pattern(pat, type_to_ir(ty, ctx.symbols), ctx)
    Tuple(pats~, ..) => {
      // positional destructure from a known Tuple type (e.g. `for pair in map`)
      let mut i = 0
      for p in pats {
        let pt = match ty {
          IRConcrete("Tuple", args) =>
            if i < args.length() {
              args[i]
            } else {
              IRUnresolved
            }
          _ => IRUnresolved
        }
        bind_pattern(p, pt, ctx)
        i += 1
      }
    }
    Constr(constr~, args~, ..) =>
      match args {
        Some(list) => {
          // payload types: local enum decl first, then builtin Some/Ok/Err
          let payload : Array[IRType] = match
            ctx.symbols.constr_params.get(constr.name.name) {
            Some(tys) => tys
            None => builtin_constr_payload(constr.name.name, ty)
          }
          let mut i = 0
          for arg in list {
            let pt = if i < payload.length() {
              payload[i]
            } else {
              IRUnresolved
            }
            bind_pattern(arg.pat, pt, ctx)
            i += 1
          }
        }
        None => ()
      }
    SpecialConstr(binder~, args~, ..) => {
      ctx.env[binder.name] = IRUnresolved
      for arg in args {
        bind_pattern(arg.pat, IRUnresolved, ctx)
      }
    }
    Record(fields~, ..) =>
      for fp in fields {
        bind_pattern(fp.pattern, IRUnresolved, ctx)
      }
    Or(pat1~, pat2~, ..) => {
      bind_pattern(pat1, ty, ctx)
      bind_pattern(pat2, ty, ctx)
    }
    With(pat~, bindings~, ..) => {
      bind_pattern(pat, ty, ctx)
      for binding in bindings {
        ctx.env[binding.0.name] = IRUnresolved
      }
    }
    Array(pats~, ..) =>
      match pats {
        Closed(list) =>
          for ap in list {
            bind_array_pat(ap, ctx)
          }
        Open(before, after, _) => {
          for ap in before {
            bind_array_pat(ap, ctx)
          }
          for ap in after {
            bind_array_pat(ap, ctx)
          }
        }
      }
    Constant(..) | Map(..) | Range(..) => ()
  }
}

///|
fn bind_array_pat(ap : @syntax.ArrayPattern, ctx : ScanCtx) -> Unit {
  match ap {
    Pattern(p) => bind_pattern(p, IRUnresolved, ctx)
    ConstSpread(binder~, ..) => ctx.env[binder.name] = IRUnresolved
    _ => ()
  }
}

// ── Call-site classification ──────────────────────────────────────────────

///|
fn callee_key(func : @syntax.Expr) -> String {
  match func {
    Method(type_name~, method_name~, ..) =>
      type_name_str(type_name) + "::" + method_name.name
    Ident(id~, ..) => longident_str(id.name)
    _ => "?"
  }
}

///|
fn visit_args(
  args : @list.List[@syntax.Argument],
  callee : String,
  ctx : ScanCtx,
  start_index : Int,
) -> Unit {
  let arrows = sig_arrow_args(ctx.symbols, callee)
  // builtin higher-order fallback: closure hints from the receiver's
  // parametric type (Map::each -> (K, V), Array::map -> (elem), ...)
  let builtin_cb = builtin_callback_params(ctx.last_recv_ty, callee)
  // library-model callbacks (A2): placeholders resolved from receiver args
  let lib_cb = lib_callback_params(ctx, callee)
  // D2b: argret pendings — a positional arg that IS a concrete value
  // (string/int constant) or a direct call with a concrete declared ret
  // seeds the callee's formal param node (the real-corpus shape is
  // `res.body("Not Found")` where body : &Responder and String impls it)
  let argret_sig : Array[FnP] = match ctx.symbols.fn_sigs.get(callee) {
    Some(sig) => sig.params
    None => []
  }
  let mut i = start_index
  for arg in args {
    let positional = match arg.kind {
      Positional => true
      _ => false
    }
    if positional && argret_sig.length() > 0 {
      let pidx = if i < argret_sig.length() { i } else { -1 }
      if pidx >= 0 {
        let pname = argret_sig[pidx].binder
        if pname != "" && pname != "_" {
          let site : String = match arg.value {
            Constant(c~, ..) =>
              match const_type(c) {
                IRConcrete(n, _) => n
                _ => ""
              }
            Apply(func~, ..) =>
              match apply_func_name(func) {
                Some(cn) =>
                  match get_fn_ret(ctx.symbols, cn) {
                    Some(IRConcrete(n, _)) => n
                    _ => ""
                  }
                None => ""
              }
            _ => ""
          }
          if site != "" {
            ctx.pt_pending.push({
              kind: "argret",
              pvar: "",
              callee,
              param_node: "fn@" + callee + ".param:" + pname,
              owner_fn: callee,
              site,
            })
          }
        }
      }
    }
    match arg.value {
      Function(..) => {
        // set closure hints from the callee's declared arrow type,
        // or from the builtin container callback signature
        ctx.pending_closure_hints.clear()
        match arrows {
          Some(per_param) =>
            if i < per_param.length() {
              for h in per_param[i] {
                ctx.pending_closure_hints.push(h)
              }
            } else {
              fill_builtin_cb(ctx, builtin_cb, start_index)
            }
          None => {
            fill_builtin_cb(ctx, builtin_cb, start_index)
            fill_builtin_cb(ctx, lib_cb, start_index)
          }
        }
        let _ = infer_expr(arg.value, ctx)
        ctx.pending_closure_hints.clear()
      }
      _ => {
        let _ = infer_expr(arg.value, ctx)
      }
    }
    i += 1
  }
}

///|
fn fill_builtin_cb(
  ctx : ScanCtx,
  builtin_cb : Array[Array[IRType?]]?,
  start_index : Int,
) -> Unit {
  match builtin_cb {
    Some(per_param) =>
      if start_index < per_param.length() {
        for h in per_param[start_index] {
          ctx.pending_closure_hints.push(h)
        }
      }
    None => ()
  }
}

///|
fn builtin_callback_params(
  recv : IRType,
  callee : String,
) -> Array[Array[IRType?]]? {
  // callback signatures of builtin higher-order methods, derived from the
  // receiver's parametric type. Slot 0 = receiver, so callers index with
  // the same start_index convention as fn_param_arrows.
  let mname = last_segment(callee)
  let ho = match recv {
    IRConcrete("Map", args) => {
      let k = if args.length() >= 1 { args[0] } else { IRUnresolved }
      let v = if args.length() >= 2 { args[1] } else { IRUnresolved }
      // per-arg-slot callback signatures: slot 0 = receiver, slot 1 = closure
      match mname {
        "each" | "eachi" | "map" | "filter" | "any" | "all" | "contains_kv" =>
          [[None], [Some(k), Some(v)]]
        "fold" => [[None], [Some(v), Some(k)]]
        _ => []
      }
    }
    IRConcrete("Array", args) | IRConcrete("Iter", args) => {
      let e = if args.length() >= 1 { args[0] } else { IRUnresolved }
      match mname {
        "each"
        | "eachi"
        | "map"
        | "filter"
        | "find"
        | "find_index"
        | "any"
        | "all"
        | "exists"
        | "collect"
        | "filter_map" => [[None], [Some(e)]]
        "fold" | "reduce" | "sort_by" => [[None], [Some(e), Some(e)]]
        _ => []
      }
    }
    _ => []
  }
  if ho.length() > 0 {
    Some(ho)
  } else {
    None
  }
}

///|
fn infer_apply(func : @syntax.Expr, ctx : ScanCtx) -> IRType {
  match func {
    Method(type_name~, method_name~, ..) => {
      let key = type_name_str(type_name) + "::" + method_name.name
      let confirmed = get_impl_method(ctx.symbols, key) != None ||
        ctx.symbols.fn_exists.contains(key) ||
        ctx.symbols.fn_exists.contains(short_key(key))
      record_site(ctx, func, "static", confirmed, key)
      ctx.stats.total_calls += 1
      ctx.stats.static_calls += 1
      if confirmed {
        ctx.stats.static_resolved += 1
      }
      match builtin_static_ret(key) {
        Some(t) => t
        None => or_unresolved(get_fn_ret(ctx.symbols, key))
      }
    }
    Constr(constr~, ..) => {
      // `Map([...])` etc.: constructor-style application
      let name = constr.name.name
      ctx.stats.total_calls += 1
      ctx.stats.static_calls += 1
      let known = ctx.symbols.constructors.contains(name) ||
        builtin_ctor_ret(name) != None
      if known {
        ctx.stats.static_resolved += 1
      }
      record_site(ctx, func, "static", known, name)
      match builtin_ctor_ret(name) {
        Some(t) => t
        None =>
          match ctx.symbols.constructors.get(name) {
            Some(tyname) => IRConcrete(tyname, [])
            None => IRUnresolved
          }
      }
    }
    Ident(id~, ..) => {
      let name = longident_str(id.name)
      match ctx.env.get(name) {
        Some(IRFn(_)) =>
          // var-bound closure call: resolve to its allocation site
          match ctx.closure_sites.get(name) {
            Some(site) => {
              let target = "$closure:" +
                name +
                "@" +
                site.line.to_string() +
                // T2.5: mark reference-shared captures in the edge label
                (if site.shared_captures.length() > 0 {
                  "(shared:" + site.shared_captures.length().to_string() + ")"
                } else {
                  ""
                })
              record_site(ctx, func, "static", true, target)
              ctx.stats.total_calls += 1
              ctx.stats.static_calls += 1
              ctx.stats.static_resolved += 1
              ctx.pending_closure = Some(name)
              IRUnresolved
            }
            None => {
              record_site(ctx, func, "higher", false, name)
              ctx.stats.total_calls += 1
              ctx.stats.higher_calls += 1
              IRUnresolved
            }
          }
        Some(_) => {
          record_site(ctx, func, "higher", false, name)
          ctx.stats.total_calls += 1
          ctx.stats.higher_calls += 1
          IRUnresolved
        }
        None => {
          let qualified = match id.name {
            Dot(..) => true // `@pkg.fn` — fully qualified static identity
            Ident(..) => false
          }
          // E2: moon.pkg alias identity — expand `@alias.fn` to the real
          // package-qualified key so dep .mbti signatures can be found
          let full_key = match id.name {
            Dot(pkg~, id~) =>
              match ctx.pkg_alias.get(pkg) {
                Some(full_pkg) => full_pkg + "::" + id
                None => name
              }
            Ident(..) => name
          }
          let known = qualified ||
            ctx.symbols.fn_exists.contains(name) ||
            ctx.symbols.fn_exists.contains(full_key) ||
            is_builtin_fn(name)
          record_site(ctx, func, "static", known, name)
          ctx.stats.total_calls += 1
          ctx.stats.static_calls += 1
          if known {
            ctx.stats.static_resolved += 1
          }
          match builtin_ctor_ret(name) {
            Some(t) => t
            None =>
              // qualified key first (dep .mbti), bare/short fallback
              match get_fn_ret(ctx.symbols, full_key) {
                Some(t) => t
                None => or_unresolved(get_fn_ret(ctx.symbols, name))
              }
          }
        }
      }
    }
    _ => {
      let _ = infer_expr(func, ctx)
      record_site(ctx, func, "higher", false, "<computed>")
      ctx.stats.total_calls += 1
      ctx.stats.higher_calls += 1
      IRUnresolved
    }
  }
}

///|
fn infer_dot_apply(
  recv : @syntax.Expr,
  mname : String,
  ctx : ScanCtx,
) -> IRType {
  let recv_ty = infer_expr(recv, ctx)
  ctx.stats.total_calls += 1
  ctx.stats.receiver_calls += 1
  match recv_ty {
    IRConcrete(name, _) => {
      let key = name + "::" + mname
      ctx.last_key = key
      ctx.last_recv_ty = recv_ty
      record_site_recv(ctx, recv, true, key, name, recv_var=recv_var_of(recv))
      ctx.stats.receiver_resolved += 1
      // symbols first (source + .mbti + dep tables, short_key fallback);
      // the builtin hardcoding table stays as last resort only
      let base = match get_fn_ret(ctx.symbols, key) {
        Some(t) =>
          match t {
            IRUnresolved => or_unresolved(builtin_method_ret(name, mname))
            _ => t
          }
        None => or_unresolved(builtin_method_ret(name, mname))
      }
      match base {
        IRConcrete("__arraymap__", _) =>
          match recv_ty {
            IRConcrete("Array", args) =>
              if args.length() >= 1 {
                IRConcrete("Array", [args[0]])
              } else {
                IRConcrete("Array", [IRUnresolved])
              }
            _ => IRConcrete("Array", [IRUnresolved])
          }
        IRConcrete("__mapval__", _) =>
          // Map::get -> Option[V]; Array index -> elem
          match recv_ty {
            IRConcrete("Map", args) =>
              if args.length() >= 2 {
                IRConcrete("Option", [args[1]])
              } else {
                IRUnresolved
              }
            _ => IRUnresolved
          }
        t => t
      }
    }
    IRTraitObj(t) => {
      ctx.last_recv_ty = IRUnresolved
      record_site_recv(
        ctx,
        recv,
        false,
        "dyn " + t + "::" + mname,
        "trait:" + t,
        recv_var=recv_var_of(recv),
      )
      ctx.stats.receiver_dispatch += 1
      IRUnresolved
    }
    IRTypeParam(p) => {
      ctx.last_recv_ty = IRUnresolved
      record_site_recv(
        ctx,
        recv,
        false,
        "T:" + p + "::" + mname,
        "T:" + p,
        recv_var=recv_var_of(recv),
      )
      ctx.stats.receiver_dispatch += 1
      IRUnresolved
    }
    _ => {
      ctx.last_key = "?::" + mname
      ctx.last_recv_ty = IRUnresolved
      record_site_recv(ctx, recv, false, "?::" + mname, "?")
      ctx.stats.receiver_unknown += 1
      IRUnresolved
    }
  }
}

///|
fn record_site(
  ctx : ScanCtx,
  expr : @syntax.Expr,
  kind : String,
  resolved : Bool,
  target : String,
) -> Unit {
  ctx.stats.sites.push({
    caller: ctx.cur_fn,
    file: ctx.file,
    line: expr.loc().start.lnum,
    kind,
    resolved,
    target,
    recv_ty: "",
    recv_var: "",
    recv_pt: [],
  })
}

///|
fn record_site_recv(
  ctx : ScanCtx,
  expr : @syntax.Expr,
  resolved : Bool,
  target : String,
  recv_ty : String,
  recv_var? : String = "",
) -> Unit {
  ctx.stats.sites.push({
    caller: ctx.cur_fn,
    file: ctx.file,
    line: expr.loc().start.lnum,
    kind: "receiver",
    resolved,
    target,
    recv_ty,
    recv_var,
    recv_pt: [],
  })
}

// T4c-2: solve this function's constraint slice and fill recv_pt on the
// dispatch sites it produced (non-empty TYPE set => refinement input)

// D2b: formal-param node — locals copy from the summary-level node so
// call-site arg allocs (into "fn@f.param:<name>") reach local uses

///|
fn pt_copy_param(param_name : String, ctx : ScanCtx) -> Unit {
  if ctx.cur_fn != "<top>" {
    ctx.pt_constraints.push(
      PTCopy(param_name, "fn@" + ctx.cur_fn + ".param:" + param_name),
    )
  }
}

// D2b: peel wrapper expressions down to the value expression

///|
fn pt_value_expr(e : @syntax.Expr) -> @syntax.Expr {
  match e {
    Sequence(last_expr~, ..) => pt_value_expr(last_expr)
    If(ifso~, ifnot~, ..) => {
      let a = pt_value_expr(ifso)
      match ifnot {
        Some(x) => {
          ignore(pt_value_expr(x))
          a
        }
        None => a
      }
    }
    Match(cases~, ..) => {
      let mut first : @syntax.Expr = e
      let mut seen = false
      for c in cases {
        if !seen {
          first = pt_value_expr(c.body)
          seen = true
        } else {
          ignore(pt_value_expr(c.body))
        }
      }
      first
    }
    Try(body~, ..) => pt_value_expr(body)
    Constraint(expr~, ..) => pt_value_expr(expr)
    Group(expr~, ..) => pt_value_expr(expr)
    _ => e
  }
}

// D2b: seed the ret-node constraint from the value expression: a callee
// call seeds the CALLEE's declared concrete ret type; a plain var copies
// its (as-yet unknown, fixpoint-filled) pts; constructors alloc directly

///|
fn pt_emit_ret(body : @syntax.Expr, ret_t : IRType, ctx : ScanCtx) -> Unit {
  if ctx.cur_fn == "<top>" {
    return
  }
  let node = "fn@" + ctx.cur_fn + ".ret"
  let v = pt_value_expr(body)
  match v {
    Apply(func~, ..) =>
      match apply_func_name(func) {
        Some(callee) => {
          // callee's declared ret; fall back to THIS function's declared
          // ret when the callee's is unknown (E2: factory shape
          // `fn make() -> C { C::new() }` — C::new has no collected sig,
          // but make's own declared return IS authoritative)
          let t2 = or_unresolved(get_fn_ret(ctx.symbols, callee))
          if t2 == IRUnresolved {
            pt_alloc_ret(node, ret_t, ctx)
          } else {
            pt_alloc_ret(node, t2, ctx)
          }
        }
        None => pt_alloc_ret(node, ret_t, ctx)
      }
    Constr(constr~, ..) =>
      match ctx.symbols.constructors.get(constr.name.name) {
        Some(tyname) =>
          ctx.pt_constraints.push(PTAlloc(node, tyname + "@ret:" + ctx.cur_fn))
        None => pt_alloc_ret(node, ret_t, ctx)
      }
    Ident(id~, ..) =>
      match id.name {
        Ident(name~) => ctx.pt_constraints.push(PTCopy(node, name))
        Dot(..) => pt_alloc_ret(node, ret_t, ctx)
      }
    _ => pt_alloc_ret(node, ret_t, ctx)
  }
}

///|
fn pt_alloc_ret(node : String, t : IRType, ctx : ScanCtx) -> Unit {
  match t {
    IRConcrete(name, _) =>
      ctx.pt_constraints.push(PTAlloc(node, name + "@ret:" + ctx.cur_fn))
    _ => ()
  }
}

// D2b: store this function's constraint slice + site range; the global
// accumulator is rewound so subsequent functions start clean

///|
fn pt_store_slice(ctx : ScanCtx, c_start : Int, s_start : Int) -> Unit {
  let n = ctx.pt_constraints.length()
  if n > c_start || ctx.stats.sites.length() > s_start {
    let slice : Array[PTConstraint] = []
    let mut i = c_start
    while i < n {
      slice.push(ctx.pt_constraints[i])
      i += 1
    }
    ctx.pt_fn_slices.push({
      fn_name: ctx.cur_fn,
      constraints: slice,
      site_start: s_start,
      site_end: ctx.stats.sites.length(),
    })
  }
  // rewind the shared accumulator (slice now owns its constraints)
  while ctx.pt_constraints.length() > c_start {
    let _ = ctx.pt_constraints.pop()
  }
}

// D2b: strip a pt site name to its TYPE segment ("B@s x" / "B@ret:f" /
// "B@ipc" -> "B")

///|
fn pt_site_type(s : String) -> String {
  let idx = find_last(s, "@")
  if idx > 0 {
    Show::to_string(s[:idx])
  } else {
    s
  }
}

// E2: live-constraint alloc dedup (pre-slice)

///|
fn pt_slice_has_alloc_here(ctx : ScanCtx, v : String, s : String) -> Bool {
  for c in ctx.pt_constraints {
    match c {
      PTAlloc(vv, ss) => if vv == v && ss == s { return true }
      _ => ()
    }
  }
  false
}

// E2: idempotence guard for the closure capture store emission

///|
fn pt_slice_has_store(ctx : ScanCtx, sv : String, field : String) -> Bool {
  for c in ctx.pt_constraints {
    match c {
      PTStore(s, f, _) => if s == sv && f == field { return true }
      _ => ()
    }
  }
  false
}

// D2b: does the slice already carry this injected alloc? (idempotence)

///|
fn pt_slice_has_alloc(slice : PTFnSlice, vname : String, site : String) -> Bool {
  for c in slice.constraints {
    match c {
      PTAlloc(v, s) => if v == vname && s == site { return true }
      _ => ()
    }
  }
  false
}

// D2b: the file-end interprocedural fixpoint (budget 2 rounds):
//   solve slices -> ret summaries -> consume pendings (ret into caller
//   vars, args into callee param nodes) -> repeat while anything changed;
//   then fill dispatch recv_pt from the final solutions

///|
fn pt_solve_all(
  ctx : ScanCtx,
  strategy? : ContextStrategy = Insensitive,
) -> Unit {
  // T7.1: dispatch skeleton — Insensitive is the current behavior
  if !strategy.is_implemented() {
    println(
      "moon-audit: warning: context strategy '" +
      strategy.name() +
      "' is not implemented; using insensitive baseline (no silent downgrade)",
    )
  }
  if ctx.pt_fn_slices.length() == 0 {
    return
  }
  // E2: monotone worklist — sets only grow (PTAlloc/PTCopy/Store edges are
  // additive), so iterating to a no-change round IS the fixpoint. Budget =
  // 2x total constraints (>= 4 rounds); exhaustion is DISCLOSED via
  // pt_not_converged instead of silently returning partial results.
  let mut budget = 4
  for s in ctx.pt_fn_slices {
    budget += s.constraints.length() * 2
  }
  let mut iterations = 0
  let mut changed = true
  let mut sols : Array[PTSolution] = []
  while changed {
    if iterations >= budget {
      ctx.stats.pt_not_converged = true
      break
    }
    sols = pt_solve_slices(ctx)
    let summaries = pt_build_summaries(ctx, sols)
    changed = pt_consume_pendings(ctx, sols, summaries)
    iterations += 1
  }
  if sols.length() == 0 {
    sols = pt_solve_slices(ctx)
  }
  // fill dispatch recv_pt from the final solutions
  for i3 in 0..<ctx.pt_fn_slices.length() {
    let s = ctx.pt_fn_slices[i3]
    let mut si = s.site_start
    while si < s.site_end && si < ctx.stats.sites.length() {
      let site = ctx.stats.sites[si]
      if site.kind == "receiver" && site.recv_var != "" {
        let sites_set = sols[i3].pts_of(site.recv_var)
        let tys : Array[String] = []
        for st in sites_set {
          let tyname = pt_site_type(st)
          if tyname != "" && !tys.contains(tyname) {
            tys.push(tyname)
          }
        }
        ctx.stats.sites[si] = { ..site, recv_pt: tys, }
      }
      si += 1
    }
  }
  ctx.stats.pt_iterations = iterations
}

///|
fn pt_solve_slices(ctx : ScanCtx) -> Array[PTSolution] {
  let sols : Array[PTSolution] = []
  for i3 in 0..<ctx.pt_fn_slices.length() {
    sols.push(solve_pt_constraints(ctx.pt_fn_slices[i3].constraints))
  }
  sols
}

///|
fn pt_build_summaries(
  ctx : ScanCtx,
  sols : Array[PTSolution],
) -> Map[String, Array[String]] {
  let summaries : Map[String, Array[String]] = Map([])
  for i3 in 0..<ctx.pt_fn_slices.length() {
    let s = ctx.pt_fn_slices[i3]
    let ret_sites = sols[i3].pts_of("fn@" + s.fn_name + ".ret")
    if ret_sites.length() > 0 {
      let tys : Array[String] = []
      for r in ret_sites {
        let ty = pt_site_type(r)
        if ty != "" && !tys.contains(ty) {
          tys.push(ty)
        }
      }
      summaries[s.fn_name] = tys
    }
  }
  summaries
}

// one pending-consumption pass; returns true if any constraint was
// injected (caller decides whether to iterate)

///|
fn pt_consume_pendings(
  ctx : ScanCtx,
  sols : Array[PTSolution],
  summaries : Map[String, Array[String]],
) -> Bool {
  let mut changed = false
  // slice lookup helpers shared by both kinds
  let by_name : Map[String, Int] = Map([])
  for i2 in 0..<ctx.pt_fn_slices.length() {
    by_name[ctx.pt_fn_slices[i2].fn_name] = i2
  }
  let slice_of = fn(key : String) -> Int? {
    match by_name.get(key) {
      Some(i3) => Some(i3)
      None => by_name.get(short_key(key))
    }
  }
  for p in ctx.pt_pending {
    if p.kind == "ret" {
      let sites = match summaries.get(p.callee) {
        Some(arr) => arr
        None =>
          match summaries.get(short_key(p.callee)) {
            Some(arr) => arr
            None => []
          }
      }
      if sites.length() > 0 {
        match slice_of(p.owner_fn) {
          Some(si) => {
            let slice = ctx.pt_fn_slices[si]
            let mut injected = false
            for site in sites {
              let full = site + "@ipc"
              if !pt_slice_has_alloc(slice, p.pvar, full) {
                slice.constraints.push(PTAlloc(p.pvar, full))
                injected = true
              }
            }
            if injected {
              changed = true
            }
          }
          None => ()
        }
      }
    } else if p.kind == "argret" {
      // concrete arg value -> callee formal param node (direct seed)
      if p.site != "" {
        match slice_of(p.callee) {
          Some(si) => {
            let slice = ctx.pt_fn_slices[si]
            let full = p.site + "@ipc"
            if !pt_slice_has_alloc(slice, p.param_node, full) {
              slice.constraints.push(PTAlloc(p.param_node, full))
              changed = true
            }
          }
          None => ()
        }
      }
    } else if p.kind == "arg" {
      // caller var's sites -> callee param node
      match slice_of(p.owner_fn) {
        Some(ci) => {
          let caller_sites = sols[ci].pts_of(p.pvar)
          if caller_sites.length() > 0 {
            match slice_of(p.callee) {
              Some(si) => {
                let slice = ctx.pt_fn_slices[si]
                let mut injected = false
                for site in caller_sites {
                  let full = pt_site_type(site) + "@ipc"
                  if !pt_slice_has_alloc(slice, p.param_node, full) {
                    slice.constraints.push(PTAlloc(p.param_node, full))
                    injected = true
                  }
                }
                if injected {
                  changed = true
                }
              }
              None => ()
            }
          }
        }
        None => ()
      }
    }
  }
  changed
}

// T4c-2: emit per-function points-to constraints for simple var bindings
//   x = <concrete-typed RHS>  ->  PTAlloc(x, "Type@s<N>")
//   x = y                     ->  PTCopy(x, y)   (flow-insensitive, per-fn)

// E2: container literal element stores — Ident aliases flow through the
// "elem" field; constructor-call elements alloc their own temp node first

///|

///|
fn elem_callee_name(func : @syntax.Expr) -> String? {
  // apply_func_name handles Ident only; constructor elements `C::new()`
  // are Method nodes — extract "Type::method" for them
  match func {
    Method(type_name~, method_name~, ..) =>
      Some(longident_str(type_name.name) + "::" + method_name.name)
    _ => apply_func_name(func)
  }
}

///|
fn pt_emit_array_elems(
  v : String,
  exprs : @list.List[@syntax.Expr],
  ctx : ScanCtx,
) -> Unit {
  let mut i = 0
  for e in exprs {
    match e {
      Ident(id~, ..) =>
        match id.name {
          Ident(name~) => ctx.pt_constraints.push(PTStore(v, "elem", name))
          Dot(..) => ()
        }
      // `C::new()` element: alloc a temp site carrying the callee's
      // DECLARED concrete ret, then store the temp into elem (the wip gap:
      // Ident-only stores made `[C::new()]` literals lose their pointees)
      Apply(func~, ..) =>
        match elem_callee_name(func) {
          Some(callee) => {
            // site label: declared concrete ret when known, else callee
            // provenance (builtin ctors like C::new have no collected sig
            // — the provenance label still makes the elem store fire)
            let label = match or_unresolved(get_fn_ret(ctx.symbols, callee)) {
              IRConcrete(n, _) => n + "@call:" + callee
              _ => "call:" + callee
            }
            let tmp = "elem@" + v + ":" + i.to_string()
            if !pt_slice_has_alloc_here(ctx, tmp, label) {
              ctx.pt_constraints.push(PTAlloc(tmp, label))
            }
            ctx.pt_constraints.push(PTStore(v, "elem", tmp))
          }
          None => ()
        }
      _ => ()
    }
    i += 1
  }
}

///|
fn pt_emit_binding(
  pattern : @syntax.Pattern,
  rhs : @syntax.Expr,
  t : IRType,
  ctx : ScanCtx,
) -> Unit {
  // D2b: record call-site bindings for the file-end fixpoint — the ret
  // pending consumes the callee's ret summary; arg pendings carry caller
  // var sites into the callee's fn-sig-aligned param nodes
  pt_record_call_pendings(pattern, rhs, ctx)
  match pattern {
    Var(binder) => {
      let v = binder.name

      // E2: container literal — alloc + elem stores fire on the FIRST
      // match regardless of type resolution (an Array literal always
      // infers IRConcrete, which used to bypass the elem model below)
      match rhs {
        Array(exprs~, ..) => {
          ctx.pt_constraints.push(PTAlloc(v, "Array@lit:" + v))
          pt_emit_array_elems(v, exprs, ctx)
        }
        _ => ()
      }
      match t {
        IRConcrete(name, _) =>
          if !pt_slice_has_alloc_here(ctx, v, name + "@s" + v) {
            ctx.pt_constraints.push(PTAlloc(v, name + "@s" + v))
          }
        _ =>
          // var-to-var alias: copy whatever y may point to
          match rhs {
            Ident(id~, ..) =>
              match id.name {
                Ident(name~) => ctx.pt_constraints.push(PTCopy(v, name))
                Dot(..) => ()
              }
            Constraint(expr~, ..) =>
              match expr {
                Ident(id~, ..) =>
                  match id.name {
                    Ident(name~) => ctx.pt_constraints.push(PTCopy(v, name))
                    Dot(..) => ()
                  }
                _ => ()
              }
            // E2: factory call `let r = make()` where make's declared ret
            // is concrete but the local's inferred type got lost (cascades)
            Apply(func~, ..) =>
              match apply_func_name(func) {
                Some(callee) => {
                  let rt = or_unresolved(get_fn_ret(ctx.symbols, callee))
                  match rt {
                    IRConcrete(n, _) =>
                      ctx.pt_constraints.push(PTAlloc(v, n + "@call:" + callee))
                    _ => ()
                  }
                }
                None => ()
              }
            // E2: container literal — alloc a list site; each Ident elem
            // stores into the "elem" pseudo-field (minimal container model:
            // ForEach iteration loads back through the same field)
            Array(exprs~, ..) => {
              ctx.pt_constraints.push(PTAlloc(v, "Array@lit:" + v))
              pt_emit_array_elems(v, exprs, ctx)
            }
            // E2: closure value binding — allocation site for the closure
            // object; captured outer Idents store into "cap:<name>" slots
            // (aligned with the T2.5 closure_sites capture table)
            Function(func~, ..) => {
              let pname : Array[String] = []
              for p in func.parameters {
                match p {
                  Positional(binder~, ..) => pname.push(binder.name)
                  Labelled(binder~, ..) => pname.push(binder.name)
                  Optional(binder~, ..) => pname.push(binder.name)
                  QuestionOptional(binder~, ..) => pname.push(binder.name)
                  DiscardPositional(..) => ()
                }
              }
              ctx.pt_constraints.push(PTAlloc(v, "$closure@" + v))
              let caps : Array[String] = []
              collect_idents(func.body, caps)
              for n in caps {
                if !pname.contains(n) &&
                  ctx.env.contains(n) &&
                  !pt_slice_has_store(ctx, v, "cap:" + n) {
                  ctx.pt_constraints.push(PTStore(v, "cap:" + n, n))
                }
              }
            }
            _ => ()
          }
      }
    }
    _ => ()
  }
}

// D2b: peel to a call and record ret/arg pendings. Only plain `Var`
// patterns bind the ret result; arg flow is recorded for every positional
// Ident argument whose formal name is known via FnSig.

///|
fn pt_record_call_pendings(
  pattern : @syntax.Pattern,
  rhs : @syntax.Expr,
  ctx : ScanCtx,
) -> Unit {
  let callee = match pt_value_expr(rhs) {
    Apply(func~, ..) =>
      match apply_func_name(func) {
        Some(n) => n
        None => return
      }
    _ => return
  }
  let binds_ret = match pattern {
    Var(binder) => binder.name
    _ => ""
  }
  if binds_ret != "" {
    ctx.pt_pending.push({
      kind: "ret",
      pvar: binds_ret,
      callee,
      param_node: "",
      owner_fn: ctx.cur_fn,
      site: "",
    })
  }
  // arg pendings: positional Ident args -> formal param nodes (FnSig)
  match pt_value_expr(rhs) {
    Apply(args~, ..) => {
      let sig = ctx.symbols.fn_sigs.get(callee)
      let params : Array[FnP] = match sig {
        Some(s) => s.params
        None =>
          match ctx.symbols.fn_sigs.get(short_key(callee)) {
            Some(s) => s.params
            None => []
          }
      }
      let mut idx = 0
      for arg in args {
        match arg.kind {
          Positional => {
            let pname = if idx < params.length() {
              params[idx].binder
            } else {
              ""
            }
            if pname != "" && pname != "_" {
              match arg.value {
                Ident(id~, ..) =>
                  match id.name {
                    Ident(name~) =>
                      ctx.pt_pending.push({
                        kind: "arg",
                        pvar: name,
                        callee,
                        param_node: "fn@" + callee + ".param:" + pname,
                        owner_fn: ctx.cur_fn,
                        site: "",
                      })
                    Dot(..) => ()
                  }
                _ => ()
              }
            }
            idx += 1
          }
          _ => () // labelled/optional args: skip in the thin slice
        }
      }
    }
    _ => ()
  }
}

// T4c-2: the source-level variable behind a receiver expression
// (Constraint/Group wrappers peeled; only plain Idents qualify)

///|
fn recv_var_of(expr : @syntax.Expr) -> String {
  match expr {
    Ident(id~, ..) =>
      match id.name {
        Ident(name~) => name
        Dot(..) => ""
      }
    Constraint(expr~, ..) => recv_var_of(expr)
    Group(expr~, ..) => recv_var_of(expr)
    _ => ""
  }
}

///|

///|
fn elem_type(t : IRType) -> IRType {
  // element type of Array/Iter/Option/Result payload, Map key/value joins
  match t {
    IRConcrete("Array", args)
    | IRConcrete("Iter", args)
    | IRConcrete("Set", args) =>
      if args.length() >= 1 {
        args[0]
      } else {
        IRUnresolved
      }
    IRConcrete("Option", args) =>
      if args.length() >= 1 {
        args[0]
      } else {
        IRUnresolved
      }
    IRConcrete("Result", args) =>
      if args.length() >= 1 {
        args[0]
      } else {
        IRUnresolved
      }
    IRConcrete("Map", args) =>
      if args.length() >= 2 {
        IRConcrete("Tuple", [args[0], args[1]])
      } else {
        IRUnresolved
      }
    IRConcrete("Bytes", _) => IRConcrete("Byte", [])
    IRConcrete("String", _) => IRConcrete("Char", [])
    _ => IRUnresolved
  }
}

///|

///|
fn is_stringy(t : IRType) -> Bool {
  match t {
    IRConcrete("String", _) | IRConcrete("StringView", _) => true
    _ => false
  }
}

///|
fn builtin_constr_payload(name : String, scrut : IRType) -> Array[IRType] {
  // `Some(x)` on Option[T] binds x : T; `Ok(x)` on Result[T, E] binds x : T
  match (name, scrut) {
    ("Some", IRConcrete("Option", args)) | ("Ok", IRConcrete("Result", args)) =>
      if args.length() >= 1 {
        [args[0]]
      } else {
        []
      }
    ("Err", IRConcrete("Result", args)) =>
      if args.length() >= 2 {
        [args[1]]
      } else {
        []
      }
    _ => []
  }
}

///|
fn builtin_static_ret(key : String) -> IRType? {
  // `Type::method` statics on builtin/container types + core trait statics
  match key {
    "Buffer::new" | "Buffer::make" => Some(IRConcrete("Buffer", []))
    "Map::new" | "Map::copy" | "Map::create" => Some(IRConcrete("Map", []))
    "StringBuilder::new" => Some(IRConcrete("StringBuilder", []))
    "Iter::new" | "Iter::from_array" | "Iter::range" | "Iter::of" =>
      Some(IRConcrete("Iter", []))
    // core trait statics (Show/ToString etc. are imported, not local)
    "Show::to_string" | "Show::to_debug_string" | "ToString::to_string" =>
      Some(IRConcrete("String", []))
    "Show::output" | "Show::output_type" => Some(IRUnit)
    _ => None
  }
}

///|
fn builtin_ctor_ret(name : String) -> IRType? {
  match name {
    "Map" => Some(IRConcrete("Map", []))
    "Buffer" => Some(IRConcrete("Buffer", []))
    "StringBuilder" => Some(IRConcrete("StringBuilder", []))
    "Deque" => Some(IRConcrete("Deque", []))
    "Iter" => Some(IRConcrete("Iter", []))
    _ => None
  }
}

///|
fn builtin_method_ret(recv : String, mname : String) -> IRType? {
  // common prelude/core methods; decascade chains on builtin containers
  match (recv, mname) {
    (
      "Array",
      "map"
      | "filter"
      | "rev"
      | "sort"
      | "concat"
      | "flatten"
      | "dedup"
      | "take"
      | "skip"
      | "drop",
    ) => Some(IRConcrete("__arraymap__", []))
    (
      "Array",
      "join"
      | "to_string"
      | "hash"
      | "get_unsafe"
      | "fold"
      | "exists"
      | "contains"
      | "length"
      | "size"
      | "blit"
      | "sort_by",
    ) => Some(IRConcrete("String", []))
    (
      "String",
      "to_string"
      | "to_owned"
      | "rev"
      | "concat"
      | "repeat"
      | "substring"
      | "trim"
      | "trim_start"
      | "trim_end"
      | "to_uppercase"
      | "to_lowercase"
      | "to_snake_case"
      | "to_camel_case"
      | "replace"
      | "get_unsafe"
      | "pad_left"
      | "pad_right"
      | "pad_start"
      | "pad_end",
    ) => Some(IRConcrete("String", []))
    (
      "String",
      "length"
      | "codeunit_size"
      | "char_length"
      | "compare"
      | "hash"
      | "is_empty"
      | "contains"
      | "starts_with"
      | "ends_with"
      | "charCodeAt"
      | "get_char_or_zero"
      | "find"
      | "last_of"
      | "count_of",
    ) => Some(IRConcrete("Int", []))
    (
      "String",
      "chars"
      | "split"
      | "split_char"
      | "split_whitespace"
      | "bytes"
      | "lines"
      | "graphemes"
      | "split_iter",
    ) => Some(IRConcrete("Array", []))
    ("Buffer", "to_string" | "to_bytes" | "to_owned") =>
      Some(IRConcrete("String", []))
    ("Buffer", "length" | "size") => Some(IRConcrete("Int", []))
    ("Map", "keys" | "values") => Some(IRConcrete("Array", []))
    ("Map", "iter" | "iter2") => Some(IRConcrete("Iter", []))
    ("Array", "to_array" | "copy" | "iter" | "rev_inplace") =>
      Some(IRConcrete("__arraymap__", []))
    ("String", "view") => Some(IRConcrete("StringView", []))
    (
      "StringView",
      "to_owned"
      | "to_string"
      | "copy"
      | "trim"
      | "trim_start"
      | "trim_end",
    ) => Some(IRConcrete("String", []))
    (
      "StringView",
      "length"
      | "size"
      | "is_empty"
      | "hash"
      | "char_length"
      | "codeunit_size",
    ) => Some(IRConcrete("Int", []))
    ("StringView", "split" | "split_char" | "chars" | "graphemes") =>
      Some(IRConcrete("Array", []))
    ("Map", "get" | "get_or_default" | "get_unsafe" | "at" | "get_or_init") =>
      Some(IRConcrete("__mapval__", [])) // marker: receiver-parametric below
    ("Map", "set" | "remove" | "clear" | "each" | "contains" | "length" | "size"
    ) => Some(IRUnit)
    ("Map", "map" | "filter") =>
      Some(IRConcrete("Map", [IRUnresolved, IRUnresolved]))
    ("Bytes", "to_string" | "copy" | "to_owned") =>
      Some(IRConcrete("String", []))
    ("Bytes", "length" | "size" | "hash" | "blit" | "iter") =>
      Some(IRConcrete("Int", []))
    ("StringBuilder", "to_string" | "to_owned") =>
      Some(IRConcrete("String", []))
    ("StringBuilder", "length" | "size") => Some(IRConcrete("Int", []))
    ("Iter", "to_array" | "collect" | "filter" | "map" | "rev" | "take" | "skip"
    ) => Some(IRConcrete("__arraymap__", []))
    (
      "Logger",
      "write_string"
      | "write_char"
      | "write_byte"
      | "log_str"
      | "log_char"
      | "log_byte",
    ) => Some(IRUnit)
    (_, "to_string" | "to_debug_string") => Some(IRConcrete("String", []))
    _ => None
  }
}

///|
fn is_builtin_fn(name : String) -> Bool {
  match name {
    "println"
    | "print"
    | "panic"
    | "abort"
    | "ignore"
    | "assert_eq"
    | "assert_true"
    | "assert_false"
    | "inspect" => true
    _ => false
  }
}

// ── Project-level driver ──────────────────────────────────────────────────

///|
pub fn run_ir_stats(
  root : String,
  config : Config,
  conservative_alias? : Bool = false,
) -> IRStatsResult {
  // E3: thin compatibility shell (single world build here)
  let world = load_program_world(root, config, conservative_alias~)
  run_ir_stats_with_world(world)
}

///|
/// E3: world-parameterized entry (ir-stats / --live-vars consume the SAME
/// pre-built world; alias policy applied at load time; config was only
/// consumed by the load, which now belongs to the caller).
pub fn run_ir_stats_with_world(world : ProgramWorld) -> IRStatsResult {
  let stats = IRStatsResult::new()
  // E2: batch mode — cross-FILE pt pendings (caller in file A seeding a
  // param of a fn defined in file B) merge into the carrier and the
  // worklist fixpoint runs ONCE after the whole module scan
  stats.pt_carrier = Some({ slices: [], pendings: [], })
  // E3: world arrives pre-built (alias policy already applied)
  for pkgf in world.packages {
    let key = canonical_dir(pkgf.dir)
    let aliases = match world.aliases.get(key) {
      Some(m) => m
      None => Map([]) // world keys every package; dead branch by construction
    }
    for file in pkgf.files {
      stats.files_scanned += 1
      let source = @fs.read_file_to_string(file) catch { _ => continue }
      let (impls, _) = @parser.parse_string(source, name=file)
      scan_package_calls(
        impls.to_array(),
        file,
        world.symbols,
        stats,
        pkg_alias=aliases,
        pt_deferred=true,
      )
    }
  }
  pt_solve_batched(stats, strategy=world.config.context_strategy)
  stats.alias_unresolved = world.symbols.alias_unresolved
  stats
}

///|
// Parse a package's moon.pkg import block into alias -> package-path map.
// Both explicit aliases (`"a/b/c" @c`) and the default alias (last path
// segment) are registered.
fn pkg_alias_map(pkg_dir : String) -> Map[String, String] {
  let result : Map[String, String] = Map([])
  let pkg_path = @path.Path(pkg_dir).join(@path.Path("moon.pkg")).0
  let content = @fs.read_file_to_string(pkg_path) catch { _ => return result }
  let lines = content.split("\n")
  let mut in_import = false
  for line in lines {
    let trimmed = line.to_owned().trim(chars=" \t\r")
    if trimmed.has_prefix("import") && trimmed.contains("{") {
      in_import = true
      if trimmed.contains("}") {
        in_import = false
      }
      continue
    }
    if in_import {
      if trimmed.contains("}") {
        in_import = false
        continue
      }
      if trimmed.has_prefix("//") {
        continue
      }
      let pkg = extract_quoted(trimmed.to_owned())
      if pkg.length() > 0 {
        // default alias: last path segment ("a/b/c" -> "c")
        let seg_idx = find_last(pkg, "/")
        let default_alias = if seg_idx >= 0 {
          Show::to_string(pkg[seg_idx + 1:])
        } else {
          pkg
        }
        result[default_alias] = pkg
        // explicit alias: `"a/b/c" @c,`
        let at_idx = find_last(trimmed.to_owned(), "@")
        if at_idx >= 0 {
          let after = Show::to_string(trimmed[at_idx + 1:])
          let alias_name = after.trim(chars=" ,\t\r").to_owned()
          if alias_name.length() > 0 {
            result[alias_name] = pkg
          }
        }
      }
    }
  }
  result
}

// ── M2: dependency symbol tables (.mooncakes ingestion) ───────────────────

///|
fn short_key(k : String) -> String {
  // "pkg::Type::method" -> "Type::method"; "pkg::Type" -> "Type"
  let segs : Array[String] = []
  let cur = StringBuilder()
  for ch in k {
    if ch == ':' {
      if cur.to_string() != "" {
        segs.push(cur.to_string())
        cur.reset()
      }
    } else {
      cur.write_char(ch)
    }
  }
  if cur.to_string() != "" {
    segs.push(cur.to_string())
  }
  let n = segs.length()
  if n >= 2 {
    segs[n - 2] + "::" + segs[n - 1]
  } else if n == 1 {
    segs[0]
  } else {
    k
  }
}

///|
pub fn get_impl_method(symbols : PkgSymbols, key : String) -> String? {
  // T1.2: exact FIRST; short_key suffix is a FALLBACK governed by
  // alias_mode (strict default at CLI: fallback misses stay unresolved
  // and are counted with reason=alias instead of cross-binding)
  match symbols.impl_methods.get(key) {
    Some(t) => Some(t)
    None =>
      match symbols.impl_methods.get(short_key(key)) {
        Some(t) =>
          if symbols.alias_mode {
            Some(t)
          } else {
            symbols.alias_unresolved += 1
            None
          }
        None => None
      }
  }
}

///|
// resolution order: exact key first; short_key is a last-resort fallback

///|
fn get_struct_fields(
  symbols : PkgSymbols,
  tyname : String,
) -> Map[String, IRType]? {
  match symbols.struct_fields.get(tyname) {
    Some(m) => Some(m)
    None =>
      match symbols.struct_fields.get(short_key(tyname)) {
        Some(m) =>
          if symbols.alias_mode {
            Some(m)
          } else {
            symbols.alias_unresolved += 1
            None
          }
        None => None
      }
  }
}

///|
fn get_fn_ret(symbols : PkgSymbols, key : String) -> IRType? {
  // resolution order: exact key; library-model types; short_key last resort
  // (T1.2: last resort governed by alias_mode, see get_impl_method)
  match symbols.fn_ret.get(key) {
    Some(t) => Some(t)
    None =>
      match symbols.lib_fn_ret.get(key) {
        Some(t) => Some(t)
        None =>
          match symbols.fn_ret.get(short_key(key)) {
            Some(t) =>
              if symbols.alias_mode {
                Some(t)
              } else {
                symbols.alias_unresolved += 1
                None
              }
            None => None
          }
      }
  }
}

///|
fn collect_dep_symbols(root : String, symbols : PkgSymbols) -> Unit {
  let deps = root + "/.mooncakes"
  let is_dir = @fs.is_dir(deps) catch { _ => false }
  if !is_dir {
    return
  }
  walk_dep_dir(deps, symbols)
}

///|
fn walk_dep_dir(dir : String, symbols : PkgSymbols) -> Unit {
  let entries = @fs.read_dir(dir) catch { _ => return }
  let mbt_files : Array[String] = []
  let mbti_files : Array[String] = []
  let subdirs : Array[String] = []
  for entry in entries {
    if entry.has_prefix(".") ||
      entry == "_build" ||
      entry.has_suffix("_test.mbt") {
      continue
    }
    let full = @path.Path(dir).join(@path.Path(entry)).0
    let child_is_dir = @fs.is_dir(full) catch { _ => false }
    if child_is_dir {
      subdirs.push(full)
    } else if entry.has_suffix(".mbt") &&
      !entry.has_suffix("_test.mbt") &&
      !entry.has_suffix("_wbtest.mbt") {
      mbt_files.push(full)
    } else if entry.has_suffix(".mbti") {
      // E2: dependency interface files carry authoritative signatures
      // (package name comes from the .mbti content itself)
      mbti_files.push(full)
    }
  }
  // E2: derive the package identity from the .mooncakes path
  // (<root>/.mooncakes/<owner>/<repo>/<path..> -> owner/repo/path..)
  // gate3 P2-1: strip the dep repo's `source = "src"` layout segment so the
  // qualified keys match canonical identities used by moon.pkg imports and
  // .mbti package names (moonbitlang/async/http, not .../async/src/http)
  let pkg_name = if dir.has_suffix(".mooncakes") {
    ""
  } else {
    dep_canonical_pkg(dir)
  }
  for file in mbt_files {
    let source = @fs.read_file_to_string(file) catch { _ => continue }
    let (impls, _) = @parser.parse_string(source, name=file)
    collect_symbols(impls.to_array(), symbols)
    if pkg_name != "" {
      register_qualified_symbols(impls.to_array(), symbols, pkg_name)
    }
  }
  for file in mbti_files {
    collect_mbti_file(file, symbols)
  }
  for subdir in subdirs {
    walk_dep_dir(subdir, symbols)
  }
}

///|
// Canonical dep package identity from a physical .mooncakes path.
// Repos with `source = "src"` layouts (e.g. moonbitlang/async) keep their
// packages under <repo>/src/<pkg>, but the canonical identity (as used by
// moon.pkg imports and .mbti package names) is <owner>/<repo>/<pkg> —
// the layout segment must be stripped (gate3 P2-1).
pub fn dep_canonical_pkg(dir : String) -> String {
  let idx = find_last(dir, "/.mooncakes/")
  if idx < 0 {
    return ""
  }
  let rest = Show::to_string(dir[idx + "/.mooncakes/".length():])
  let segs : Array[String] = []
  for seg in rest.split("/") {
    segs.push(Show::to_string(seg))
  }
  if segs.length() < 3 {
    return rest // owner or repo level: no tail to strip
  }
  let owner = segs[0]
  let repo = segs[1]
  // read the dep repo root moon.mod for a `source = "xxx"` layout segment
  let mod_path = Show::to_string(dir[:idx]) +
    "/.mooncakes/" +
    owner +
    "/" +
    repo +
    "/moon.mod"
  let mod_content = @fs.read_file_to_string(mod_path) catch { _ => "" }
  let mut layout = ""
  for line in mod_content.split("\n") {
    let t = Show::to_string(Show::to_string(line).trim())
    if t.has_prefix("source") {
      let eq = find_last(t, "=")
      if eq >= 0 {
        let v = Show::to_string(Show::to_string(t[eq + 1:]).trim())
        let q : UInt16 = 34 // '"'
        if v.length() >= 2 && v[0] == q {
          layout = Show::to_string(v[1:v.length() - 1])
        }
      }
    }
  }
  let tail : Array[String] = []
  let mut i = 2
  let mut dropped = false
  while i < segs.length() {
    if layout != "" && !dropped && segs[i] == layout {
      dropped = true // drop exactly one layout segment
    } else {
      tail.push(segs[i])
    }
    i += 1
  }
  owner +
  "/" +
  repo +
  (if tail.length() > 0 { "/" + tail.join("/") } else { "" })
}

///|
// Register fn/method symbols under package-qualified keys
// ("owner/repo::fname" / "owner/repo::SelfTy::method") so that call sites
// with moon.pkg alias expansion can reach dep signatures.
fn register_qualified_symbols(
  impls : Array[@syntax.Impl],
  symbols : PkgSymbols,
  pkg : String,
) -> Unit {
  for item in impls {
    match item {
      TopFuncDef(fun_decl~, ..) => {
        let qkey = pkg + "::" + fun_decl.name.name
        symbols.fn_exists[qkey] = true
        match fun_decl.return_type {
          Some(ty) => symbols.fn_ret[qkey] = type_to_ir(ty, symbols)
          None => ()
        }
        match fun_decl.type_name {
          Some(tn) => {
            let mq = pkg + "::" + type_name_str(tn) + "::" + fun_decl.name.name
            symbols.fn_exists[mq] = true
            match fun_decl.return_type {
              Some(ty) => symbols.fn_ret[mq] = type_to_ir(ty, symbols)
              None => ()
            }
          }
          None => ()
        }
      }
      TopImpl(self_ty~, method_name~, ret_ty~, ..) => {
        let self_ty_name = match self_ty {
          Some(t) => type_to_string(t)
          None => "?"
        }
        let qkey = pkg + "::" + self_ty_name + "::" + method_name.name
        symbols.impl_methods[qkey] = "?"
        symbols.fn_exists[qkey] = true
        match ret_ty {
          Some(ty) => symbols.fn_ret[qkey] = type_to_ir(ty, symbols)
          None => ()
        }
      }
      _ => ()
    }
  }
}

// ── M4 slice: closed-world call graph (CHA + devirtualization index) ─────

///|

///|
fn last_segment(s : String) -> String {
  let idx = find_last(s, "::")
  if idx >= 0 {
    Show::to_string(s[idx + 2:])
  } else {
    s
  }
}

///|
fn find_last(s : String, sep : String) -> Int {
  let mut best = -1
  let mut i = 0
  while i <= s.length() - sep.length() {
    if s[i:i + sep.length()] == sep {
      best = i
    }
    i += 1
  }
  best
}

///|
pub(all) struct CallGraph {
  edges : Array[String] // "caller -> callee" resolved edges (1 per site)
  dispatch_edges : Array[String] // devirtualized: one per impl target
  unresolved : Array[String] // callers with unknown targets (1 per site)
  bound_sites : Int // T0.2: sites with a unique known target
  candidate_sites : Int // sites expanded into candidate sets (dispatch)
  unresolved_sites : Int // sites with no target at all
  pt_resolved_sites : Int // T4c-2: dispatch sites REFINED by receiver pts
  pt_not_converged : Bool // E2: worklist budget exhausted (disclosed)
}

///|
pub fn CallGraph::site_total(self : CallGraph) -> Int {
  self.bound_sites + self.candidate_sites + self.unresolved_sites
}

///|
// T0.2(b): coverage denominator is CALL SITES, not edges — a site with a
// 13-target candidate set is one covered site, not 13 (the old mixed
// denominator reported 75% when only 1 of 2 sites had candidates)
pub fn CallGraph::site_coverage(self : CallGraph) -> Int {
  let total = self.site_total()
  if total == 0 {
    return 0
  }
  (self.bound_sites + self.candidate_sites) * 100 / total
}

///|
pub fn run_call_graph(
  root : String,
  config : Config,
  conservative_alias? : Bool = false,
) -> CallGraph {
  // E3: thin compatibility shell (single world build here)
  let world = load_program_world(root, config, conservative_alias~)
  run_call_graph_with_world(world)
}

///|
/// E3: world-parameterized entry. Alias policy is already applied to the
/// world's symbols at load time; no internal reload.
pub fn run_call_graph_with_world(world : ProgramWorld) -> CallGraph {
  let symbols = world.symbols
  // devirtualization index keyed by TRAIT IDENTITY ("Trait::method" ->
  // self types); impl_methods values carry the trait path. A method-name-only
  // index remains as fallback for sites whose trait identity is unknown.
  let trait_method_index : Map[String, Array[String]] = Map([])
  let method_index : Map[String, Array[String]] = Map([])
  symbols.impl_methods.each(fn(key, trait_path) {
    // key = "SelfTy::method"
    let idx = find_last(key, "::")
    if idx > 0 {
      let mname = Show::to_string(key[idx + 2:])
      let self_ty = Show::to_string(key[:idx])
      let push = fn(table : Map[String, Array[String]], k : String) {
        match table.get(k) {
          Some(arr) => if !arr.contains(self_ty) { arr.push(self_ty) }
          None => table[k] = [self_ty]
        }
      }
      push(trait_method_index, trait_path + "::" + mname)
      push(trait_method_index, short_key(trait_path) + "::" + mname)
      push(method_index, mname)
    }
  })
  // call sites -> edges — SAME world facts as run_ir_stats (single source)
  let stats = IRStatsResult::new()
  // E2: batch mode — same cross-file carrier as run_ir_stats
  stats.pt_carrier = Some({ slices: [], pendings: [], })
  for pkgf in world.packages {
    let key = canonical_dir(pkgf.dir)
    let aliases = match world.aliases.get(key) {
      Some(m) => m
      None => Map([]) // world keys every package; dead branch by construction
    }
    for file in pkgf.files {
      stats.files_scanned += 1
      let source = @fs.read_file_to_string(file) catch { _ => continue }
      let (impls, _) = @parser.parse_string(source, name=file)
      scan_package_calls(
        impls.to_array(),
        file,
        symbols,
        stats,
        pkg_alias=aliases,
        pt_deferred=true,
      )
    }
  }
  pt_solve_batched(stats, strategy=world.config.context_strategy)
  let edges : Array[String] = []
  let dispatch_edges : Array[String] = []
  let unresolved : Array[String] = []
  // resolve a dispatch site by TRAIT IDENTITY first ("Trait::method"),
  // then fall back to the method-name-only index.
  // R7: returns true iff a NON-EMPTY target set was produced — callers
  // classify by the RESULT, never before resolving (an empty candidate set
  // is unknown/no-impls, not covered).
  // T4c-2: receiver pts TYPES refine the candidate set — when non-empty,
  // the target set is the intersection with the receiver's points-to types
  let resolve_dispatch = fn(
    dyn_target : String,
    caller : String,
    recv_pt : Array[String],
  ) -> Bool {
    // dyn_target = "Alpha::act" or "pkg::Alpha::act" (dyn prefix removed)
    let mname = last_segment(dyn_target)
    let midx = find_last(dyn_target, "::")
    let trait_part = if midx > 0 {
      Show::to_string(dyn_target[:midx])
    } else {
      ""
    }
    let identity_hit = if trait_part != "" {
      match trait_method_index.get(trait_part + "::" + mname) {
        Some(arr) => Some(arr)
        None => trait_method_index.get(short_key(trait_part) + "::" + mname)
      }
    } else {
      None
    }
    let targets = match identity_hit {
      Some(self_tys) => Some(self_tys)
      None => method_index.get(mname)
    }
    match targets {
      Some(self_tys) => {
        let refined = if recv_pt.length() > 0 {
          let keep : Array[String] = []
          for st in self_tys {
            if recv_pt.contains(st) {
              keep.push(st)
            }
          }
          if keep.length() > 0 {
            keep
          } else {
            self_tys
          } // no empty by pt
        } else {
          self_tys
        }
        let mut n = 0
        for st in refined {
          dispatch_edges.push(caller + " -> " + st + "::" + mname)
          n += 1
        }
        n > 0
      }
      None => {
        unresolved.push(caller + " -> ?" + mname + " (no-impls)")
        false
      }
    }
  }
  let mut bound_sites = 0
  let mut candidate_sites = 0
  let mut unresolved_sites = 0
  let mut pt_resolved_sites = 0
  for site in stats.sites {
    let clean_target = site.target
      .replace(old=" (unconfirmed)", new="")
      .replace(old="?", new="")
    if site.resolved {
      if site.kind == "receiver" && site.target.has_prefix("dyn ") {
        // R7: classify by the RESOLVED non-empty target set — resolve
        // first, count second; empty set → unknown(no-impls), never
        // candidate, and a site is never both candidate and unresolved
        if resolve_dispatch(
            Show::to_string(clean_target[4:]),
            site.caller,
            site.recv_pt,
          ) {
          candidate_sites += 1
          if site.recv_pt.length() > 0 {
            pt_resolved_sites += 1
          }
        } else {
          unresolved_sites += 1
        }
      } else {
        bound_sites += 1
        edges.push(site.caller + " -> " + clean_target)
      }
    } else if site.target.has_prefix("dyn ") {
      if resolve_dispatch(
          Show::to_string(site.target[4:]),
          site.caller,
          site.recv_pt,
        ) {
        candidate_sites += 1
        if site.recv_pt.length() > 0 {
          pt_resolved_sites += 1
        }
      } else {
        unresolved_sites += 1
      }
    } else if site.kind == "receiver" && site.recv_ty.has_prefix("trait:") {
      // receiver typed as a trait object: use its trait identity
      if resolve_dispatch(clean_target, site.caller, site.recv_pt) {
        candidate_sites += 1
        if site.recv_pt.length() > 0 {
          pt_resolved_sites += 1
        }
      } else {
        unresolved_sites += 1
      }
    } else if site.kind == "receiver" && site.recv_pt.length() > 0 {
      // E2: static type was lost (cascade) but the worklist recovered the
      // receiver's pointee TYPES — classify by that non-empty target set
      // (R7-consistent: resolved-set-first classification)
      let mname = last_segment(clean_target)
      if resolve_dispatch(mname, site.caller, site.recv_pt) {
        candidate_sites += 1
        pt_resolved_sites += 1
      } else {
        unresolved_sites += 1
        unresolved.push(site.caller + " -> ?" + mname + " (no-impls)")
      }
    } else {
      unresolved_sites += 1
      unresolved.push(site.caller + " -> ?")
    }
  }
  {
    edges,
    dispatch_edges,
    unresolved,
    bound_sites,
    candidate_sites,
    unresolved_sites,
    pt_resolved_sites,
    pt_not_converged: stats.pt_not_converged,
  }
}

// ── Phase 2: .mbti ingestion (official interface files) ──────────────────
// Parses package interface files (moon info output / pkg.generated.mbti)
// with the official mbti_parser and registers public signatures into the
// symbol tables — the first step toward replacing builtin hardcoding.

///|
pub fn collect_mbti_file(path : String, symbols : PkgSymbols) -> Unit {
  let source = @fs.read_file_to_string(path) catch { _ => return }
  let (mbti, reports) = @mbti_parser.parse_string(source, name=path)
  if reports.length() > 0 {
    return // unparseable interface: skip conservatively
  }
  // Pre-pass A: local trait -> method-name sets (for impl -> trait join)
  let trait_methods : Map[String, Map[String, Bool]] = Map([])
  // Pre-pass B: impl relations (self type short name -> trait name)
  let impl_relations : Array[(String, String)] = []
  for pair in mbti.sigs {
    match pair.0 {
      Trait(t) => {
        let mset : Map[String, Bool] = Map([])
        for m in t.methods {
          mset[m.name.name] = true
        }
        trait_methods[t.name.name] = mset
      }
      Impl(i) => {
        let self_short = match i.type_ {
          Name(constr_id~, ..) => short_key(longident_str(constr_id.id))
          _ => ""
        }
        if self_short != "" {
          impl_relations.push((self_short, longident_str(i.trait_name.name)))
        }
      }
      _ => ()
    }
  }
  for pair in mbti.sigs {
    match pair.0 {
      Func(func_sig) => {
        // register generics first so signature types map to IRTypeParam
        for tp in func_sig.type_params {
          symbols.type_params[tp.name.name] = true
        }
        let fname = func_sig.name.name
        let (ret_ty, _) = func_sig.return_
        let key = match func_sig.type_name {
          Some(self_ty) =>
            // method: register under "SelfTy::method"
            self_ty.name + "::" + fname
          None => fname
        }
        // qualified identity: register "pkg::key" alongside the short key
        // so cross-package same-name symbols never overwrite each other
        let qkey = mbti.package_name + "::" + key
        // source wins: .mbti only supplements symbols not already collected
        // from source (module walk runs before this pass)
        if !symbols.fn_exists.contains(key) {
          symbols.fn_exists[key] = true
          symbols.fn_ret[key] = type_to_ir(ret_ty, symbols)
          // P1-2a: .mbti signatures go through the FnSig sole write point
          collect_mbti_fn_sig(func_sig, key, symbols)
        }
        if qkey != key && !symbols.fn_exists.contains(qkey) {
          symbols.fn_exists[qkey] = true
          if !symbols.fn_ret.contains(qkey) {
            symbols.fn_ret[qkey] = type_to_ir(ret_ty, symbols)
          }
        }
        // impl -> trait join: attach trait identity to "SelfTy::method"
        // when the trait's method set contains this method (local mbti trait
        // or a trait already collected from source)
        match func_sig.type_name {
          Some(self_ty) =>
            if !symbols.impl_methods.contains(key) {
              for relation in impl_relations {
                let (impl_self, impl_trait) = relation
                if impl_self == short_key(self_ty.name) {
                  let trait_key = impl_trait + "::" + fname
                  let in_local_trait = match trait_methods.get(impl_trait) {
                    Some(mset) => mset.contains(fname)
                    None => false
                  }
                  if in_local_trait || symbols.trait_params.contains(trait_key) {
                    symbols.impl_methods[key] = impl_trait
                    break
                  }
                }
              }
            }
          None => ()
        }
      }
      Type(type_sig) => collect_mbti_type(type_sig, symbols)
      Trait(trait_sig) => collect_mbti_trait(trait_sig, symbols)
      Impl(_) => () // handled via the join above
      Const(const_sig) =>
        if !symbols.value_types.contains(const_sig.name.name) {
          symbols.value_types[const_sig.name.name] = type_to_ir(
            const_sig.type_,
            symbols,
          )
        }
      Value(value_sig) =>
        if !symbols.value_types.contains(value_sig.name.name) {
          symbols.value_types[value_sig.name.name] = type_to_ir(
            value_sig.type_,
            symbols,
          )
        }
      _ => ()
    }
  }
}

// TypeSig: struct fields / constructors into the shared tables.
// Registered under both the declared name and its short_key form.

///|
fn collect_mbti_type(sig : @mbti_ast.TypeSig, symbols : PkgSymbols) -> Unit {
  let tycon = sig.name.name
  for tp in sig.type_params {
    match tp {
      Name(n) => symbols.type_params[n.name] = true
      Underscore(_) => ()
    }
  }
  match sig.components {
    Record(fields~) =>
      if !symbols.struct_fields.contains(tycon) {
        let field_map : Map[String, IRType] = Map([])
        for field in fields {
          field_map[field.name.label] = type_to_ir(field.ty, symbols)
        }
        symbols.struct_fields[tycon] = field_map
        let short = short_key(tycon)
        if short != tycon && !symbols.struct_fields.contains(short) {
          symbols.struct_fields[short] = field_map
        }
      }
    Variant(constrs) => collect_constrs(constrs, tycon, symbols)
    ExtensibleEnum(constrs) => collect_constrs(constrs, tycon, symbols)
    ExtendEnum(constructors~, ..) =>
      for c in constructors {
        if !symbols.constructors.contains(c.name.name) {
          symbols.constructors[c.name.name] = tycon
        }
      }
    TupleStruct(_) =>
      if !symbols.constructors.contains(tycon) {
        symbols.constructors[tycon] = tycon
      }
    Newtype(_) | Alias(_) | Error(_) | Abstract => ()
  }
}

// TraitSig: method signatures -> trait_params ("Trait::method" keys)

///|
fn collect_mbti_trait(sig : @mbti_ast.TraitSig, symbols : PkgSymbols) -> Unit {
  let tname = sig.name.name
  symbols.trait_names[tname] = true
  for m in sig.methods {
    let key = tname + "::" + m.name.name
    // P1-2b: build the FnSig first, derive trait_params from it (sole
    // write point). Guard on fn_sigs: source traits already stored their
    // sigs during the module walk (source wins, first-write preserved).
    if !symbols.fn_sigs.contains(key) {
      collect_mbti_trait_method(m, key, symbols)
      materialize_trait_from_sig(symbols, key)
      let (ret_ty, _) = m.return_
      if !symbols.fn_ret.contains(key) {
        symbols.fn_ret[key] = type_to_ir(ret_ty, symbols)
      }
    }
  }
}

///|
pub fn collect_mbti_dir(dir : String, symbols : PkgSymbols) -> Unit {
  let entries = @fs.read_dir(dir) catch { _ => return }
  for entry in entries {
    if entry.has_prefix(".") {
      continue
    }
    let full = @path.Path(dir).join(@path.Path(entry)).0
    let is_dir = @fs.is_dir(full) catch { _ => false }
    if is_dir && entry != "_build" {
      collect_mbti_dir(full, symbols)
    } else if entry.has_suffix(".mbti") {
      collect_mbti_file(full, symbols)
    }
  }
}

///|
fn is_numeric_ty(name : String) -> Bool {
  match name {
    "Int" | "UInt" | "Int64" | "UInt64" | "Double" | "Float" | "Byte" => true
    _ => false
  }
}

///|
fn numeric_join(a : IRType, b : IRType) -> IRType {
  // Double dominates Int in mixed arithmetic; otherwise Unresolved
  match (a, b) {
    (IRConcrete("Double", []), _) | (_, IRConcrete("Double", [])) =>
      IRConcrete("Double", [])
    _ => IRUnresolved
  }
}

///|
fn bind_is_pattern(pat : @syntax.Pattern, ctx : ScanCtx) -> Unit {
  // builtin type-test constructors in `is` patterns bind their payload var
  match pat {
    Constr(constr~, args~, ..) => {
      let t = match constr.name.name {
        "String" => IRConcrete("String", [])
        "Int" => IRConcrete("Int", [])
        "Double" => IRConcrete("Double", [])
        "Bool" => IRConcrete("Bool", [])
        "Char" => IRConcrete("Char", [])
        "Bytes" => IRConcrete("Bytes", [])
        _ => IRUnresolved
      }
      if t != IRUnresolved {
        match args {
          Some(list) =>
            for arg in list {
              bind_pattern(arg.pat, t, ctx)
            }
          None => ()
        }
      }
    }
    SpecialConstr(binder~, args~, ..) => {
      let t = match binder.name {
        "String" => IRConcrete("String", [])
        "Int" => IRConcrete("Int", [])
        "Double" => IRConcrete("Double", [])
        "Bool" => IRConcrete("Bool", [])
        _ => IRUnresolved
      }
      if t != IRUnresolved {
        for arg in args {
          bind_pattern(arg.pat, t, ctx)
        }
      }
    }
    _ => ()
  }
}

///|
fn lib_callback_params(
  ctx : ScanCtx,
  callee : String,
) -> Array[Array[IRType?]]? {
  // library-model callback signatures: placeholders K/V/E resolve from the
  // receiver's parametric args; anything else parses as a type expression
  let placeholders = match ctx.symbols.lib_callbacks.get(callee) {
    Some(ps) => ps
    None =>
      match ctx.symbols.lib_callbacks.get(short_key(callee)) {
        Some(ps) => ps
        None => return None
      }
  }
  let recv_args = match ctx.last_recv_ty {
    IRConcrete(_, args) => args
    _ => []
  }
  let hints : Array[IRType?] = []
  for ph in placeholders {
    match ph {
      "K" | "E" => {
        let t = if recv_args.length() >= 1 {
          recv_args[0]
        } else {
          IRUnresolved
        }
        hints.push(Some(t))
      }
      "V" => {
        let t = if recv_args.length() >= 2 {
          recv_args[1]
        } else {
          IRUnresolved
        }
        hints.push(Some(t))
      }
      other => hints.push(Some(parse_type_expr(other)))
    }
  }
  // slot 0 = receiver (convention shared with builtin_callback_params)
  Some([[None], hints])
}

// T4c-2: sites whose receiver points-to TYPE set is known (ir-stats line)

///|
pub fn IRStatsResult::pt_resolved_dispatch(self : IRStatsResult) -> Int {
  let mut n = 0
  for site in self.sites {
    if site.kind == "receiver" && site.recv_pt.length() > 0 {
      n += 1
    }
  }
  n
}

// ── G2: per-function CFG fallback diagnosis ──────────────────────────────

///|
pub fn get_fallback_reasons(root : String, config : Config) -> Array[String] {
  let symbols = PkgSymbols::new()
  walk_packages(root, config, fn(_pkg_dir, mbt_files) {
    for file in mbt_files {
      let source = @fs.read_file_to_string(file) catch { _ => return }
      let (impls, _) = @parser.parse_string(source, name=file)
      collect_symbols(impls.to_array(), symbols)
    }
  })
  let result : Array[String] = []
  walk_packages(root, config, fn(_pkg_dir, mbt_files) {
    for file in mbt_files {
      let source = @fs.read_file_to_string(file) catch { _ => return }
      let (impls, _) = @parser.parse_string(source, name=file)
      for item in impls {
        match item {
          TopFuncDef(fun_decl~, decl_body~, ..) => {
            let fname = fun_decl.name.name
            match decl_body {
              DeclBody(expr=body) => {
                let ir = build_block_ir(fname, body)
                let errs = validate_cfg(ir)
                if errs.length() > 0 {
                  result.push(file + ":" + fname + " — " + errs[0])
                }
              }
              _ => ()
            }
          }
          TopImpl(method_name~, body~, ..) => {
            let fname = method_name.name
            match body {
              DeclBody(expr=body) => {
                let ir = build_block_ir(fname, body)
                let errs = validate_cfg(ir)
                if errs.length() > 0 {
                  result.push(file + ":" + fname + " — " + errs[0])
                }
              }
              _ => ()
            }
          }
          _ => ()
        }
      }
    }
  })
  result
}
