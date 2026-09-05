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
  fn_exists : Map[String, Bool] // fn names defined in this package
  fn_ret : Map[String, IRType] // fn name -> annotated return type
  impl_methods : Map[String, String] // "SelfTy::method" -> trait path
  constructors : Map[String, String] // constructor name -> type name
  struct_fields : Map[String, Map[String, IRType]] // type -> field -> type
  constr_params : Map[String, Array[IRType]] // constructor -> payload types
  trait_params : Map[String, Array[IRType?]] // "Trait::m" -> declared param types
  fn_param_arrows : Map[String, Array[Array[IRType?]]] // fn -> per-param arrow arg types
  alias_arrows : Map[String, Array[IRType?]] // type alias -> arrow param types
  value_types : Map[String, IRType] // const/value name -> declared type (.mbti)
  trait_names : Map[String, Bool] // declared trait names (local + .mbti)
  type_params : Map[String, Bool] // generic params seen in this package
}

///|
pub fn PkgSymbols::new() -> PkgSymbols {
  let symbols : PkgSymbols = {
    fn_exists: Map([]),
    fn_ret: Map([]),
    impl_methods: Map([]),
    constructors: Map([]),
    struct_fields: Map([]),
    constr_params: Map([]),
    trait_params: Map([]),
    fn_param_arrows: Map([]),
    alias_arrows: Map([]),
    value_types: Map([]),
    trait_names: Map([]),
    type_params: Map([]),
  }
  // core trait method signatures (Show etc.) for impl param backfill
  let show_params : Array[IRType?] = [None, Some(IRConcrete("Logger", []))]
  symbols.trait_params["Show::output"] = show_params
  symbols
}

///|
pub(all) struct CallSiteStat {
  caller : String
  file : String
  line : Int
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
          Some(ps) => collect_fn_param_arrows(ps, name, symbols)
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
              Some(ps) => collect_fn_param_arrows(ps, key, symbols)
              None => ()
            }
          }
          None => ()
        }
      }
      TopImpl(self_ty~, trait_~, method_name~, params~, ret_ty~, ..) => {
        let self_ty_name = match self_ty {
          Some(t) => type_to_string(t)
          None => "?"
        }
        let key = self_ty_name + "::" + method_name.name
        symbols.impl_methods[key] = longident_str(trait_.name)
        symbols.fn_exists[key] = true
        collect_fn_param_arrows(params, key, symbols)
        match ret_ty {
          Some(ty) => symbols.fn_ret[key] = type_to_ir(ty, symbols)
          None => ()
        }
      }
      TopTrait(decl) => {
        symbols.trait_names[decl.name.name] = true
        for m in decl.methods {
          let key = decl.name.name + "::" + m.name.name
          let tys : Array[IRType?] = []
          for param in m.params {
            match param {
              Positional(binder~, ty~) | Labelled(binder~, ty~) => {
                ignore(binder)
                tys.push(
                  match ty {
                    Some(t) => Some(type_to_ir(t, symbols))
                    None => None
                  },
                )
              }
              _ => tys.push(None)
            }
          }
          symbols.trait_params[key] = tys
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
fn collect_fn_param_arrows(
  params : @list.List[@syntax.Parameter],
  key : String,
  symbols : PkgSymbols,
) -> Unit {
  let per_param : Array[Array[IRType?]] = []
  for param in params {
    match param {
      // DiscardPositional: mbti params arrive anonymous but still typed
      Positional(ty~, ..) | Labelled(ty~, ..) | DiscardPositional(ty~, ..) =>
        match ty {
          Some(Arrow(args~, ..)) => {
            let arrow_tys : Array[IRType?] = []
            for aty in args {
              arrow_tys.push(Some(type_to_ir(aty, symbols)))
            }
            per_param.push(arrow_tys)
          }
          Some(Name(constr_id~, ..)) =>
            // type alias that points to an arrow type (e.g. `Middleware`)
            match symbols.alias_arrows.get(longident_str(constr_id.id)) {
              Some(tys) => per_param.push(tys)
              None => per_param.push([])
            }
          _ => per_param.push([])
        }
      _ => per_param.push([])
    }
  }
  symbols.fn_param_arrows[key] = per_param
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
  mut cur_fn : String // enclosing function name (call graph caller)
}

///|
pub fn scan_package_calls(
  impls : Array[@syntax.Impl],
  file : String,
  symbols : PkgSymbols,
  stats : IRStatsResult,
) -> Unit {
  collect_symbols(impls, symbols)
  let ctx : ScanCtx = {
    symbols,
    env: Map([]),
    file,
    stats,
    pending_closure_hints: [],
    last_key: "?",
    cur_fn: "<top>",
  }
  for item in impls {
    match item {
      TopFuncDef(fun_decl~, decl_body~, ..) => {
        ctx.cur_fn = fun_decl.name.name
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
        let declared = ctx.symbols.trait_params.get(tkey)
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
  let saved : Array[(String, IRType)] = []
  let hint_arr : Array[IRType?] = match hints {
    Some(h) => h
    None => []
  }
  let mut i = 0
  for param in params {
    match param {
      Positional(binder~, ty~) =>
        bind_param_hinted(binder.name, ty, i, hint_arr, ctx, saved)
      Labelled(binder~, ty~) =>
        bind_param_hinted(binder.name, ty, i, hint_arr, ctx, saved)
      Optional(binder~, ty~, ..) =>
        bind_param_hinted(binder.name, ty, i, hint_arr, ctx, saved)
      QuestionOptional(binder~, ty~) =>
        bind_param_hinted(binder.name, ty, i, hint_arr, ctx, saved)
      DiscardPositional(..) => ()
    }
    i += 1
  }
  let _ = infer_expr(body, ctx)
  restore_env(saved, ctx)
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
    Arrow(..) => IRFn
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
        IRUnresolved
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
          Optional(binder~, ty~, ..) =>
            bind_param_hinted(binder.name, ty, i, hints, ctx, saved)
          QuestionOptional(binder~, ty~) =>
            bind_param_hinted(binder.name, ty, i, hints, ctx, saved)
          DiscardPositional(..) => ()
        }
        i += 1
      }
      let _ = infer_expr(func.body, ctx)
      restore_env(saved, ctx)
      IRFn
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
    Is(expr~, ..) => {
      let _ = infer_expr(expr, ctx)
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
      scan_func_ctx(func, ctx)
      let nm = name.name
      let saved : Array[(String, IRType)] = []
      saved.push((nm, or_unresolved(ctx.env.get(nm))))
      ctx.env[nm] = IRFn
      let t = infer_expr(body, ctx)
      restore_env(saved, ctx)
      t
    }
    LetAnd(bindings~, body~, ..) => {
      let saved : Array[(String, IRType)] = []
      for binding in bindings {
        let (binder, ty, func) = binding
        let fsaved : Array[(String, IRType)] = []
        bind_params(func.parameters, ctx, fsaved)
        let _ = infer_expr(func.body, ctx)
        restore_env(fsaved, ctx)
        saved.push((binder.name, or_unresolved(ctx.env.get(binder.name))))
        match ty {
          Some(t) => ctx.env[binder.name] = type_to_ir(t, ctx.symbols)
          None => ctx.env[binder.name] = IRFn
        }
      }
      let t = infer_expr(body, ctx)
      restore_env(saved, ctx)
      t
    }
    Let(pattern~, expr~, body~, ..) => {
      let t = infer_expr(expr, ctx)
      bind_pattern(pattern, t, ctx)
      infer_expr(body, ctx)
    }
    LetMut(binder~, ty~, expr~, body~, ..) => {
      let t = infer_expr(expr, ctx)
      match ty {
        Some(t2) => ctx.env[binder.name] = type_to_ir(t2, ctx.symbols)
        None => ctx.env[binder.name] = t
      }
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
    Try(body~, catch_~, ..) => {
      let t = infer_expr(body, ctx)
      for case in catch_ {
        let _ = infer_expr(case.body, ctx)
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
    Tuple(pats~, ..) =>
      for p in pats {
        bind_pattern(p, IRUnresolved, ctx)
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
  let arrows = ctx.symbols.fn_param_arrows.get(callee)
  let mut i = start_index
  for arg in args {
    match arg.value {
      Function(..) => {
        // set closure hints from the callee's declared arrow type
        ctx.pending_closure_hints.clear()
        match arrows {
          Some(per_param) =>
            if i < per_param.length() {
              for h in per_param[i] {
                ctx.pending_closure_hints.push(h)
              }
            }
          None => ()
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
          let known = qualified ||
            ctx.symbols.fn_exists.contains(name) ||
            is_builtin_fn(name)
          record_site(ctx, func, "static", known, name)
          ctx.stats.total_calls += 1
          ctx.stats.static_calls += 1
          if known {
            ctx.stats.static_resolved += 1
          }
          match builtin_ctor_ret(name) {
            Some(t) => t
            None => or_unresolved(get_fn_ret(ctx.symbols, name))
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
      record_site_recv(ctx, recv, true, key, name)
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
      record_site_recv(
        ctx,
        recv,
        false,
        "dyn " + t + "::" + mname,
        "trait:" + t,
      )
      ctx.stats.receiver_dispatch += 1
      IRUnresolved
    }
    IRTypeParam(p) => {
      record_site_recv(ctx, recv, false, "T:" + p + "::" + mname, "T:" + p)
      ctx.stats.receiver_dispatch += 1
      IRUnresolved
    }
    _ => {
      ctx.last_key = "?::" + mname
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
  })
}

///|
fn record_site_recv(
  ctx : ScanCtx,
  expr : @syntax.Expr,
  resolved : Bool,
  target : String,
  recv_ty : String,
) -> Unit {
  ctx.stats.sites.push({
    caller: ctx.cur_fn,
    file: ctx.file,
    line: expr.loc().start.lnum,
    kind: "receiver",
    resolved,
    target,
    recv_ty,
  })
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
  // `Type::method` statics on builtin/container types
  match key {
    "Buffer::new" | "Buffer::make" => Some(IRConcrete("Buffer", []))
    "Map::new" | "Map::copy" | "Map::create" => Some(IRConcrete("Map", []))
    "StringBuilder::new" => Some(IRConcrete("StringBuilder", []))
    "Iter::new" | "Iter::from_array" | "Iter::range" | "Iter::of" =>
      Some(IRConcrete("Iter", []))
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
pub fn run_ir_stats(root : String, config : Config) -> IRStatsResult {
  let stats = IRStatsResult::new()
  // Phase 1: module-wide symbol collection (all packages share one table)
  let symbols = PkgSymbols::new()
  walk_packages(root, config, fn(_pkg_dir, mbt_files) {
    for file in mbt_files {
      let source = @fs.read_file_to_string(file) catch { _ => return }
      let (impls, _) = @parser.parse_string(source, name=file)
      collect_symbols(impls.to_array(), symbols)
    }
  })
  // Phase 1.5: ingest dependency sources (.mooncakes) into the same table
  collect_dep_symbols(root, symbols)
  // Phase 1.6: ingest official interface files (.mbti) when present
  collect_mbti_dir(root, symbols)
  // Phase 2: per-function inference with the merged table
  walk_packages(root, config, fn(_pkg_dir, mbt_files) {
    for file in mbt_files {
      stats.files_scanned += 1
      let source = @fs.read_file_to_string(file) catch { _ => return }
      let (impls, _) = @parser.parse_string(source, name=file)
      scan_package_calls(impls.to_array(), file, symbols, stats)
    }
  })
  stats
}

// ── M2: dependency symbol tables (.mooncakes ingestion) ───────────────────

///|
fn short_key(k : String) -> String {
  // "pkg::Type::method" -> "Type::method"; "pkg::Type" -> "Type"
  let segs : Array[String] = []
  let cur = StringBuilder::new()
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
  // resolution order: exact (qualified or short as written) FIRST;
  // short_key suffix match is a LAST-RESORT fallback for receiver types
  // whose package prefix is unknown at the call site
  match symbols.impl_methods.get(key) {
    Some(t) => Some(t)
    None => symbols.impl_methods.get(short_key(key))
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
    None => symbols.struct_fields.get(short_key(tyname))
  }
}

///|
fn get_fn_ret(symbols : PkgSymbols, key : String) -> IRType? {
  // resolution order: exact key first; short_key is a last-resort fallback
  match symbols.fn_ret.get(key) {
    Some(t) => Some(t)
    None => symbols.fn_ret.get(short_key(key))
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
    }
  }
  for file in mbt_files {
    let source = @fs.read_file_to_string(file) catch { _ => continue }
    let (impls, _) = @parser.parse_string(source, name=file)
    collect_symbols(impls.to_array(), symbols)
  }
  for subdir in subdirs {
    walk_dep_dir(subdir, symbols)
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
  edges : Array[String] // "caller -> callee" resolved edges
  dispatch_edges : Array[String] // devirtualized: one per impl target
  unresolved : Array[String] // callers with unknown targets
}

///|
pub fn run_call_graph(root : String, config : Config) -> CallGraph {
  // symbols: module + deps (closed world over available sources)
  let symbols = PkgSymbols::new()
  walk_packages(root, config, fn(_pkg_dir, mbt_files) {
    for file in mbt_files {
      let source = @fs.read_file_to_string(file) catch { _ => return }
      let (impls, _) = @parser.parse_string(source, name=file)
      collect_symbols(impls.to_array(), symbols)
    }
  })
  collect_dep_symbols(root, symbols)
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
  // call sites -> edges
  let stats = IRStatsResult::new()
  walk_packages(root, config, fn(_pkg_dir, mbt_files) {
    for file in mbt_files {
      stats.files_scanned += 1
      let source = @fs.read_file_to_string(file) catch { _ => return }
      let (impls, _) = @parser.parse_string(source, name=file)
      scan_package_calls(impls.to_array(), file, symbols, stats)
    }
  })
  let edges : Array[String] = []
  let dispatch_edges : Array[String] = []
  let unresolved : Array[String] = []
  // resolve a dispatch site by TRAIT IDENTITY first ("Trait::method"),
  // then fall back to the method-name-only index
  let resolve_dispatch = fn(dyn_target : String, caller : String) -> Unit {
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
    match identity_hit {
      Some(self_tys) =>
        for st in self_tys {
          dispatch_edges.push(caller + " -> " + st + "::" + mname)
        }
      None =>
        match method_index.get(mname) {
          Some(self_tys) =>
            for st in self_tys {
              dispatch_edges.push(caller + " -> " + st + "::" + mname)
            }
          None => unresolved.push(caller + " -> ?" + mname)
        }
    }
  }
  for site in stats.sites {
    let clean_target = site.target
      .replace(old=" (unconfirmed)", new="")
      .replace(old="?", new="")
    if site.resolved {
      if site.kind == "receiver" && site.target.has_prefix("dyn ") {
        // trait-object dispatch: enumerate impls of (trait, method)
        resolve_dispatch(Show::to_string(clean_target[4:]), site.caller)
      } else {
        edges.push(site.caller + " -> " + clean_target)
      }
    } else if site.target.has_prefix("dyn ") {
      resolve_dispatch(Show::to_string(site.target[4:]), site.caller)
    } else if site.kind == "receiver" && site.recv_ty.has_prefix("trait:") {
      // receiver typed as a trait object: use its trait identity
      resolve_dispatch(clean_target, site.caller)
    } else {
      unresolved.push(site.caller + " -> ?")
    }
  }
  { edges, dispatch_edges, unresolved }
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
          collect_fn_param_arrows(func_sig.params, key, symbols)
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
    if !symbols.trait_params.contains(key) {
      let tys : Array[IRType?] = []
      for param in m.params {
        match param {
          // mbti renders params as TYPES ONLY: they arrive as
          // DiscardPositional(ty=Some(..)) — the type still flows to this
          // position for impl-param backfill
          Positional(ty~, ..)
          | Labelled(ty~, ..)
          | DiscardPositional(ty~, ..) =>
            tys.push(
              match ty {
                Some(t) => Some(type_to_ir(t, symbols))
                None => None
              },
            )
          _ => tys.push(None)
        }
      }
      symbols.trait_params[key] = tys
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
