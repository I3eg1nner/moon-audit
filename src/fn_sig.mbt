// T1.3: complete function-signature model. FnSig is the single richer
// record built during ProgramWorld loading (source decls + .mbti + lib
// models); the legacy fn_param_arrows/trait_params tables become derived
// artifacts materialized alongside (production reads go through the
// sig_* accessors in tyrecon.mbt — full table removal is T1.4 scope).

///|
pub(all) struct FnP {
  binder : String
  kind : String // positional | labelled | optional | optional-q | discard
  has_default : Bool // optional with default expression
  ty : IRType // IRUnresolved when unannotated
  arrow_args : Array[IRType?] // arrow param types when the param is a fn
} derive(Debug)

///|
pub(all) struct FnSig {
  params : Array[FnP]
  generic_constraints : Array[String] // e.g. "T : Show"
  return_ty : IRType
  error_effect : String // none | default | typed | noraise | maybe
  is_async : Bool
  entry : String // app-main | test | library-pub | ffi-extern | internal
} derive(Debug)

// T1.5: package-level entry classification (moon.pkg flags via the
// official config parser — same parse as imports, zero extra IO passes).

///|
pub fn classify_pkg(pkg_dir : String) -> String {
  let pkg_path = @path.Path(pkg_dir).join(@path.Path("moon.pkg")).0
  let content = @fs.read_file_to_string(pkg_path) catch {
    _ => return "library"
  }
  let (ast, _) = @moon_config.parse_moon_pkg(content)
  match ast {
    Obj(fields, ..) =>
      for pair in fields {
        if pair.0 == "is-main" {
          match pair.1 {
            Bool(true, ..) => return "app-main"
            _ => ()
          }
        }
        if pair.0 == "is-test" {
          match pair.1 {
            Bool(true, ..) => return "test"
            _ => ()
          }
        }
      }
    _ => ()
  }
  "library"
}

// ── FnSig construction (single source for sigs + legacy materialization) ──

///|
pub fn collect_fn_sig(
  params : @list.List[@syntax.Parameter],
  key : String,
  symbols : PkgSymbols,
  ret_ty : @syntax.Type?,
  err : @syntax.ErrorType,
  is_async : Bool,
  constraints : @list.List[@syntax.TypeVarBinder],
  entry : String,
) -> Unit {
  let fps : Array[FnP] = []
  for param in params {
    match param {
      Positional(binder~, ty~) =>
        fps.push(fn_p(binder.name, "positional", false, ty, symbols))
      Labelled(binder~, ty~) =>
        fps.push(fn_p(binder.name, "labelled", false, ty, symbols))
      Optional(binder~, ..) =>
        fps.push(fn_p(binder.name, "optional", true, None, symbols))
      QuestionOptional(binder~, ty~) =>
        fps.push(fn_p(binder.name, "optional-q", false, ty, symbols))
      // DiscardPositional carries a type (mbti anonymous params) and must
      // keep the legacy arrow/alias materialization (zero-drift)
      DiscardPositional(ty~, ..) =>
        fps.push(fn_p("_", "discard", false, ty, symbols))
    }
  }
  let gc : Array[String] = []
  for q in constraints {
    for c in q.constraints {
      gc.push(q.name + " : " + longident_str(c.trait_))
    }
  }
  let error_effect = match err {
    NoErrorType => "none"
    DefaultErrorType(..) => "default"
    ErrorType(..) => "typed"
    Noraise(..) => "noraise"
    MaybeError(..) => "maybe"
  }
  let sig : FnSig = {
    params: fps,
    generic_constraints: gc,
    return_ty: match ret_ty {
      Some(t) => type_to_ir(t, symbols)
      None => IRUnresolved
    },
    error_effect,
    is_async,
    entry,
  }
  store_fn_sig(symbols, key, sig)
}

// ── sole write points for the legacy tables (T1.4 removes them) ──────────
// fn_param_arrows is written ONLY here (derived from FnSig);
// trait_params is written ONLY in materialize_trait_from_sig below.

///|
pub fn store_fn_sig(symbols : PkgSymbols, key : String, sig : FnSig) -> Unit {
  symbols.fn_sigs[key] = sig
  let arrows : Array[Array[IRType?]] = []
  for p in sig.params {
    arrows.push(p.arrow_args)
  }
  symbols.fn_param_arrows[key] = arrows
}

///|
pub fn materialize_trait_from_sig(symbols : PkgSymbols, key : String) -> Unit {
  // trait_params derived from the stored FnSig (single trait write point;
  // used by the source TopTrait path, the .mbti TraitSig path and the
  // builtin Show::output seed — never written directly anymore)
  match symbols.fn_sigs.get(key) {
    Some(sig) => symbols.trait_params[key] = project_trait_params(sig)
    None => ()
  }
}

///|
pub fn project_trait_params(sig : FnSig) -> Array[IRType?] {
  let tys : Array[IRType?] = []
  for p in sig.params {
    if p.ty == IRUnresolved && p.arrow_args.length() == 0 {
      tys.push(None)
    } else {
      tys.push(Some(p.ty))
    }
  }
  tys
}

// T1.3/P1-2a: .mbti FuncSig -> FnSig through the same sole write point
// (params arrive as @syntax.Parameter; constraints as mbti
// TypeParamWithConstraints; every .mbti decl is public)

///|
pub fn collect_mbti_fn_sig(
  func_sig : @mbti_ast.FuncSig,
  key : String,
  symbols : PkgSymbols,
) -> Unit {
  let fps : Array[FnP] = []
  for param in func_sig.params {
    match param {
      Positional(binder~, ty~) =>
        fps.push(fn_p(binder.name, "positional", false, ty, symbols))
      Labelled(binder~, ty~) =>
        fps.push(fn_p(binder.name, "labelled", false, ty, symbols))
      Optional(binder~, ..) =>
        fps.push(fn_p(binder.name, "optional", true, None, symbols))
      QuestionOptional(binder~, ty~) =>
        fps.push(fn_p(binder.name, "optional-q", false, ty, symbols))
      DiscardPositional(ty~, ..) =>
        fps.push(fn_p("_", "discard", false, ty, symbols))
    }
  }
  let gc : Array[String] = []
  for tp in func_sig.type_params {
    for c in tp.constraints {
      gc.push(tp.name.name + " : " + longident_str(c.name))
    }
  }
  let (ret_ty, err) = func_sig.return_
  let error_effect = match err {
    NoErrorType => "none"
    DefaultErrorType(..) => "default"
    ErrorType(..) => "typed"
    Noraise(..) => "noraise"
    MaybeError(..) => "maybe"
  }
  store_fn_sig(symbols, key, {
    params: fps,
    generic_constraints: gc,
    return_ty: type_to_ir(ret_ty, symbols),
    error_effect,
    is_async: func_sig.is_async != None,
    entry: "library-pub",
  })
}

///|
fn fn_p(
  name : String,
  kind : String,
  has_default : Bool,
  ty : @syntax.Type?,
  symbols : PkgSymbols,
) -> FnP {
  // legacy zero-drift rule: arrow/alias materialization applies ONLY to
  // positional/labelled/discard params (Optional/QuestionOptional pushed
  // [] in the legacy collector regardless of annotation)
  if kind == "optional" || kind == "optional-q" {
    return {
      binder: name,
      kind,
      has_default,
      ty: IRUnresolved,
      arrow_args: [],
    }
  }
  match ty {
    Some(Arrow(args~, ..)) => {
      let arrow_args : Array[IRType?] = []
      for aty in args {
        arrow_args.push(Some(type_to_ir(aty, symbols)))
      }
      { binder: name, kind, has_default, ty: IRFn(name), arrow_args, }
    }
    Some(t) => {
      // alias-to-arrow (e.g. `middleware : Middleware` where the alias
      // points at an arrow type) must survive materialization exactly as
      // the legacy collector did
      let tname = match t {
        Name(constr_id~, ..) => longident_str(constr_id.id)
        _ => ""
      }
      if tname != "" {
        match symbols.alias_arrows.get(tname) {
          Some(arrow_args) =>
            return {
              binder: name,
              kind,
              has_default,
              ty: type_to_ir(t, symbols),
              arrow_args,
            }
          None => ()
        }
      }
      {
        binder: name,
        kind,
        has_default,
        ty: type_to_ir(t, symbols),
        arrow_args: [],
      }
    }
    None =>
      { binder: name, kind, has_default, ty: IRUnresolved, arrow_args: [], }
  }
}

// ── unified read accessors (production entry points) ─────────────────────

///|
pub fn sig_arrow_args(
  symbols : PkgSymbols,
  key : String,
) -> Array[Array[IRType?]]? {
  match symbols.fn_sigs.get(key) {
    Some(sig) => {
      let arrows : Array[Array[IRType?]] = []
      for p in sig.params {
        arrows.push(p.arrow_args)
      }
      Some(arrows)
    }
    None => symbols.fn_param_arrows.get(key) // legacy fallback (T1.4 removes)
  }
}

///|
pub fn sig_trait_params(symbols : PkgSymbols, key : String) -> Array[IRType?]? {
  match symbols.fn_sigs.get(key) {
    Some(sig) => Some(project_trait_params(sig))
    None => symbols.trait_params.get(key) // legacy fallback (T1.4 removes)
  }
}

// P1-2b: .mbti TraitMethodSig -> FnSig (same sole write points);
// mirrors collect_mbti_fn_sig for the trait-method shape

///|
pub fn collect_mbti_trait_method(
  m : @mbti_ast.TraitMethodSig,
  key : String,
  symbols : PkgSymbols,
) -> Unit {
  let fps : Array[FnP] = []
  for param in m.params {
    match param {
      Positional(binder~, ty~) =>
        fps.push(fn_p(binder.name, "positional", false, ty, symbols))
      Labelled(binder~, ty~) =>
        fps.push(fn_p(binder.name, "labelled", false, ty, symbols))
      Optional(binder~, ..) =>
        fps.push(fn_p(binder.name, "optional", true, None, symbols))
      QuestionOptional(binder~, ty~) =>
        fps.push(fn_p(binder.name, "optional-q", false, ty, symbols))
      DiscardPositional(ty~, ..) =>
        fps.push(fn_p("_", "discard", false, ty, symbols))
    }
  }
  let gc : Array[String] = []
  for tp in m.type_params {
    for c in tp.constraints {
      gc.push(tp.name.name + " : " + longident_str(c.name))
    }
  }
  let (ret_ty, err) = m.return_
  let error_effect = match err {
    NoErrorType => "none"
    DefaultErrorType(..) => "default"
    ErrorType(..) => "typed"
    Noraise(..) => "noraise"
    MaybeError(..) => "maybe"
  }
  store_fn_sig(symbols, key, {
    params: fps,
    generic_constraints: gc,
    return_ty: type_to_ir(ret_ty, symbols),
    error_effect,
    is_async: m.is_async != None,
    entry: "internal", // trait method declaration (no body)
  })
}
