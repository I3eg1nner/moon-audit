// M1 type-reconstruction spike unit tests (see docs/ir/PLAN.md)

///|
fn test_tmp(sub : String) -> String {
  // cross-platform temp base without @sys (unavailable in lib tests):
  // try /tmp first; on Windows that fails, fall back to a relative dir
  // under the test working directory (writable in CI sandboxes)
  // side-effect-free probe: read_dir succeeds iff /tmp exists & readable
  ignore(
    @fs.read_dir("/tmp") catch {
      _ => {
        // create the fallback base once: tests only create their leaf dir
        @fs.create_dir("./moon_audit_test_tmp") catch {
          _ => ()
        }
        return "./moon_audit_test_tmp/" + sub
      }
    },
  )
  "/tmp/" + sub
}

///|
fn scan_src(src : String) -> (IRStatsResult, PkgSymbols) {
  let (impls, _) = @parser.parse_string(src, name="t.mbt")
  let symbols = PkgSymbols::new()
  let stats = IRStatsResult::new()
  scan_package_calls(impls.to_array(), "t.mbt", symbols, stats)
  (stats, symbols)
}

///|
test "static_type_method_resolves" {
  let (stats, _) = scan_src("pub fn go(x : Int) -> Int { Int::max(x, 1) }")
  inspect(stats.total_calls, content="1")
  inspect(stats.static_calls, content="1")
  // builtin type method: identity known (call graph edge exists)
  inspect(stats.static_resolved, content="0")
  inspect(stats.receiver_calls, content="0")
}

///|
test "annotated_param_receiver_concrete" {
  let (stats, _) = scan_src(
    "pub struct Req { url : String } pub fn go(r : Req) -> Unit { ignore(r.url) }",
  )
  // r.url is a field access; the only call is ignore(...) itself
  inspect(stats.total_calls, content="1")
  inspect(stats.static_calls, content="1")
  inspect(stats.receiver_calls, content="0")
}

///|
test "local_fn_static_resolution" {
  let (stats, _) = scan_src(
    "fn helper(a : Int) -> Int { a + 1 } pub fn go() -> Int { helper(1) }",
  )
  inspect(stats.total_calls, content="1")
  inspect(stats.static_resolved, content="1")
}

///|
test "let_chain_type_propagation" {
  let (stats, _) = scan_src(
    "pub struct Req { url : String } pub fn go(r : Req) -> Int { let u = r.url; u.length() }",
  )
  inspect(stats.receiver_calls, content="1")
  inspect(stats.receiver_resolved, content="1")
}

///|
test "record_literal_inference" {
  let (stats, _) = scan_src(
    "pub struct Req { url : String } pub fn go() -> Int { let r = Req::{ url: \"x\" }; r.url.length() }",
  )
  inspect(stats.receiver_calls, content="1")
  inspect(stats.receiver_resolved, content="1")
}

///|
test "trait_impl_method_resolution" {
  let (stats, _) = scan_src(
    "pub trait Writer { fn output(Self, s : String) -> Unit } pub struct Box { v : Int } pub impl Writer for Box with fn output(self, s) -> Unit { ignore(s.length()) }",
  )
  // s is backfilled from the trait declaration (String)
  inspect(stats.receiver_calls, content="1")
  inspect(stats.receiver_resolved, content="1")
}

///|
test "closure_hint_backfill_from_alias" {
  let (stats, _) = scan_src(
    "pub type Mid = (String, Int) -> Unit pub fn call_it(mid : Mid) -> Unit { ignore(mid) } pub fn go() -> Unit { call_it(fn(s, n) { ignore(s.length()); ignore(n + 1) }) }",
  )
  inspect(stats.receiver_calls, content="1")
  inspect(stats.receiver_resolved, content="1")
}

///|
test "foreach_binder_element_type" {
  let (stats, _) = scan_src(
    "pub fn go(xs : Array[String]) -> Unit { for x in xs { ignore(x.length()) } }",
  )
  inspect(stats.receiver_calls, content="1")
  inspect(stats.receiver_resolved, content="1")
}

///|
test "map_get_value_chain" {
  let (stats, _) = scan_src(
    "pub fn go(m : Map[String, String]) -> Int { let v = m.get(\"k\"); ignore(v); 0 }",
  )
  // Map receiver is concrete via annotation
  inspect(stats.receiver_calls, content="1")
  inspect(stats.receiver_resolved, content="1")
}

///|
test "higher_order_shadowed_call" {
  let (stats, _) = scan_src("pub fn go(f : (Int) -> Int) -> Int { f(1) }")
  inspect(stats.total_calls, content="1")
  inspect(stats.higher_calls, content="1")
}

///|
test "qualified_static_identity" {
  let (stats, _) = scan_src("pub fn go() -> Unit { @strconv.parse_int(\"1\") }")
  inspect(stats.total_calls, content="1")
  inspect(stats.static_resolved, content="1")
}

///|
test "builtin_ctor_map" {
  let (stats, _) = scan_src(
    "pub fn go() -> Unit { let m = Map([]); m.set(\"a\", 1) }",
  )
  inspect(stats.receiver_calls, content="1")
  inspect(stats.receiver_resolved, content="1")
}

///|
test "irtype_display_parametric" {
  let t : IRType = IRType::IRConcrete("Array", [
    IRType::IRConcrete("String", []),
  ])
  inspect(t.display(), content="Array[String]")
  inspect(IRType::IRUnresolved.display(), content="?")
  assert_eq(IRType::IRConcrete("Int", []).is_concrete(), true)
  assert_eq(IRType::IRUnit.is_concrete(), false)
}

///|
test "combined_resolution_math" {
  let stats = IRStatsResult::new()
  stats.total_calls = 10
  stats.static_resolved = 5
  stats.receiver_resolved = 3
  inspect(stats.combined_resolution(), content="80")
}

///|
test "m3_structural_summary_cross_function" {
  let src = "fn set_custom(res : Response, val : String) -> Unit { res.set_header(\"X-Custom\", val) } pub fn handler(res : Response, req : Request) -> Unit { let v = req.query(\"q\"); set_custom(res, v) }"
  let (impls, _) = @parser.parse_string(src, name="t.mbt")
  let ictx = InterProceduralContext::new()
  collect_func_summaries_flow(impls, "t.mbt", ictx)
  // summary must record val -> HeaderValue for set_custom
  inspect(ictx.summaries.contains("set_custom"), content="true")
  let findings : Array[Finding] = []
  let imports : ImportContext = {
    has_cmark: false,
    has_rabbita: false,
    has_mocket: true,
    has_crescent: false,
    has_liquid: false,
    has_pug: false,
    is_stdlib: false,
  }
  run_cross_func_taint(impls, "t.mbt", src, findings, ictx, imports)
  inspect(findings.length() > 0, content="true")
}

///|
test "phase2_mbti_ingestion" {
  // official mbti_parser: public signature becomes a resolvable static target
  let src = "pub fn go() -> Unit { dep_pub(1) }"
  let (impls, _) = @parser.parse_string(src, name="t.mbt")
  let symbols = PkgSymbols::new()
  let stats = IRStatsResult::new()
  // simulate an interface file
  let dir = test_tmp("mbti_test_pkg")
  @fs.create_dir(dir) catch {
    _ => ()
  }
  let f = dir + "/pkg.generated.mbti"
  @fs.write_string_to_file(f, "package \"x/y\"\n\npub fn dep_pub(Int) -> Int\n") catch {
    _ => ()
  }
  collect_mbti_file(f, symbols)
  inspect(symbols.fn_exists.contains("dep_pub"), content="true")
  scan_package_calls(impls.to_array(), "t.mbt", symbols, stats)
  inspect(stats.static_resolved, content="1")
}

///|
test "phase2a_mbti_type_trait_impl_ingestion" {
  // full ingestion: struct fields (Type), method set (Trait), and the
  // impl->trait join (Impl + method FuncSig), all from an interface file
  let src = "pub fn go(h : Holder) -> Int { h.payload.token().length() }"
  let (impls, _) = @parser.parse_string(src, name="t.mbt")
  let symbols = PkgSymbols::new()
  let dir = test_tmp("mbti_p2a")
  @fs.create_dir(dir) catch {
    _ => ()
  }
  let f = dir + "/pkg.generated.mbti"
  @fs.write_string_to_file(
    f, "package \"x/y\"\n\npub struct Holder {\n  payload : Token2\n}\n\npub trait Tokenizer {\n  fn token(Self) -> String\n}\n\npub impl Tokenizer for Token2\n\npub fn Token2::token(Self) -> String\n",
  ) catch {
    _ => ()
  }
  collect_mbti_file(f, symbols)
  // Type ingestion: struct fields registered
  inspect(symbols.struct_fields.contains("Holder"), content="true")
  // Impl + Func join: trait identity attached to "SelfTy::method"
  inspect(symbols.impl_methods.contains("Token2::token"), content="true")
  // (a) chain resolution through mbti struct field + mbti method signature:
  // Holder -> payload : Token2 -> token() : String -> length() : Int
  let stats = IRStatsResult::new()
  scan_package_calls(impls.to_array(), "t.mbt", symbols, stats)
  inspect(stats.receiver_resolved, content="2")
  inspect(stats.receiver_unknown, content="0")
}

///|
test "phase2a_mbti_trait_backfill_and_const" {
  // (b) impl body params backfilled from a trait declared ONLY in .mbti;
  // plus Const/Value ingestion feeding local type reconstruction
  let src = "pub struct Box3 { v : Int } pub impl Writer2 for Box3 with fn output(self, buf) -> Unit { buf.write_string(self.v.to_string()) } pub fn use_limit() -> String { let x = limit; x.to_string() }"
  let (impls, _) = @parser.parse_string(src, name="t.mbt")
  let symbols = PkgSymbols::new()
  let dir = test_tmp("mbti_p2b")
  @fs.create_dir(dir) catch {
    _ => ()
  }
  let f = dir + "/pkg.generated.mbti"
  @fs.write_string_to_file(
    f, "package \"x/y\"\n\npub trait Writer2 {\n  fn output(Self, String) -> Unit\n}\n\npub let limit : Int\n",
  ) catch {
    _ => ()
  }
  collect_mbti_file(f, symbols)
  inspect(symbols.trait_params.contains("Writer2::output"), content="true")
  inspect(symbols.value_types.contains("limit"), content="true")
  let stats = IRStatsResult::new()
  scan_package_calls(impls.to_array(), "t.mbt", symbols, stats)
  // buf : String (backfilled), self.v : Int field, x : Int (const value type)
  inspect(stats.receiver_resolved, content="3")
  inspect(stats.receiver_unknown, content="0")
}

///|
test "phase2a_mbti_source_wins" {
  // conflict rule: symbols collected from source take precedence;
  // .mbti only supplements what is missing
  let symbols = PkgSymbols::new()
  // pre-seed as the source pass would
  symbols.fn_exists["conflicted"] = true
  symbols.fn_ret["conflicted"] = IRType::IRConcrete("Source", [])
  let dir = test_tmp("mbti_p2c")
  @fs.create_dir(dir) catch {
    _ => ()
  }
  let f = dir + "/pkg.generated.mbti"
  @fs.write_string_to_file(
    f, "package \"x/y\"\n\npub fn conflicted() -> MbtiType\n\npub fn only_in_mbti() -> Int\n",
  ) catch {
    _ => ()
  }
  collect_mbti_file(f, symbols)
  inspect(
    symbols.fn_ret.get("conflicted") == Some(IRType::IRConcrete("Source", [])),
    content="true",
  )
  inspect(symbols.fn_exists.contains("only_in_mbti"), content="true")
}

///|
test "mbti_trait_params_render_as_types_only" {
  // regression guard: mbti trait methods render params as TYPES ONLY
  // (names are erased in interfaces); named params are a parse error
  @fs.create_dir(test_tmp("mbti_dbg")) catch {
    _ => ()
  }
  @fs.write_string_to_file(
    test_tmp("mbti_dbg/pkg.generated.mbti"),
    "package \"x/y\"\n\npub trait Writer2 {\n  fn output(Self, String) -> Unit\n}\n\npub let limit : Int\n",
  ) catch {
    _ => ()
  }
  let source = @fs.read_file_to_string(test_tmp("mbti_dbg/pkg.generated.mbti")) catch {
    _ => ""
  }
  let (_m, reports) = @mbti_parser.parse_string(source, name="probe")
  inspect(reports.length(), content="0")
}

///|
test "phase2b_amp_trait_receiver_is_dispatch" {
  // review counterexample: &Alpha param must classify as trait-object
  // dispatch (not unknown receiver)
  let src = "pub trait Alpha { fn act(Self) -> Unit } pub struct B { v : Int } pub impl Alpha for B with fn act(self) -> Unit { ignore(self.v) } pub fn f(x : &Alpha) -> Unit { x.act() }"
  let (stats, symbols) = scan_src(src)
  ignore(symbols)
  inspect(stats.receiver_calls, content="1")
  inspect(stats.receiver_dispatch, content="1")
  inspect(stats.receiver_unknown, content="0")
  // site records the trait identity
  let mut found = false
  for site in stats.sites {
    if site.kind == "receiver" && site.recv_ty == "trait:Alpha" {
      found = true
    }
  }
  assert_true(found)
}

///|
test "phase2b_devirtualized_dispatch_edge" {
  // call-graph: &Alpha receiver yields a dispatch edge f -> B::act
  let dir = test_tmp("p2b_cg/src")
  // create both levels: fs.create_dir is not recursive
  @fs.create_dir(test_tmp("p2b_cg")) catch {
    _ => ()
  }
  @fs.create_dir(dir) catch {
    _ => ()
  }
  let snippet = "pub trait Alpha { fn act(Self) -> Unit } pub struct B { v : Int } pub impl Alpha for B with fn act(self) -> Unit { ignore(self.v) } pub fn f(x : &Alpha) -> Unit { x.act() }"
  @fs.write_string_to_file(dir + "/lib.mbt", "// probe\n" + snippet + "\n") catch {
    _ => ()
  }
  let cg = run_call_graph(test_tmp("p2b_cg"), Config::default())
  let mut hit = false
  for e in cg.dispatch_edges {
    if e == "f -> B::act" {
      hit = true
    }
  }
  assert_true(hit)
}

///|
test "phase2b_qualified_keys_no_cross_package_overwrite" {
  // two packages exporting the same Trait::method must coexist:
  // exact (qualified) keys take priority; short key is fallback only
  let symbols = PkgSymbols::new()
  symbols.impl_methods["pkgA::Foo::act"] = "TraitA"
  symbols.impl_methods["pkgB::Foo::act"] = "TraitB"
  assert_true(get_impl_method(symbols, "pkgA::Foo::act") == Some("TraitA"))
  assert_true(get_impl_method(symbols, "pkgB::Foo::act") == Some("TraitB"))
  // mbti ingestion registers qualified identities alongside short keys
  let f = test_tmp("p2b_mbti/pkg.generated.mbti")
  @fs.create_dir(test_tmp("p2b_mbti")) catch {
    _ => ()
  }
  @fs.remove_file(f) catch {
    _ => ()
  } // avoid stale interfaces from older runs
  @fs.write_string_to_file(
    f, "package \"alpha/dep\"\n\npub fn Foo::act(Int) -> Int\n",
  ) catch {
    _ => ()
  }
  let s2 = PkgSymbols::new()
  collect_mbti_file(f, s2)
  inspect(s2.fn_exists.contains("Foo::act"), content="true")
  inspect(s2.fn_exists.contains("alpha/dep::Foo::act"), content="true")
}

// ---------------------------------------------------------------------------
// P3 summaries: return-value flow + field writes
// ---------------------------------------------------------------------------

///|
test "p3_summary_return_flow_recorded" {
  let src = "fn wrap(s : String) -> String { s }"
  let (impls, _) = @parser.parse_string(src, name="t.mbt")
  let ictx = InterProceduralContext::new()
  collect_func_summaries_flow(impls, "t.mbt", ictx)
  match ictx.summaries.get("wrap") {
    Some(s) => {
      inspect(s.ret_from.length(), content="1")
      inspect(s.ret_from[0], content="s")
    }
    None => inspect(true, content="false")
  }
}

///|
test "p3_summary_field_write_recorded" {
  let src = "fn fill(b : Box, s : String) -> Unit { b.v = s }"
  let (impls, _) = @parser.parse_string(src, name="t.mbt")
  let ictx = InterProceduralContext::new()
  collect_func_summaries_flow(impls, "t.mbt", ictx)
  match ictx.summaries.get("fill") {
    Some(s) => {
      inspect(s.field_taint.contains("b"), content="true")
      match s.field_taint.get("b") {
        Some(entries) => {
          inspect(entries.length(), content="1")
          inspect(entries[0].0, content="v")
          inspect(entries[0].1, content="s")
        }
        None => inspect(true, content="false")
      }
    }
    None => inspect(true, content="false")
  }
}

///|
test "p3_return_flow_end_to_end_alerts" {
  // acceptance (a): tainted value through wrap() into a header sink
  let src = "fn wrap(s : String) -> String { s } pub fn caller(resp : Response, req : Request) -> Unit { let v = req.query(\"q\"); resp.set_header(\"X\", wrap(v)) }"
  let (impls, _) = @parser.parse_string(src, name="t.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "t.mbt", src, findings, Error)
  inspect(findings.length() > 0, content="true")
}

///|
test "p3_field_write_end_to_end_alerts_via_ictx" {
  // acceptance (b): fill() writes tainted param into a field of another
  // param; the caller reads the field into a header sink — the field-write
  // summary consumed at the call site taints the receiver argument
  let fill_src = "fn fill(b : Box, s : String) -> Unit { b.v = s }"
  let (fill_impls, _) = @parser.parse_string(fill_src, name="lib.mbt")
  let ictx = InterProceduralContext::new()
  collect_func_summaries_flow(fill_impls, "lib.mbt", ictx)
  inspect(ictx.summaries.contains("fill"), content="true")
  let caller_src = "pub fn caller(resp : Response, req : Request) -> Unit { let b = Box::{v: \"\"}; fill(b, req.query(\"q\")); resp.set_header(\"X\", b.v) }"
  let (caller_impls, _) = @parser.parse_string(caller_src, name="app.mbt")
  let findings : Array[Finding] = []
  run_cwe113(caller_impls, "app.mbt", caller_src, findings, Error, ictx~)
  inspect(findings.length() > 0, content="true")
  // without the summary the field read stays a config-like Clean (known
  // approximation before P3 — documented); the summary is what closes it
  let findings2 : Array[Finding] = []
  run_cwe113(caller_impls, "app.mbt", caller_src, findings2, Error)
  inspect(findings2.length(), content="0")
}

///|
test "p4_closure_annotated_alloc_site" {
  let src = "pub fn go() -> Unit { let h = fn(s : String) { ignore(s.length()) }; h(\"x\") }"
  let (impls, _) = @parser.parse_string(src, name="t.mbt")
  let symbols = PkgSymbols::new()
  let stats = IRStatsResult::new()
  scan_package_calls(impls.to_array(), "t.mbt", symbols, stats)
  // s.length() resolves via annotation
  inspect(stats.receiver_resolved, content="1")
  // h("x") reclassified higher -> static resolved ($closure target)
  inspect(stats.higher_calls, content="0")
  inspect(stats.static_resolved >= 2, content="true") // ignore + h("x")
  inspect(
    stats.sites.filter(fn(s) { s.target.has_prefix("$closure:") }).length(),
    content="1",
  )
}

///|
test "p4_closure_unannotated_backfilled_at_call" {
  let src = "pub fn go() -> Unit { let h = fn(s) { ignore(s.length()) }; h(\"x\") }"
  let (impls, _) = @parser.parse_string(src, name="t.mbt")
  let symbols = PkgSymbols::new()
  let stats = IRStatsResult::new()
  scan_package_calls(impls.to_array(), "t.mbt", symbols, stats)
  // closure body deferred to call site; arg "x" (String) backfills s
  inspect(stats.receiver_resolved, content="1")
  inspect(stats.receiver_unknown, content="0")
  inspect(stats.higher_calls, content="0")
  inspect(stats.static_resolved >= 2, content="true")
}

///|
test "p4_closure_uncalled_unannotated_deferred" {
  // never called: body not walked at all (no phantom unknowns, no double count)
  let src = "pub fn go() -> Unit { let h = fn(s) { ignore(s.length()) }; ignore(h) }"
  let (impls, _) = @parser.parse_string(src, name="t.mbt")
  let symbols = PkgSymbols::new()
  let stats = IRStatsResult::new()
  scan_package_calls(impls.to_array(), "t.mbt", symbols, stats)
  inspect(stats.receiver_unknown, content="0")
  inspect(stats.receiver_resolved, content="0")
}

///|
test "e1_extern_stub_signature_ingestion" {
  // extern declarations (DeclStubs) carry full signatures; calls through
  // their return values must resolve
  let source = "pub struct Conn { fd : Int } extern \"C\" fn mg_connect(url : String) -> Conn = \"c\" \"mg_connect\" pub fn go() -> Unit { let conn = mg_connect(\"x\"); ignore(conn.fd) }"
  let (impls, _) = @parser.parse_string(source, name="t.mbt")
  let symbols = PkgSymbols::new()
  let stats = IRStatsResult::new()
  scan_package_calls(impls.to_array(), "t.mbt", symbols, stats)
  inspect(symbols.fn_exists.contains("mg_connect"), content="true")
  match symbols.fn_ret.get("mg_connect") {
    Some(IRConcrete("Conn", _)) => inspect("ok", content="ok")
    _ => inspect("missing or wrong ret type", content="ok")
  }
  // mg_connect + ignore(...) both resolve as static targets
  inspect(stats.static_resolved, content="2")
}

///|
test "e1_tuple_pattern_from_map_elem" {
  let source = "pub fn go(m : Map[String, Int]) -> Int { for pair in m { let (k, v) = pair; ignore(k.length()); v } 0 }"
  let (impls, _) = @parser.parse_string(source, name="t.mbt")
  let symbols = PkgSymbols::new()
  let stats = IRStatsResult::new()
  scan_package_calls(impls.to_array(), "t.mbt", symbols, stats)
  inspect(stats.receiver_unknown, content="0")
  inspect(stats.receiver_resolved, content="1")
}

///|
test "e1_builtin_map_each_closure_hints" {
  let source = "pub fn go(m : Map[String, Int]) -> Unit { m.each((k, v) => ignore(k.length())) }"
  let (impls, _) = @parser.parse_string(source, name="t.mbt")
  let symbols = PkgSymbols::new()
  let stats = IRStatsResult::new()
  scan_package_calls(impls.to_array(), "t.mbt", symbols, stats)
  inspect(stats.receiver_unknown, content="0")
}

///|
test "e1_core_trait_static_returns" {
  let source = "pub fn go(x : Int) -> Int { Show::to_string(x).length() }"
  let (impls, _) = @parser.parse_string(source, name="t.mbt")
  let symbols = PkgSymbols::new()
  let stats = IRStatsResult::new()
  scan_package_calls(impls.to_array(), "t.mbt", symbols, stats)
  inspect(stats.receiver_unknown, content="0")
}

///|
fn e2_setup_dep_mbti() -> String raise {
  let dir = test_tmp("e2_dep_pkg")
  @fs.create_dir(dir) catch {
    _ => ()
  }
  let f = dir + "/pkg.generated.mbti"
  @fs.write_string_to_file(
    f, "package \"acme/dep\"\n\npub fn make() -> Req\n\npub fn Req::hello(Self) -> String\n",
  )
  f
}

///|
test "e2_dep_mbti_signature_resolves_call_and_receiver" {
  // (a) dep .mbti signature resolves the call; (b) return type feeds the
  // receiver chain so Req::hello becomes concrete
  let f = e2_setup_dep_mbti()
  let symbols = PkgSymbols::new()
  collect_mbti_file(f, symbols)
  inspect(symbols.fn_exists.contains("acme/dep::make"), content="true")
  inspect(symbols.fn_ret.get("acme/dep::make") != None, content="true")
  let src = "pub struct Wrap { q : Req } pub fn go(w : Wrap) -> Unit { let r = @dep.make(); ignore(r.hello()); ignore(w.q.hello()) }"
  let (impls, _) = @parser.parse_string(src, name="t.mbt")
  let stats = IRStatsResult::new()
  let aliases : Map[String, String] = Map([])
  aliases["dep"] = "acme/dep"
  scan_package_calls(
    impls.to_array(),
    "t.mbt",
    symbols,
    stats,
    pkg_alias=aliases,
  )
  // @dep.make resolved via alias -> qualified key
  inspect(stats.static_resolved >= 1, content="true")
  // r.hello() and w.q.hello() resolved via .mbti return type / field type
  inspect(stats.receiver_resolved >= 1, content="true")
}

///|
test "e2_alias_expansion_hits_qualified_key" {
  // (b) without the alias map the qualified key is unreachable; with it,
  // fn_exists/fn_ret hit the package-qualified registration
  let f = e2_setup_dep_mbti()
  let symbols = PkgSymbols::new()
  collect_mbti_file(f, symbols)
  let src = "pub fn go() -> Unit { @dep.make() }"
  let (impls, _) = @parser.parse_string(src, name="t.mbt")
  let stats_noalias = IRStatsResult::new()
  scan_package_calls(impls.to_array(), "t.mbt", symbols, stats_noalias)
  // bare fallback cannot reach "acme/dep::make" ret (site still known as
  // qualified static identity, but ret stays Unresolved) — with alias the
  // ret resolves, which is observable through a receiver chain
  let stats_alias = IRStatsResult::new()
  let aliases : Map[String, String] = Map([])
  aliases["dep"] = "acme/dep"
  scan_package_calls(
    impls.to_array(),
    "t.mbt",
    symbols,
    stats_alias,
    pkg_alias=aliases,
  )
  inspect(stats_alias.static_resolved, content="1")
  inspect(
    stats_noalias.static_resolved < stats_alias.static_resolved ||
    stats_noalias.static_resolved == stats_alias.static_resolved,
    content="true",
  )
}

///|
test "e2_letfn_call_static_not_higher" {
  // (c) local fn bound by LetFn registers as closure allocation site:
  // calling it resolves to $closure target instead of higher-order
  let src = "pub fn go() -> Int { fn helper(x : Int) -> Int { x + 1 }; helper(2) }"
  let (impls, _) = @parser.parse_string(src, name="t.mbt")
  let symbols = PkgSymbols::new()
  let stats = IRStatsResult::new()
  scan_package_calls(impls.to_array(), "t.mbt", symbols, stats)
  inspect(stats.higher_calls, content="0")
  inspect(stats.static_resolved >= 1, content="true") // helper call resolves
  // the call site resolves to the closure allocation site target
  let found = stats.sites.any(fn(s) {
    s.kind == "static" && s.target == "$closure:helper@1"
  })
  inspect(found, content="true")
}

///|
test "gate3_p2_1_dep_canonical_pkg_strips_source_layout" {
  // self-contained fixture (CI has no /data/my checkout): build a
  // .mooncakes-like tree in /tmp with source="src" layout
  let root = test_tmp("gate3_p2_1_fixture")
  let async_src = root + "/.mooncakes/moonbitlang/async/src"
  // create_dir is not recursive: build the chain level by level (root first)
  @fs.create_dir(root) catch {
    _ => ()
  }
  let mut cur = root
  for seg in ["/.mooncakes", "/moonbitlang", "/async", "/src", "/http"] {
    cur = cur + seg
    @fs.create_dir(cur) catch {
      _ => ()
    }
  }
  // dep_canonical_pkg reads the REPO-ROOT moon.mod (like the real async repo)
  @fs.write_string_to_file(
    root + "/.mooncakes/moonbitlang/async/moon.mod",
    "name = \"moonbitlang/async\"\nsource = \"src\"\n",
  ) catch {
    _ => ()
  }
  // physical path -> canonical identity (source segment stripped)
  inspect(
    dep_canonical_pkg(async_src + "/http"),
    content="moonbitlang/async/http",
  )
  // repo root package (src itself) -> owner/repo
  inspect(dep_canonical_pkg(async_src), content="moonbitlang/async")
  // moon.mod unreadable -> conservative: keep physical path (no strip)
  inspect(
    dep_canonical_pkg("/x/.mooncakes/moonbitlang/async/src"),
    content="moonbitlang/async/src",
  )
  // non-src layout: path preserved untouched
  inspect(
    dep_canonical_pkg("/x/.mooncakes/moonbitlang/x/fs"),
    content="moonbitlang/x/fs",
  )
  // outside .mooncakes: empty
  inspect(dep_canonical_pkg("/data/my/moon-audit/src"), content="")
}

// ---------------------------------------------------------------------------
// Taint rule DSL (A1)
// ---------------------------------------------------------------------------

///|
test "taint_dsl_custom_source_and_sink" {
  let src = "pub fn go(env : Env) -> Unit { let v = env.fetch_input(); env.custom_set(\"X\", v) }"
  let (impls, _) = @parser.parse_string(src, name="t.mbt")
  let findings : Array[Finding] = []
  // no rules: neither fetch_input (source) nor custom_set (sink) is known
  run_cwe113(impls, "t.mbt", src, findings, Error)
  inspect(findings.length(), content="0")
  // with DSL: fetch_input is a source, custom_set is a header sink
  let rules : TaintRuleset = {
    sources: [
      { method_name: "fetch_input", kind: "QueryParam", value_slot: 1, },
    ],
    sinks: [{ method_name: "custom_set", kind: "HeaderValue", value_slot: 1, }],
    sanitizers: [],
    fn_types: [],
    callbacks: [],
    extends: [],
  }
  let findings2 : Array[Finding] = []
  run_cwe113(impls, "t.mbt", src, findings2, Error, rules~)
  inspect(findings2.length(), content="1")
}

///|
test "taint_dsl_custom_sanitizer" {
  let src = "pub fn go(env : Env, val : String) -> Unit { env.custom_set(\"X\", env.cleanse(val)) }"
  let (impls, _) = @parser.parse_string(src, name="t.mbt")
  let rules : TaintRuleset = {
    sources: [],
    sinks: [{ method_name: "custom_set", kind: "HeaderValue", value_slot: 1, }],
    sanitizers: [{ method_name: "cleanse", kind: "", value_slot: 0, }],
    fn_types: [],
    callbacks: [],
    extends: [],
  }
  let findings : Array[Finding] = []
  run_cwe113(impls, "t.mbt", src, findings, Error, rules~)
  inspect(findings.length(), content="0")
}

///|
test "taint_dsl_value_slot" {
  // custom sink whose value is the FIRST positional arg
  let src = "pub fn go(env : Env, val : String) -> Unit { env.h(\"danger\", val) }"
  let (impls, _) = @parser.parse_string(src, name="t.mbt")
  let rules : TaintRuleset = {
    sources: [],
    sinks: [{ method_name: "h", kind: "HeaderValue", value_slot: 0, }],
    sanitizers: [],
    fn_types: [],
    callbacks: [],
    extends: [],
  }
  let findings : Array[Finding] = []
  run_cwe113(impls, "t.mbt", src, findings, Error, rules~)
  // slot 0 = "danger" (constant) => no finding from val at slot 1
  inspect(findings.length(), content="0")
}

///|
test "taint_dsl_load_from_file" {
  let dir = test_tmp("taint_dsl_test")
  @fs.create_dir(dir) catch {
    _ => ()
  }
  let f = dir + "/taint-rules.json"
  @fs.write_string_to_file(
    f, "{ \"sources\": [{ \"method\": \"fetch_input\", \"kind\": \"QueryParam\" }], \"sinks\": [{ \"method\": \"custom_set\", \"kind\": \"HeaderValue\", \"value_slot\": 1 }], \"sanitizers\": [{ \"method\": \"cleanse\" }] }",
  ) catch {
    _ => ()
  }
  let (rs, source) = load_taint_rules(dir)
  inspect(source, content=f)
  inspect(rs.sources.length(), content="1")
  inspect(rs.sinks.length(), content="1")
  inspect(rs.sanitizers.length(), content="1")
  inspect(rs.source_hit("fetch_input"), content="true")
  inspect(rs.header_sink_hit("custom_set"), content="true")
  inspect(rs.sanitizer_hit("cleanse"), content="true")
  inspect(rs.sink_value_slot("custom_set") == Some(1), content="true")
}

///|
test "taint_dsl_no_file_is_builtin" {
  let (rs, source) = load_taint_rules(test_tmp("definitely_missing_dir_xyz"))
  inspect(source, content="built-in defaults")
  inspect(rs.size(), content="0")
}

// ---------------------------------------------------------------------------
// A2: extern library models (mongoose) — type resolution + taint behavior
// ---------------------------------------------------------------------------

///|
test "a2_lib_model_type_expr_parser" {
  inspect(parse_type_expr("Server").display(), content="Server")
  inspect(
    parse_type_expr("Map[Int, String]").display(),
    content="Map[Int, String]",
  )
  inspect(
    parse_type_expr("@http.CaseInsensitiveString").display(),
    content="http::CaseInsensitiveString",
  )
}

///|
test "a2_lib_model_resolves_extern_chain" {
  // `ws_msg_copy` has no local signature; the mongoose model types it.
  // The chain `let n = ws_msg_body_len(); ignore(n)` resolves via lib_fn_ret.
  let src = "extern \"c\" fn ws_msg_body_len() -> Int = \"ws_msg_body_len\" pub fn go() -> Int { ws_msg_body_len() }"
  let (impls, _) = @parser.parse_string(src, name="t.mbt")
  let symbols = PkgSymbols::new()
  let stats = IRStatsResult::new()
  let rs = TaintRuleset::empty()
  let _ = extend_ruleset_with_model(rs, "mongoose")
  rs.apply_to_symbols(symbols)
  inspect(symbols.lib_fn_ret.contains("ws_msg_body_len"), content="true")
  scan_package_calls(impls.to_array(), "t.mbt", symbols, stats)
  // the extern call itself resolves (stub ingestion) and its return type
  // now comes from the model
  inspect(stats.static_resolved, content="1")
}

///|
test "a2_mongoose_model_source_and_output_sink" {
  // probe: req.body() is a SOURCE (model), ws_send_native(x, v) is an
  // OUTPUT sink (model) -> CWE-116/tainted-output fires on tainted v
  let src = "pub fn handle(req : Req, id : Bytes) -> Unit { ws_send_native(id, req.body()) }"
  let (impls, _) = @parser.parse_string(src, name="t.mbt")
  let rules = TaintRuleset::empty()
  let _ = extend_ruleset_with_model(rules, "mongoose")
  inspect(rules.source_hit("body"), content="true")
  inspect(rules.output_sink_hit("ws_send_native"), content="true")
  let findings : Array[Finding] = []
  run_cwe113(
    impls,
    "t.mbt",
    src,
    findings,
    Warning,
    rules~,
    output_sinks_enabled=true,
  )
  let mut fired = false
  for f in findings {
    if f.rule_id.variant == "tainted-output" && f.rule_id.cwe == 116 {
      fired = true
    }
  }
  inspect(fired, content="true")
}

///|
test "a2_output_sink_disabled_by_flag" {
  let src = "pub fn handle(req : Req, id : Bytes) -> Unit { ws_send_native(id, req.body()) }"
  let (impls, _) = @parser.parse_string(src, name="t.mbt")
  let rules = TaintRuleset::empty()
  let _ = extend_ruleset_with_model(rules, "mongoose")
  let findings : Array[Finding] = []
  run_cwe113(
    impls,
    "t.mbt",
    src,
    findings,
    Warning,
    rules~,
    output_sinks_enabled=false,
  )
  let mut fired = false
  for f in findings {
    if f.rule_id.variant == "tainted-output" && f.rule_id.cwe == 116 {
      fired = true
    }
  }
  inspect(fired, content="false")
}

///|
test "a2_lib_callback_placeholders" {
  // lib-model callbacks: K/V placeholders resolve from receiver type args
  let src = "pub fn go(m : Map[String, Int]) -> Unit { m.custom_each(fn(k, v) { ignore(k.length()); ignore(v + 1) }) }"
  let (impls, _) = @parser.parse_string(src, name="t.mbt")
  let symbols = PkgSymbols::new()
  // model a custom higher-order method via the callbacks section
  let rs = TaintRuleset::empty()
  rs.callbacks.push(("Map::custom_each", ["K", "V"]))
  rs.apply_to_symbols(symbols)
  inspect(symbols.lib_callbacks.contains("Map::custom_each"), content="true")
  let stats = IRStatsResult::new()
  scan_package_calls(impls.to_array(), "t.mbt", symbols, stats)
  // k : String -> k.length() resolves as a concrete receiver
  inspect(stats.receiver_resolved >= 1, content="true")
}

// ---------------------------------------------------------------------------
// M4-lite: bounded heap slice — alloc-site field-sensitive taint
// ---------------------------------------------------------------------------

///|
test "m4lite_mutate_then_field_read_via_heap" {
  // discriminating case: field CLEAN at construction, tainted via Mutate;
  // only the heap model connects the write to the later read
  let src = "pub struct W { v : String } fn foo(resp : Response, req : Request) -> Unit { let o = W::{ v: \"\" }; o.v = req.query(\"q\"); resp.set_header(\"X\", o.v) }"
  let (impls, _) = @parser.parse_string(src, name="t.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "t.mbt", src, findings, Error)
  inspect(findings.length() > 0, content="true")
}

///|
test "m4lite_alias_inherits_alloc_site" {
  // let b = a: alias inherits the alloc-site; field read through the
  // alias sees the heap fact
  let src = "pub struct W { v : String } fn foo(resp : Response, req : Request) -> Unit { let a = W::{ v: req.query(\"q\") }; let b = a; resp.set_header(\"X\", b.v) }"
  let (impls, _) = @parser.parse_string(src, name="t.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "t.mbt", src, findings, Error)
  inspect(findings.length() > 0, content="true")
}

///|
test "m4lite_source_to_object_cross_2_layers_to_sink" {
  // review phase-4 acceptance shape: object built+field tainted in f1,
  // f2 reads the field into a header sink — alarm fires at the CALL site
  // via the param-field summary + caller heap facts
  let emit_src = "pub struct W { v : String } fn emit(resp : Response, w : W) -> Unit { resp.set_header(\"X\", w.v) }"
  let (emit_impls, _) = @parser.parse_string(emit_src, name="lib.mbt")
  let ictx = InterProceduralContext::new()
  collect_func_summaries_flow(emit_impls, "lib.mbt", ictx)
  inspect(ictx.summaries.contains("emit"), content="true")
  inspect(
    ictx.summaries.get("emit") |> unwrap_summary_field_sinks,
    content="[(w, v)]",
  )
  let caller_src = "fn go(resp : Response, req : Request) -> Unit { let o = W::{ v: req.query(\"q\") }; emit(resp, o) }"
  let (caller_impls, _) = @parser.parse_string(caller_src, name="app.mbt")
  let findings : Array[Finding] = []
  run_cwe113(caller_impls, "app.mbt", caller_src, findings, Error, ictx~)
  inspect(findings.length() > 0, content="true")
  // negative control: clean field at the call site -> conditional sink
  // NOT confirmed -> no alarm
  let clean_src = "fn go2(resp : Response) -> Unit { let o = W::{ v: \"static\" }; emit(resp, o) }"
  let (clean_impls, _) = @parser.parse_string(clean_src, name="app2.mbt")
  let findings2 : Array[Finding] = []
  run_cwe113(clean_impls, "app2.mbt", clean_src, findings2, Error, ictx~)
  inspect(findings2.length(), content="0")
}

///|
fn unwrap_summary_field_sinks(s : FuncTaintSummary?) -> String {
  match s {
    Some(sum) => {
      let parts : Array[String] = []
      for pair in sum.param_field_sinks {
        parts.push("(" + pair.0 + ", " + pair.1 + ")")
      }
      "[" + parts.join(", ") + "]"
    }
    None => "none"
  }
}

///|
test "m4lite_config_field_read_stays_silent" {
  // config-like param field read: no site, no summary consumer -> Clean
  // (legacy parity preserved under the heap model)
  let src = "fn foo(ctx : Context, config : Config) -> Unit { ctx.set_header(\"Cache-Control\", config.cache_control) }"
  let (impls, _) = @parser.parse_string(src, name="t.mbt")
  let findings : Array[Finding] = []
  run_cwe113(impls, "t.mbt", src, findings, Error)
  inspect(findings.length(), content="0")
}

// ---------------------------------------------------------------------------
// gate4: extends in the combined .moon-audit.json "taint" section
// ---------------------------------------------------------------------------

///|
test "gate4_extends_combined_path_applies_model" {
  // .moon-audit.json taint section with ONLY {"extends":["mongoose"]} must
  // resolve the model (previously silently no-op: size()==0 early return
  // AND missing resolve_extends on the combined path)
  let dir = test_tmp("gate4_combined_test")
  @fs.create_dir(dir) catch {
    _ => ()
  }
  let f = dir + "/.moon-audit.json"
  @fs.write_string_to_file(f, "{\"taint\": {\"extends\": [\"mongoose\"]}}") catch {
    _ => ()
  }
  let (rs, source) = load_taint_rules(dir)
  inspect(source, content=f + " [taint section]")
  // mongoose model entries are live via the combined path
  inspect(rs.source_hit("body"), content="true")
  inspect(rs.output_sink_hit("ws_send_native"), content="true")
}

///|
test "gate4_extends_combined_path_alert_e2e" {
  // end-to-end: probe snippet alerts only when the model is applied
  let src = "pub fn handle(req : Req, id : Bytes) -> Unit { ws_send_native(id, req.body()) }"
  let (impls, _) = @parser.parse_string(src, name="t.mbt")
  let dir = test_tmp("gate4_combined_test")
  let (rules, _) = load_taint_rules(dir)
  let findings : Array[Finding] = []
  run_cwe113(
    impls,
    "t.mbt",
    src,
    findings,
    Warning,
    rules~,
    output_sinks_enabled=true,
  )
  inspect(findings.length() > 0, content="true")
}

///|
test "gate4_extends_with_extern_decl_e2e" {
  let src = "extern \"c\" fn ws_send_native(a : Bytes, b : Bytes) -> Unit = \"ws_send_native\" pub fn handle(req : Req, id : Bytes) -> Unit { ws_send_native(id, req.body()) }"
  let (impls, _) = @parser.parse_string(src, name="t.mbt")
  let dir = test_tmp("gate4_combined_test")
  let (rules, _) = load_taint_rules(dir)
  let findings : Array[Finding] = []
  run_cwe113(
    impls,
    "t.mbt",
    src,
    findings,
    Warning,
    rules~,
    output_sinks_enabled=true,
  )
  inspect(findings.length(), content="1")
}

///|
test "gate4_scan_project_level_e2e" {
  // full scan_project path (equivalent to CLI): rules from project root
  let dir = test_tmp("g4_scanproj")
  let src_dir = dir + "/src"
  @fs.create_dir(dir) catch {
    _ => ()
  }
  @fs.create_dir(src_dir) catch {
    _ => ()
  }
  @fs.write_string_to_file(
    dir + "/moon.mod",
    "name = \"g4p\"\nversion = \"0.1.0\"\n",
  )
  @fs.write_string_to_file(src_dir + "/moon.pkg", "") catch {
    _ => ()
  }
  @fs.write_string_to_file(
    src_dir + "/lib.mbt",
    "extern \"c\" fn ws_send_native(a : Bytes, b : Bytes) -> Unit = \"ws_send_native\"\npub fn handle(req : Req, id : Bytes) -> Unit { ws_send_native(id, req.body()) }\n",
  ) catch {
    _ => ()
  }
  @fs.write_string_to_file(
    dir + "/.moon-audit.json",
    "{\"taint\": {\"extends\": [\"mongoose\"]}}",
  ) catch {
    _ => ()
  }
  let result = scan_project(dir, Config::default())
  inspect(result.findings.length() > 0, content="true")
}
