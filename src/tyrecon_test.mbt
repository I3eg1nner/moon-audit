// M1 type-reconstruction spike unit tests (see docs/ir/PLAN.md)

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
  let dir = "/tmp/mbti_test_pkg"
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
  let dir = "/tmp/mbti_p2a"
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
  let dir = "/tmp/mbti_p2b"
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
  let dir = "/tmp/mbti_p2c"
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
  @fs.create_dir("/tmp/mbti_dbg") catch {
    _ => ()
  }
  @fs.write_string_to_file(
    "/tmp/mbti_dbg/pkg.generated.mbti", "package \"x/y\"\n\npub trait Writer2 {\n  fn output(Self, String) -> Unit\n}\n\npub let limit : Int\n",
  ) catch {
    _ => ()
  }
  let source = @fs.read_file_to_string("/tmp/mbti_dbg/pkg.generated.mbti") catch {
    _ => ""
  }
  let (_m, reports) = @mbti_parser.parse_string(source, name="probe")
  inspect(reports.length(), content="0")
}
