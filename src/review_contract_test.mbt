// Review contract tests (2026-09-20 external review counter-examples).
// Each test encodes a CLI-reproduced defect as a precise assertion:
//   rc1  sanitizer must clean value before sink (no FP under --cfg-engine)
//   rc2  two sinks on one line report separately (call-site identity)
//   rc3  method-form sink reports exactly once at its real line
//   rc4  trait impl summary key is trait-qualified (generation side)

///|
fn rc_rules() -> TaintRuleset {
  // sink: sink / set_header ; source: query ; sanitizer: sanitize
  let j = @json.parse(
    "{\"sources\":[{\"method\":\"query\",\"kind\":\"RequestData\"}],\"sinks\":[{\"method\":\"sink\",\"kind\":\"HeaderValue\",\"value_slot\":0},{\"method\":\"set_header\",\"kind\":\"HeaderValue\",\"value_slot\":0}],\"sanitizers\":[{\"method\":\"sanitize\",\"kind\":\"HeaderValue\"}]}",
  ) catch {
    _ => return TaintRuleset::empty()
  }
  let warnings : Array[String] = []
  parse_ruleset_json(j, "rc-test", warnings)
}

///|
fn rc_scan(src : String, fn_name : String) -> Array[Finding] {
  let (impls, _) = @parser.parse_string(src, name="rc.mbt")
  let rules = rc_rules()
  let ir = build_block_ir(fn_name, rc_fn_body(impls, fn_name), rules~)
  let entry : Array[(String, Taint)] = []
  for p in rc_fn_params(impls, fn_name) {
    entry.push((p, Tainted))
  }
  exec_independent(ir, entry, rules, None)
}

///|
fn rc_fn_body(impls : @list.List[@syntax.Impl], name : String) -> @syntax.Expr {
  for item in impls {
    match item {
      TopFuncDef(fun_decl~, decl_body~, ..) =>
        if fun_decl.name.name == name {
          match decl_body {
            DeclBody(expr=Function(func~, ..)) => return func.body
            DeclBody(expr=b) => return b
            _ => ()
          }
        }
      _ => ()
    }
  }
  @syntax.Expr::Unit(
    loc={
      start: { fname: "", lnum: 0, bol: 0, cnum: 0, },
      end: { fname: "", lnum: 0, bol: 0, cnum: 0, },
    },
    faked=true,
  )
}

///|
fn rc_fn_params(
  impls : @list.List[@syntax.Impl],
  name : String,
) -> Array[String] {
  for item in impls {
    match item {
      TopFuncDef(fun_decl~, decl_body~, ..) =>
        if fun_decl.name.name == name {
          match decl_body {
            DeclBody(expr=Function(func~, ..)) => {
              let names : Array[String] = []
              for p in func.parameters {
                match p {
                  Positional(binder~, ..)
                  | Labelled(binder~, ..)
                  | Optional(binder~, ..)
                  | QuestionOptional(binder~, ..) => names.push(binder.name)
                  DiscardPositional(..) => ()
                }
              }
              return names
            }
            _ => ()
          }
        }
      _ => ()
    }
  }
  []
}

// rc1: sanitizer semantics — sanitize(value) must Clean the value so the
// sink call does NOT fire (review case cfg_sanitizer: --cfg-engine FP).

///|
test "rc1_sanitizer_respected_by_independent_executor" {
  let findings = rc_scan(
    "fn sanitize(value : String) -> String { ignore(value); \"safe\" } fn sink(value : String) -> Unit { ignore(value) } pub fn go(value : String) -> Unit { sink(sanitize(value)) }",
    "go",
  )
  inspect(findings.length(), content="0")
}

// rc2: two sink calls on ONE line are distinct call sites — both report
// (review case dedup_same_line: 1 reported, 2 expected).

///|
test "rc2_same_line_two_sinks_both_report" {
  let findings = rc_scan(
    "fn sink(value : String) -> Unit { ignore(value) } fn source() -> String { \"dirty\" } pub fn go() -> Unit { sink(source()); sink(source()) }",
    "go",
  )
  inspect(findings.length(), content="2")
}

// rc3: method-form sink (r.set_header(v)) fires EXACTLY once, at the
// call's real line — never a line-0 duplicate from the CallStmt arm
// (review case dedup_receiver: 2 findings, one at line 0).

///|
test "rc3_method_sink_single_finding_real_line" {
  let findings = rc_scan(
    "pub struct Req { } fn source() -> String { \"dirty\" } pub fn go(r : Req) -> Unit { r.set_header(source()) }",
    "go",
  )
  inspect(findings.length(), content="1")
  inspect(findings[0].line > 0, content="true")
}

// rc4: trait impl summary identity includes the trait name — two traits
// with same method name on the same type must not share a summary key
// (generation side of the review's trait query misalignment).

///|
test "rc4_trait_impl_summary_key_is_trait_qualified" {
  let (impls, _) = @parser.parse_string(
    "pub trait Pick { fn pick(Self, String, String) -> String } pub struct First { } pub impl Pick for First with fn pick(self, a, b) -> String { ignore(self); ignore(b); a }",
    name="rc-trait.mbt",
  )
  let units = extract_summary_units(impls, "t.mbt")
  let mut has_qualified = false
  let mut has_unqualified = false
  for u in units {
    if u.name == "First:Pick::pick" {
      has_qualified = true
    }
    if u.name == "First::pick" {
      has_unqualified = true
    }
  }
  inspect(has_qualified, content="true")
  inspect(has_unqualified, content="false")
}

// rc5: full-pipeline trait dispatch (review 2026-09-20 counterexample):
// only the Second impls fire (dirty_dot line 8, dirty_static line 10);
// First impls stay clean — requires receiver-aware summary selection.

///|
test "rc5_full_scan_trait_dispatch_exact_lines" {
  let dir = "/tmp/dbg-dispatch-fixture"
  @fs.create_dir(dir) catch {
    _ => ()
  }
  @fs.write_string_to_file(dir + "/moon.mod", "name = \"dbg/d\"\n") catch {
    _ => ()
  }
  @fs.write_string_to_file(dir + "/moon.pkg", "") catch {
    _ => ()
  }
  @fs.write_string_to_file(
    dir + "/taint-rules.json",
    "{\"sources\":[{\"method\":\"source\",\"kind\":\"RequestData\"}],\"sinks\":[{\"method\":\"sink\",\"kind\":\"HeaderValue\",\"value_slot\":0}]}",
  ) catch {
    _ => ()
  }
  @fs.write_string_to_file(
    dir + "/probe.mbt",
    "fn source() -> String { \"dirty\" } fn sink(value : String) -> Unit { ignore(value) } pub fn bare() -> Unit { sink(source()) }",
  ) catch {
    _ => ()
  }
  @fs.write_string_to_file(
    dir + "/main.mbt",
    "pub trait Pick { fn pick(Self, String, String) -> String }\npub struct First { }\npub struct Second { }\npub impl Pick for First with fn pick(self, a, b) -> String { ignore(self); ignore(b); a }\npub impl Pick for Second with fn pick(self, a, b) -> String { ignore(self); ignore(a); b }\nfn source() -> String { \"dirty\" }\nfn sink(value : String) -> Unit { ignore(value) }\npub fn dirty_dot() -> Unit { let x = Second::{}; sink(x.pick(\"safe\", source())) }\npub fn clean_dot() -> Unit { let x = First::{}; sink(x.pick(\"safe\", source())) }\npub fn dirty_static() -> Unit { sink(Second::pick(Second::{}, \"safe\", source())) }\npub fn clean_static() -> Unit { sink(First::pick(First::{}, \"safe\", source())) }",
  ) catch {
    _ => ()
  }
  let base = Config::default()
  let cfg = { ..base, analysis_mode: "deep", }
  let world = load_program_world(
    dir,
    base,
    with_symbols=true,
    conservative_alias=false,
  )
  println(
    "impl_methods size: " + world.symbols.impl_methods.length().to_string(),
  )
  let result = scan_project_with_world(world, cfg)
  // review contract: ONLY the Second-impl paths fire (8, 10); the First
  // paths (9, 11) stay clean — summary dispatch must be receiver-aware
  let lines : Array[String] = []
  for f in result.findings {
    if f.file.has_suffix("main.mbt") {
      lines.push(f.line.to_string())
    }
  }
  inspect(lines.join(","), content="8,10")
}

///|
test "rc6_struct_literal_parses_as_record" {
  let src = "pub struct Second { }\npub fn go() -> Unit { let x = Second::{}; ignore(x) }"
  let (impls, _) = @parser.parse_string(src, name="p.mbt")
  let body = rc_fn_body(impls, "go")
  let mut form = "NOT-LET"
  match body {
    Let(expr=init, ..) =>
      form = match init {
        Constr(constr~, ..) => "CONSTR:" + constr.name.name
        Apply(func=Constr(constr~, ..), ..) =>
          "APPLY-CONSTR:" + constr.name.name
        Apply(func=Ident(..), ..) => "APPLY-IDENT"
        Ident(..) => "IDENT"
        Sequence(..) => "SEQUENCE"
        Array(..) => "ARRAY"
        Tuple(..) => "TUPLE"
        Field(..) => "FIELD"
        Interp(..) => "INTERP"
        Method(..) => "METHOD"
        LabelledBlock(..) => "LABELLED"
        Record(..) => "RECORD"
        RecordUpdate(..) => "RECORD-UPDATE"
        Group(..) => "GROUP"
        Map(..) => "MAP"
        Unit(..) => "UNIT"
        _ => "OTHER"
      }
    _ => ()
  }
  inspect(form, content="RECORD")
}
