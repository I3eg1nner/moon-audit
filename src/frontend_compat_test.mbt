///|
fn compat_test_body(source : String) -> @syntax.Expr raise {
  let (items, reports) = @src.parse_source(source, name="legacy.mbt")
  assert_true(reports.is_empty())
  match items.head().unwrap() {
    TopFuncDef(decl_body=DeclBody(expr~), ..) => expr
    _ => fail("expected function body")
  }
}

///|
test "legacy try question keeps distinct kind and original locations" {
  let source = "fn f() {\n  try? g()\n}"
  match compat_test_body(source) {
    TryOperator(body=Apply(..), kind=Question, try_loc~, loc~) => {
      inspect(try_loc.start.fname, content="legacy.mbt")
      inspect(try_loc.start.lnum, content="2")
      inspect(try_loc.start.cnum - try_loc.start.bol, content="2")
      inspect(try_loc.end.cnum - try_loc.start.cnum, content="4")
      inspect(loc.end.lnum, content="2")
    }
    _ => fail("try? must not become try! or a normal call")
  }
}

///|
test "legacy try question preserves pipe expression precedence" {
  let expr = compat_test_body("fn f() { try? g() + 1 }")
  match expr {
    TryOperator(body=Infix(..), kind=Question, ..) => ()
    _ => fail("try? must enclose the complete infix expression")
  }
}

///|
test "legacy loop retains cases and its own node" {
  let source = "fn f(n : Int) {\n  loop n {\n    0 => 0\n    x => continue (x - 1)\n  }\n}"
  match compat_test_body(source) {
    Loop(body~, label=None, loop_loc~, loc~, ..) => {
      inspect(body.length(), content="2")
      inspect(loop_loc.start.lnum, content="2")
      inspect(loop_loc.start.cnum - loop_loc.start.bol, content="2")
      inspect(loc.end.lnum, content="5")
    }
    _ => fail("legacy loop must not become a modern for or an ordinary match")
  }
}

///|
test "labelled legacy loop retains label and continue" {
  let expr = compat_test_body(
    "fn f(n : Int) { again~: loop n {\n  0 => 0\n  x => continue again~ (x - 1)\n} }",
  )
  match expr {
    Loop(label=Some(label), body~, ..) => {
      inspect(label.name, content="again")
      inspect(body.length(), content="2")
    }
    _ => fail("labelled loop lost its label")
  }
}

///|
test "legacy nodes are traversed by rule visitors and interpolation expansion" {
  let source =
    #|fn f(s : String) {
    #|  loop s {
    #|    x => try? g(x.replace(old="<", new="&lt;"))
    #|  }
    #|}
    #|fn text(s : String) { "\{loop s { x => x.replace(old="<", new="&lt;") }}" }
  let (items, reports) = @src.parse_source(source, name="legacy.mbt")
  inspect(reports.length(), content="0")
  let findings : Array[@src.Finding] = []
  @src.run_cwe116(items, "legacy.mbt", source, findings, Error)
  inspect(findings.length(), content="2")
  inspect(findings[0].line, content="3")
  inspect(findings[1].line, content="6")
}

///|
test "malformed legacy constructs still report errors" {
  for
    source in [
      "fn f() { try? }", "fn f() { loop 0 { x => } }", "fn f() { loop 0 { x 1 } }",
      "fn f() { loop 0 { x => x } + }",
    ] {
    let (_, reports) = @src.parse_source(source, name="legacy.mbt")
    assert_true(!reports.is_empty())
  }
}

///|
test "legacy spellings in strings and comments do not alter current AST" {
  let source = "// loop try?\nfn f() { \"loop try?\" }"
  let (official, original_errors) = @official_parser.parse_string(
    source,
    name="same.mbt",
  )
  let (actual, errors) = @src.parse_source(source, name="same.mbt")
  assert_true(original_errors.is_empty() && errors.is_empty())
  assert_true(
    actual.map(fn(i) { i.json_repr() }) == official.map(fn(i) { i.json_repr() }),
  )
}

///|
test "lexical errors cannot become successful recovered legacy or current ASTs" {
  for
    source in [
      "fn f() { loop 1 { x => x } ` }", "fn f() { try? g() $ }", "fn f() { g() ` }",
    ] {
    let (_, reports) = @src.parse_source(source, name="invalid.mbt")
    assert_true(reports.any(fn(r) { r.msg.has_prefix("Lexer: ") }))
    for parser in [@parser.Handrolled, @parser.MoonYacc] {
      let (_, direct) = @parser.parse_string(
        source,
        name="invalid.mbt",
        parser~,
      )
      assert_true(direct.any(fn(r) { r.msg.has_prefix("Lexer: ") }))
    }
  }
}

///|
test "interpolation lexical errors retain original source positions" {
  let source =
    #|fn text() {
    #|  "\{loop 1 { x => x } $}"
    #|}
  let (_, reports) = @src.parse_source(source, name="hole.mbt")
  assert_true(
    reports.any(fn(r) {
      r.msg.has_prefix("Interpolation: ") &&
      r.loc.start.fname == "hole.mbt" &&
      r.loc.start.lnum == 2
    }),
  )
}
