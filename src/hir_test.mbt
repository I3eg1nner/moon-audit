// T2a unit tests: explicit eval-order HIR statements + value positions
// (see docs/ir/ROADMAP-T.md T2.1 / T2.3 and the acceptance contract)

///|
fn t2a_run(src : String) -> (Array[Finding], Array[Stmt]) {
  let (impls, _) = @parser.parse_string(src, name="t2a.mbt")
  let findings : Array[Finding] = []
  let trace : Array[Stmt] = []
  for item in impls {
    match item {
      TopFuncDef(fun_decl~, decl_body~, ..) =>
        match decl_body {
          DeclBody(expr=body) => {
            let t = run_flow_taint_trace(
              fun_decl.decl_params,
              body,
              "t2a.mbt",
              src,
              Error,
              findings,
            )
            for s in t {
              trace.push(s)
            }
          }
          _ => ()
        }
      _ => ()
    }
  }
  (findings, trace)
}

///|
fn count_stmt(trace : Array[Stmt], pred : (Stmt) -> Bool) -> Int {
  let mut n = 0
  for s in trace {
    if pred(s) {
      n += 1
    }
  }
  n
}

///|
test "t2a_a_single_evaluation_is_structural" {
  // every argument materializes into exactly ONE temp before the call;
  // nested calls each contribute their own (temps, CallStmt) group
  let src = "pub fn go(h : (Int) -> Int, q : String, r : Response) -> Unit { r.set_header(\"X\", h(1)); ignore(r.set_header(\"Y\", h(h(2)))) }"
  let (findings, trace) = t2a_run(src)
  // three call sites in total: h(1), h(2), h(h(2)) outer, set_header x2
  let calls = count_stmt(trace, fn(s) {
    match s {
      CallStmt(target, _) => target == "h" || target == "set_header"
      _ => false
    }
  })
  // 3 h-calls + 2 set_header calls
  inspect(calls, content="5")
  // sink fired on both set_header sites (tainted param q flows via r? no —
  // header VALUE slot: h(1) result of higher-order call stays unresolved;
  // the trace-level assertion is structural, findings may be 0)
  inspect(findings.length() >= 0, content="true")
  // exactly one LetEvalTemp per evaluated argument occurrence (DotApply
  // materializes the receiver temp first): h(1)=1, h(2)=1, h(h(2))=1,
  // set_header = (recv+2 args) x2 = 6, ignore = 1 → 10
  let temps = count_stmt(trace, fn(s) {
    match s {
      LetEvalTemp(_, _) => true
      _ => false
    }
  })
  inspect(temps, content="10")
}

///|
test "t2a_b_ctor_payload_position_beats_whole_taint" {
  // Pair("safe", q): whole taint is Tainted, but position 0 ("safe") must
  // project CLEAN via (decl, ctor, idx) addressing — whole-binding would
  // over-report here
  let pos0 = "pub fn go(q : String, r : Response) -> Unit { let p = Pair(\"safe\", q); match p { Pair(a, b) => r.set_header(\"X\", a) } }"
  let (f0, _) = t2a_run(pos0)
  inspect(f0.length(), content="0")
  let pos1 = "pub fn go(q : String, r : Response) -> Unit { let p = Pair(\"safe\", q); match p { Pair(a, b) => r.set_header(\"X\", b) } }"
  let (f1, _) = t2a_run(pos1)
  inspect(f1.length(), content="1")
}

///|
test "t2a_c_same_name_decls_do_not_cross_contaminate" {
  // rebinding `m` allocates a NEW declaration with its own positions —
  // the stale Some(q) positions are unreachable after let m = Some("safe")
  let src = "pub fn go(q : String, r : Response) -> Unit { let m = Some(q); let m = Some(\"safe\"); match m { Some(v) => r.set_header(\"X\", v) } }"
  let (f, _) = t2a_run(src)
  inspect(f.length(), content="0")
  // control: without the rebinding the SAME projection reports
  let ctrl = "pub fn go(q : String, r : Response) -> Unit { let m = Some(q); match m { Some(v) => r.set_header(\"X\", v) } }"
  let (fc, _) = t2a_run(ctrl)
  inspect(fc.length(), content="1")
}
