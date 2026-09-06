// T5.1 acceptance: ONE parse/merge pipeline for all three model entry paths
// (dedicated taint-rules.json / .moon-audit.json "taint" section / extends),
// documented conflict semantics, and unknown-field warnings.

///|
fn t51_mkdir(path : String) -> Unit {
  @fs.create_dir(path) catch {
    _ => ()
  }
}

///|
fn t51_write(path : String, content : String) -> Unit {
  @fs.write_string_to_file(path, content) catch {
    _ => ()
  }
}

///|
test "t51_three_entry_equivalence" {
  let model_json = "{\"sources\":[{\"method\":\"msrc\"}],\"callbacks\":{\"each_k\":[\"K\"]}}"
  // entry A: dedicated taint-rules.json
  let rootA = test_tmp("t51_eq_A")
  t51_mkdir(rootA)
  t51_mkdir(rootA + "/libmodels")
  t51_write(
    rootA + "/taint-rules.json",
    "{\"sources\":[{\"method\":\"src1\",\"kind\":\"X\"}],\"sinks\":[{\"method\":\"snk1\",\"kind\":\"HeaderValue\"}],\"extends\":[\"mymodel\"]}",
  )
  t51_write(rootA + "/libmodels/mymodel.json", model_json)
  // entry B: .moon-audit.json "taint" section (same content)
  let rootB = test_tmp("t51_eq_B")
  t51_mkdir(rootB)
  t51_mkdir(rootB + "/libmodels")
  t51_write(
    rootB + "/.moon-audit.json",
    "{\"taint\":{\"sources\":[{\"method\":\"src1\",\"kind\":\"X\"}],\"sinks\":[{\"method\":\"snk1\",\"kind\":\"HeaderValue\"}],\"extends\":[\"mymodel\"]}}",
  )
  t51_write(rootB + "/libmodels/mymodel.json", model_json)
  let (rsA, _, wA) = load_taint_rules(rootA)
  let (rsB, _, wB) = load_taint_rules(rootB)
  inspect(wA.length() == 0, content="true")
  inspect(wB.length() == 0, content="true")
  inspect(rsA.size() == rsB.size(), content="true")
  inspect(rsA.source_hit("src1"), content="true")
  inspect(rsB.source_hit("src1"), content="true")
  inspect(rsA.source_hit("msrc"), content="true")
  inspect(rsB.source_hit("msrc"), content="true")
  inspect(rsA.header_sink_hit("snk1"), content="true")
  inspect(rsB.header_sink_hit("snk1"), content="true")
  inspect(rsA.callbacks.length(), content="1")
  inspect(rsB.callbacks.length(), content="1")
}

///|
test "t51_extends_v2_trait_edges_and_nested_models_survive" {
  // v2 callbacks / trait_edges / nested extends previously LOST on the
  // extends path (the divergent merge_model_json never handled them)
  let root = test_tmp("t51_extends")
  t51_mkdir(root)
  t51_mkdir(root + "/libmodels")
  t51_write(root + "/taint-rules.json", "{\"extends\":[\"outer\"]}")
  t51_write(
    root + "/libmodels/outer.json",
    "{\"callbacks\":{\"iter_map\":{\"slots\":[\"T\"],\"timing\":\"deferred\"}},\"trait_edges\":[{\"method\":\"Map::get\",\"trait_method\":\"hash\",\"note\":\"conservative\"}],\"extends\":[\"inner\"]}",
  )
  t51_write(
    root + "/libmodels/inner.json",
    "{\"types\":{\"mk\":\"Map[Int,Int]\"},\"sanitizers\":[{\"method\":\"deep_clean\"}]}",
  )
  let (rs, _, w) = load_taint_rules(root)
  inspect(w.length() == 0, content="true")
  // v2 callback timing survived the extends path
  let found_deferred = rs.cb_timing.any(fn(c) {
    c.0 == "iter_map" && c.1 == Deferred
  })
  inspect(found_deferred, content="true")
  inspect(rs.callbacks.length(), content="1")
  // trait edge survived
  inspect(rs.trait_edges.length(), content="1")
  inspect(rs.trait_edges[0].lib_method, content="Map::get")
  inspect(rs.trait_edges[0].trait_method, content="hash")
  // nested extends: inner merged through outer
  inspect(rs.sanitizer_hit("deep_clean"), content="true")
  let mk = rs.fn_types.any(fn(p) { p.0 == "mk" && p.1 == "Map[Int,Int]" })
  inspect(mk, content="true")
}

///|
test "t51_unknown_fields_warn_not_silent" {
  let root = test_tmp("t51_unknown")
  t51_mkdir(root)
  t51_write(
    root + "/taint-rules.json",
    "{\"sorces\":[1],\"sources\":[{\"method\":\"ok_src\",\"knd\":\"typo\"}],\"callbacks\":{\"c\":{\"slots\":[\"K\"],\"slotz\":1}},\"extends\":[\"no_such_model\"]}",
  )
  let (rs, _, w) = load_taint_rules(root)
  // unknown top-level key warned
  let w1 = w.any(fn(x) { x.contains("unknown field 'sorces'") })
  inspect(w1, content="true")
  // unknown rule key warned
  let w2 = w.any(fn(x) { x.contains("'knd'") })
  inspect(w2, content="true")
  // unknown v2 callback key warned
  let w3 = w.any(fn(x) { x.contains("'slotz'") })
  inspect(w3, content="true")
  // unknown extends model warned (was silent before T5.1)
  let w4 = w.any(fn(x) { x.contains("unknown model 'no_such_model'") })
  inspect(w4, content="true")
  // known parts still parsed
  inspect(rs.source_hit("ok_src"), content="true")
  inspect(rs.callbacks.length(), content="1")
}

///|
test "t51_conflict_merge_last_wins_and_dup_dedup" {
  let root = test_tmp("t51_conflict")
  t51_mkdir(root)
  t51_mkdir(root + "/libmodels")
  t51_write(
    root + "/taint-rules.json",
    "{\"types\":{\"f\":\"Int\"},\"sources\":[{\"method\":\"dup_src\"}],\"extends\":[\"m\"]}",
  )
  // model redefines types.f with a DIFFERENT value and repeats the rule
  t51_write(
    root + "/libmodels/m.json",
    "{\"types\":{\"f\":\"String\"},\"sources\":[{\"method\":\"dup_src\"}]}",
  )
  let (rs, _, w) = load_taint_rules(root)
  // conflict warned, last (model) wins
  let c = w.any(fn(x) { x.contains("conflict: types['f'] 'Int' vs 'String'") })
  inspect(c, content="true")
  let f = rs.fn_types.any(fn(p) { p.0 == "f" && p.1 == "String" })
  inspect(f, content="true")
  inspect(rs.fn_types.length(), content="1")
  // exact duplicate rule across entries deduped to one
  inspect(rs.sources.length(), content="1")
  inspect(rs.source_hit("dup_src"), content="true")
}

///|
test "t51_extends_cycle_guard" {
  let root = test_tmp("t51_cycle")
  t51_mkdir(root)
  t51_mkdir(root + "/libmodels")
  t51_write(root + "/taint-rules.json", "{\"extends\":[\"a\"]}")
  t51_write(
    root + "/libmodels/a.json",
    "{\"sources\":[{\"method\":\"a_src\"}],\"extends\":[\"b\"]}",
  )
  t51_write(
    root + "/libmodels/b.json",
    "{\"sources\":[{\"method\":\"b_src\"}],\"extends\":[\"a\"]}",
  )
  let (rs, _, w) = load_taint_rules(root)
  inspect(rs.source_hit("a_src"), content="true")
  inspect(rs.source_hit("b_src"), content="true")
  let cyc = w.any(fn(x) { x.contains("extends cycle detected at 'a'") })
  inspect(cyc, content="true")
}
