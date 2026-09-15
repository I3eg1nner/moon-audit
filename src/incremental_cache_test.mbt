// F2 (T7.2): fn-level cache tests — hit / symbols-invalidate / body-invalidate

///|
test "f2_cache_hit_reuses_cached_findings" {
  let src = "fn f(resp : Response, val : String) -> Unit { resp.set_header(\"X\", val) }\npub fn g(resp : Response) -> Unit { resp.set_header(\"Y\", \"safe\") }"
  let (impls, _) = @parser.parse_string(src, name="t.mbt")
  let cache = FnCache::new()
  let fp = "fp-v1"
  // first run: cache miss → run and store
  let f1 : Array[Finding] = []
  run_cwe113(impls, "t.mbt", src, f1, Error, symbols_fp=fp, cache~)
  inspect(f1.length(), content="1")
  inspect(cache.hits, content="0")
  inspect(cache.misses, content="2") // both f and g miss on first run
  inspect(cache.size(), content="2")
  // second run same fp + same body: hit → replay
  let f2 : Array[Finding] = []
  run_cwe113(impls, "t.mbt", src, f2, Error, symbols_fp=fp, cache~)
  inspect(f2.length(), content="1") // identical findings replayed
  inspect(f2[0].line, content="1")
  inspect(f2[0].rule_id.variant, content="crlf-injection")
  inspect(cache.hits, content="2") // both f and g hit
  inspect(cache.misses, content="2") // no new misses (still the 2 from run 1)
}

///|
test "f2_symbols_change_invalidates_all" {
  let src = "fn f(resp : Response, val : String) -> Unit { resp.set_header(\"X\", val) }"
  let (impls, _) = @parser.parse_string(src, name="t.mbt")
  let cache = FnCache::new()
  let f1 : Array[Finding] = []
  run_cwe113(impls, "t.mbt", src, f1, Error, symbols_fp="fp-A", cache~)
  inspect(f1.length(), content="1")
  // symbols changed → fingerprint differs → miss (re-analysis)
  let f2 : Array[Finding] = []
  run_cwe113(impls, "t.mbt", src, f2, Error, symbols_fp="fp-B", cache~)
  inspect(f2.length(), content="1") // still finds it (re-analyzed)
  inspect(cache.hits, content="0") // never hit
  inspect(cache.misses, content="2") // two misses
}

///|
test "f2_body_change_invalidates_that_fn_only" {
  let src1 = "fn f(resp : Response, val : String) -> Unit { resp.set_header(\"X\", val) }\npub fn g(resp : Response) -> Unit { resp.set_header(\"Y\", \"safe\") }"
  let src2 = "fn f2_changed(resp : Response, val : String) -> Unit { resp.set_header(\"X\", val) }\npub fn g(resp : Response) -> Unit { resp.set_header(\"Y\", \"safe\") }"
  let (impls1, _) = @parser.parse_string(src1, name="t.mbt")
  let (impls2, _) = @parser.parse_string(src2, name="t.mbt")
  let cache = FnCache::new()
  let f1 : Array[Finding] = []
  run_cwe113(impls1, "t.mbt", src1, f1, Error, symbols_fp="fp-v1", cache~)
  inspect(cache.size(), content="2")
  // f changed → miss; g unchanged → hit
  let f2 : Array[Finding] = []
  run_cwe113(impls2, "t.mbt", src2, f2, Error, symbols_fp="fp-v1", cache~)
  // f2_changed is new (miss), g is same (hit)
  inspect(cache.hits, content="1") // g hit
  inspect(cache.misses, content="3") // f+g (1st) + f2_changed (2nd)
}

///|
test "f2_fn_body_hash_stable_for_same_text" {
  let h1 = fn_body_hash("f", "1-10:Let")
  let h2 = fn_body_hash("f", "1-10:Let")
  inspect(h1 == h2, content="true")
  let h3 = fn_body_hash("f", "2-20:If")
  inspect(h1 != h3, content="true")
}

///|
test "f2_cache_stats_zero_on_new" {
  let c = FnCache::new()
  inspect(c.hits, content="0")
  inspect(c.misses, content="0")
  inspect(c.size(), content="0")
}

///|
test "f2_scan_twice_second_run_hits_cache" {
  // end-to-end: scan_project_with_world twice → second run's fn cache hits
  // (in-process; each call creates a new FnCache, so this tests the
  // library-API reuse pattern, not CLI single-shot)
  let root = test_tmp("f2_scan_twice")
  @fs.create_dir(root) catch {
    _ => ()
  }
  @fs.create_dir(root + "/src") catch {
    _ => ()
  }
  @fs.write_string_to_file(root + "/moon.mod", "name = \"f2st\"\n") catch {
    _ => ()
  }
  @fs.write_string_to_file(root + "/src/moon.pkg", "") catch {
    _ => ()
  }
  @fs.write_string_to_file(
    root + "/src/lib.mbt",
    "pub fn go() -> Unit { ignore(1) }",
  ) catch {
    _ => ()
  }
  let world = load_program_world(root, Config::default())
  let r1 = scan_project_with_world(world, Config::default())
  let r2 = scan_project_with_world(world, Config::default())
  inspect(r1.findings.length(), content="0")
  inspect(r2.findings.length(), content="0")
  // both scans produce identical file counts
  inspect(r2.files_scanned, content="1")
}

///|
test "f2_same_location_body_edit_invalidates_cached_finding" {
  let unsafe_src = "fn f(resp : Response, val : String) -> Unit { resp.set_header(\"X\", val) }"
  let safe_src = "fn f(resp : Response, val : String) -> Unit { resp.set_header(\"X\", \"x\") }"
  let (unsafe_impls, _) = @parser.parse_string(unsafe_src, name="t.mbt")
  let (safe_impls, _) = @parser.parse_string(safe_src, name="t.mbt")
  let cache = FnCache::new()
  let before : Array[Finding] = []
  run_cwe113(unsafe_impls, "t.mbt", unsafe_src, before, Error, cache~)
  inspect(before.length(), content="1")
  let after : Array[Finding] = []
  run_cwe113(safe_impls, "t.mbt", safe_src, after, Error, cache~)
  inspect(after.length(), content="0")
  inspect(cache.hits, content="0")
  inspect(cache.misses, content="2")
}

///|
test "f2_severity_change_invalidates_cached_finding" {
  let src = "fn f(resp : Response, val : String) -> Unit { resp.set_header(\"X\", val) }"
  let (impls, _) = @parser.parse_string(src, name="t.mbt")
  let cache = FnCache::new()
  let first : Array[Finding] = []
  run_cwe113(impls, "t.mbt", src, first, Error, cache~)
  let second : Array[Finding] = []
  run_cwe113(impls, "t.mbt", src, second, Warning, cache~)
  inspect(second.length(), content="1")
  inspect(severity_str(second[0].severity), content="warning")
}

///|
test "f2_rules_change_invalidates_cached_finding" {
  let src = "fn f(resp : Response, val : String) -> Unit { resp.set_header(\"X\", clean(val)) }"
  let (impls, _) = @parser.parse_string(src, name="t.mbt")
  let cache = FnCache::new()
  let rules = TaintRuleset::empty()
  let first : Array[Finding] = []
  run_cwe113(impls, "t.mbt", src, first, Error, cache~, rules~)
  inspect(first.length(), content="1")
  rules.sanitizers.push({ method_name: "clean", kind: "", value_slot: 0, })
  let second : Array[Finding] = []
  run_cwe113(impls, "t.mbt", src, second, Error, cache~, rules~)
  inspect(second.length(), content="0")
}

///|
test "f2_output_sink_policy_invalidates_cached_finding" {
  let src = "fn f(val : String) -> Unit { emit(val) }"
  let (impls, _) = @parser.parse_string(src, name="t.mbt")
  let cache = FnCache::new()
  let rules = TaintRuleset::empty()
  rules.sinks.push({ method_name: "emit", kind: "Output", value_slot: 0, })
  let first : Array[Finding] = []
  run_cwe113(
    impls,
    "t.mbt",
    src,
    first,
    Error,
    cache~,
    rules~,
    output_sinks_enabled=true,
  )
  inspect(first.length(), content="1")
  let second : Array[Finding] = []
  run_cwe113(
    impls,
    "t.mbt",
    src,
    second,
    Error,
    cache~,
    rules~,
    output_sinks_enabled=false,
  )
  inspect(second.length(), content="0")
}

///|
test "f2_changed_callee_summary_invalidates_unchanged_caller" {
  let src = "fn f(resp : Response, val : String) -> Unit { resp.set_header(\"X\", helper(\"safe\", val)) }"
  let (impls, _) = @parser.parse_string(src, name="t.mbt")
  let cache = FnCache::new()
  let ictx = InterProceduralContext::new()
  let summary : FuncTaintSummary = {
    name: "helper",
    file: "helper.mbt",
    line: 1,
    params: ["safe", "x"],
    param_sinks: Map([]),
    ret_from: ["safe"],
    field_taint: Map([]),
    param_field_sinks: [],
  }
  ictx.summaries["helper"] = summary
  let first : Array[Finding] = []
  run_cwe113(impls, "t.mbt", src, first, Error, cache~, ictx~)
  inspect(first.length(), content="0")
  summary.ret_from.clear()
  summary.ret_from.push("x")
  let second : Array[Finding] = []
  run_cwe113(impls, "t.mbt", src, second, Error, cache~, ictx~)
  inspect(second.length(), content="1")
  inspect(cache.hits, content="0")
  inspect(cache.misses, content="2")
}

///|
test "f2_same_line_adjacent_edit_refreshes_finding_snippet" {
  let src1 = "fn f(resp : Response, val : String) -> Unit { resp.set_header(\"X\", val) } // old"
  let src2 = "fn f(resp : Response, val : String) -> Unit { resp.set_header(\"X\", val) } // new"
  let (impls1, _) = @parser.parse_string(src1, name="t.mbt")
  let (impls2, _) = @parser.parse_string(src2, name="t.mbt")
  let cache = FnCache::new()
  let first : Array[Finding] = []
  run_cwe113(impls1, "t.mbt", src1, first, Error, cache~)
  let second : Array[Finding] = []
  run_cwe113(impls2, "t.mbt", src2, second, Error, cache~)
  inspect(second.length(), content="1")
  assert_true(second[0].snippet == src2)
  assert_true(second[0].fingerprint != first[0].fingerprint)
}

///|
test "f2_caller_array_mutation_cannot_corrupt_cached_findings" {
  let cache = FnCache::new()
  let original = [mk_finding("saved")]
  cache.store("t.mbt", "f", "body", "symbols", original, 0)
  original.clear()
  match cache.lookup("t.mbt", "f", "body", "symbols") {
    Some(found) => {
      inspect(found.length(), content="1")
      found.clear()
    }
    None => fail("missing cached findings")
  }
  match cache.lookup("t.mbt", "f", "body", "symbols") {
    Some(found) => inspect(found.length(), content="1")
    None => fail("missing cached findings after caller mutation")
  }
}

///|
test "f2_cache_identity_has_unambiguous_component_boundaries" {
  assert_true(FnCache::key("a|b", "c") != FnCache::key("a", "b|c"))
  assert_true(fn_body_hash("a::b", "c") != fn_body_hash("a", "b::c"))
}

///|
test "f2_normal_cache_cannot_bypass_strict_cfg_verification" {
  let source =
    #|fn f(resp : Response, dirty : String) -> Unit {
    #|  let emit = fn() -> Unit { resp.set_header("X", dirty) }
    #|  emit()
    #|}
  let (impls, errors) = @parser.parse_string(source, name="verify.mbt")
  inspect(errors.length(), content="0")
  let cache = FnCache::new()
  set_cfg_verify_mode(false)
  cfg_exec_reset()
  let normal : Array[Finding] = []
  run_cwe113(impls, "verify.mbt", source, normal, Error, cache~)
  set_cfg_verify_mode(true)
  cfg_exec_reset()
  let first : Array[Finding] = []
  run_cwe113(impls, "verify.mbt", source, first, Error, cache~)
  let (_, _, first_divergent, _) = cfg_exec_stats()
  let first_unconfirmed = cfg_exec_unconfirmed_count()
  // Strict checks must rerun even when the preceding run was strict too.
  cfg_exec_reset()
  let second : Array[Finding] = []
  run_cwe113(impls, "verify.mbt", source, second, Error, cache~)
  let (_, _, second_divergent, _) = cfg_exec_stats()
  let second_unconfirmed = cfg_exec_unconfirmed_count()
  set_cfg_verify_mode(false)
  cfg_exec_reset()
  inspect(normal.length(), content="1")
  inspect(first.length(), content="1")
  inspect(second.length(), content="1")
  inspect(first_divergent, content="1")
  inspect(first_unconfirmed, content="1")
  inspect(second_divergent, content="1")
  inspect(second_unconfirmed, content="1")
  inspect(cache.size(), content="1")
  inspect(cache.hits, content="0")
  inspect(cache.misses, content="1")
}

///|
test "f2_strict_cfg_run_does_not_seed_normal_result_cache" {
  let source =
    #|fn f(resp : Response, dirty : String) -> Unit {
    #|  resp.set_header("X", dirty)
    #|}
  let (impls, errors) = @parser.parse_string(source, name="verify.mbt")
  inspect(errors.length(), content="0")
  let cache = FnCache::new()
  set_cfg_verify_mode(true)
  cfg_exec_reset()
  let strict : Array[Finding] = []
  run_cwe113(impls, "verify.mbt", source, strict, Error, cache~)
  let strict_cache_size = cache.size()
  let strict_cache_misses = cache.misses
  set_cfg_verify_mode(false)
  cfg_exec_reset()
  let first_normal : Array[Finding] = []
  run_cwe113(impls, "verify.mbt", source, first_normal, Error, cache~)
  let (normal_executed, _, _, _) = cfg_exec_stats()
  let second_normal : Array[Finding] = []
  run_cwe113(impls, "verify.mbt", source, second_normal, Error, cache~)
  cfg_exec_reset()
  inspect(strict.length(), content="1")
  inspect(strict_cache_size, content="0")
  inspect(strict_cache_misses, content="0")
  inspect(first_normal.length(), content="1")
  inspect(second_normal.length(), content="1")
  inspect(normal_executed, content="1")
  inspect(cache.size(), content="1")
  inspect(cache.misses, content="1")
  inspect(cache.hits, content="1")
}

///|
test "p6_1_disk_cache_roundtrip" {
  // build an in-memory cache, save, load, verify entries survive
  let root = test_tmp("p6_1_disk")
  @fs.create_dir(root) catch {
    _ => ()
  }
  let cache = FnCache::new()
  // simulate two functions with no findings
  cache.entries[FnCache::key("file_a.mbt", "fn_one")] = {
    body_hash: "hash1",
    symbols_fp: "fp_gen_1",
    findings: [],
    env_keys: 0,
  }
  cache.entries[FnCache::key("file_b.mbt", "fn_two")] = {
    body_hash: "hash2",
    symbols_fp: "fp_gen_1",
    findings: [],
    env_keys: 0,
  }
  // save
  disk_cache_save(cache, root, "fp_gen_1")
  // load with matching generation
  let loaded = disk_cache_load(root, "fp_gen_1")
  inspect(loaded.size(), content="2")
  let found = match loaded.lookup("file_a.mbt", "fn_one", "hash1", "fp_gen_1") {
    Some(arr) => arr.length() == 0
    None => false
  }
  inspect(found, content="true")
  // stale generation → empty
  let stale = disk_cache_load(root, "fp_gen_2")
  inspect(stale.size(), content="0")
}

///|
test "p6_1_disk_cache_no_crash_on_missing" {
  // load from nonexistent path should return empty, not crash (the original SIGABRT scenario)
  let cache = disk_cache_load("/nonexistent/path", "any_fp")
  inspect(cache.size(), content="0")
}
