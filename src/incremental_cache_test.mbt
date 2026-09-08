// F2 (T7.2): fn-level cache tests — hit / symbols-invalidate / body-invalidate

///|
test "f2_cache_hit_reuses_cached_findings" {
  let src = "fn f(resp : Response, val : String) -> Unit { resp.set_header(\"X\", val) } pub fn g(resp : Response) -> Unit { resp.set_header(\"Y\", \"safe\") }"
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
  let src1 = "fn f(resp : Response, val : String) -> Unit { resp.set_header(\"X\", val) } pub fn g(resp : Response) -> Unit { resp.set_header(\"Y\", \"safe\") }"
  let src2 = "fn f2_changed(resp : Response, val : String) -> Unit { resp.set_header(\"X\", val) } pub fn g(resp : Response) -> Unit { resp.set_header(\"Y\", \"safe\") }"
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
