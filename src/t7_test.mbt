// T7 thin-slice tests: timing format, mode difference, fingerprint
// value-sensitivity (gate15 known-gap closure)

///|
test "t7_timing_render_format" {
  // stage recording + render shape: "timing: <stage>=Nms ... total=Nms"
  let ts = StageTimings::new()
  ts.record("world-load", 12)
  ts.record("analysis", 340)
  let line = ts.render()
  inspect(line.has_prefix("timing: "), content="true")
  inspect(line.contains("world-load=12ms"), content="true")
  inspect(line.contains("analysis=340ms"), content="true")
  inspect(line.contains("total=352ms"), content="true")
  // time<T> records elapsed (>= 0) without changing the result
  let ts2 = StageTimings::new()
  let v = ts2.time("work", fn() { 41 + 1 })
  inspect(v, content="42")
  inspect(ts2.render().contains("work="), content="true")
  // empty record renders an explicit note, not a blank line
  inspect(StageTimings::new().render(), content="timing: (no stages recorded)")
}

///|
test "t7_deep_mode_enables_interproc_on_nonweb" {
  // non-web project: helper param reaches a header sink inside helper; the
  // caller passes a tainted value. quick mode must NOT run the cross-func
  // phase (non-web gate); deep mode must report it.
  let root = test_tmp("t7_mode")
  let dir = root + "/src"
  @fs.create_dir(root) catch {
    _ => ()
  }
  @fs.create_dir(dir) catch {
    _ => ()
  }
  @fs.write_string_to_file(root + "/moon.mod", "name = \"t7/m\"\n") catch {
    _ => ()
  }
  @fs.write_string_to_file(dir + "/moon.pkg", "") catch {
    _ => ()
  }
  @fs.write_string_to_file(
    dir + "/lib.mbt",
    "fn set_custom(res : Response, val : String) -> Unit { res.set_header(\"X-Custom\", val) } pub fn go(res : Response, req : Request) -> Unit { let v = req.query(\"q\"); set_custom(res, v) }",
  ) catch {
    _ => ()
  }
  let quick_cfg = { ..Config::default(), analysis_mode: "quick", }
  let deep_cfg = { ..Config::default(), analysis_mode: "deep", }
  let quick = scan_project(root, quick_cfg)
  let deep = scan_project(root, deep_cfg)
  // quick: the helper's own intra-procedural param->sink fires (CWE-113
  // is ungated); the CALLER finding requires the cross-func phase
  inspect(quick.findings.length().to_string(), content="1")
  // deep: cross-func phase adds the caller-side finding (summary hit)
  inspect(deep.findings.length().to_string(), content="2")
  inspect(quick.analysis_scope.contains("mode=quick"), content="true")
  inspect(deep.analysis_scope.contains("mode=deep"), content="true")
}

///|
test "t7_fingerprint_value_sensitivity" {
  // gate15 known-gap: same key, different VALUE must change the fingerprint
  let a = PkgSymbols::new()
  a.fn_ret["f"] = IRConcrete("Int", [])
  let b = PkgSymbols::new()
  b.fn_ret["f"] = IRConcrete("String", []) // same name, different type
  inspect(symbols_fingerprint(a) != symbols_fingerprint(b), content="true")
  // struct field type change also invalidates
  let fc : Map[String, IRType] = Map([])
  fc["x"] = IRConcrete("Int", [])
  let fd : Map[String, IRType] = Map([])
  fd["x"] = IRConcrete("Bytes", [])
  let c = PkgSymbols::new()
  c.struct_fields["S"] = fc
  let d = PkgSymbols::new()
  d.struct_fields["S"] = fd
  inspect(symbols_fingerprint(c) != symbols_fingerprint(d), content="true")
  // version stamps present in the key material: fingerprints differ from
  // the raw-hash of entries alone (constant prefix observed via stability
  // — same table twice must be equal)
  inspect(symbols_fingerprint(a) == symbols_fingerprint(a), content="true")
}
