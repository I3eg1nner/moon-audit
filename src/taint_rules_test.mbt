// ---------------------------------------------------------------------------
// P4b: async semantic model tests
// ---------------------------------------------------------------------------

///|
test "p4b_async_spawn_timing_deferred" {
  let rs = TaintRuleset::empty()
  ignore(extend_ruleset_with_model(rs, "async"))
  // spawn callback is deferred (stored, not executed during the call)
  inspect(rs.cb_timing_deferred_key("spawn") != None, content="true")
  inspect(rs.cb_timing_deferred_key("spawn_bg") != None, content="true")
  inspect(rs.cb_timing_deferred_key("spawn_loop") != None, content="true")
  // iterate is immediate
  inspect(rs.cb_timing_deferred_key("iterate") == None, content="true")
}

///|
test "p4b_async_http_sources" {
  let rs = TaintRuleset::empty()
  ignore(extend_ruleset_with_model(rs, "async"))
  // get/post/put return tainted (network data)
  let src_names : Array[String] = []
  for s in rs.sources {
    src_names.push(s.method_name)
  }
  inspect(src_names.contains("get"), content="true")
  inspect(src_names.contains("post"), content="true")
  inspect(src_names.contains("read_file"), content="true")
  inspect(src_names.contains("recv"), content="true")
}

///|
test "p4b_async_write_sinks" {
  let rs = TaintRuleset::empty()
  ignore(extend_ruleset_with_model(rs, "async"))
  // write_file/send_text/send_binary are sinks
  let sink_names : Array[String] = []
  for s in rs.sinks {
    sink_names.push(s.method_name)
  }
  inspect(sink_names.contains("write_file"), content="true")
  inspect(sink_names.contains("send_text"), content="true")
  inspect(sink_names.contains("send_binary"), content="true")
}

///|
test "p4b_async_model_opt_in_only" {
  // no "async" in extends → no async rules (add-only semantics)
  let rs = TaintRuleset::empty()
  let has = rs.sources.any(fn(s) { s.method_name == "read_file" })
  inspect(has, content="false")
}
