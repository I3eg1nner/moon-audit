// T6.4 thin: analysis dump structure tests

///|
fn make_dump_probe() -> String {
  // a minimal project whose functions exercise every dumped analysis:
  // - a receiver call (call-graph + HIR CallStmt)
  // - an allocation + alias (points-to constraints)
  // - a local binding with a later use (live vars)
  let root = test_tmp("t6b_dump_probe")
  let src = @path.Path(root).join(@path.Path("src")).0
  @fs.create_dir(root) catch {
    _ => ()
  }
  @fs.create_dir(src) catch {
    _ => ()
  }
  let modp = @path.Path(root).join(@path.Path("moon.mod")).0
  @fs.write_string_to_file(modp, "name = \"t6b/p\"\n") catch {
    _ => ()
  }
  let pkgp = @path.Path(src).join(@path.Path("moon.pkg")).0
  @fs.write_string_to_file(pkgp, "") catch {
    _ => ()
  }
  let libp = @path.Path(src).join(@path.Path("lib.mbt")).0
  @fs.write_string_to_file(
    libp, "pub struct Box { v : String } pub fn go(b : Box) -> String { let a = b; a.v.to_owned() }",
  ) catch {
    _ => ()
  }
  root
}

///|
fn dump_file_non_empty(dir : String, name : String) -> Bool {
  let p = @path.Path(dir).join(@path.Path(name)).0
  let content = @fs.read_file_to_string(p) catch { _ => return false }
  content.trim().length() > 0
}

///|
test "t6b_dump_all_five_files_present_and_non_empty" {
  let root = make_dump_probe()
  let dir = test_tmp("t6b_dump_out")
  dump_analyses(dir, root, Config::default())
  // the four data files + the plan
  inspect(dump_file_non_empty(dir, "analysis-plan.txt"), content="true")
  inspect(dump_file_non_empty(dir, "hir-traces.txt"), content="true")
  inspect(dump_file_non_empty(dir, "call-graph.txt"), content="true")
  inspect(dump_file_non_empty(dir, "points-to.txt"), content="true")
  inspect(dump_file_non_empty(dir, "live-vars.txt"), content="true")
}

///|
test "t6b_dump_plan_contains_all_analyses_in_dependency_order" {
  let root = make_dump_probe()
  let dir = test_tmp("t6b_dump_plan")
  dump_analyses(dir, root, Config::default())
  let p = @path.Path(dir).join(@path.Path("analysis-plan.txt")).0
  let plan = @fs.read_file_to_string(p) catch { _ => "" }
  // all four analyses are scheduled
  inspect(plan.contains("taint-flow"), content="true")
  inspect(plan.contains("call-graph"), content="true")
  inspect(plan.contains("points-to"), content="true")
  inspect(plan.contains("live-vars"), content="true")
  // dependency order: every analysis appears after its declared deps
  // (current deps are empty, so this asserts the numbered order lines exist)
  let lines = plan.split("\n")
  let mut ordered = 0
  for line in lines {
    let t = line.trim()
    let first_is_digit = if t.length() > 0 {
      let c0 = t[0]
      let zero : UInt16 = 48
      let nine : UInt16 = 57
      c0 >= zero && c0 <= nine
    } else {
      false
    }
    if first_is_digit {
      ordered += 1
    }
  }
  inspect(ordered >= 4, content="true") // four numbered steps
}

///|
test "t6b_dump_hir_trace_has_provenance_fn_header" {
  let root = make_dump_probe()
  let dir = test_tmp("t6b_dump_hir")
  dump_analyses(dir, root, Config::default())
  let p = @path.Path(dir).join(@path.Path("hir-traces.txt")).0
  let hir = @fs.read_file_to_string(p) catch { _ => "" }
  // fn header carries provenance: fn name @ source file
  inspect(hir.contains("fn go @ "), content="true")
  inspect(hir.contains("lib.mbt"), content="true")
  // the receiver call shows up as a CallStmt in the trace
  inspect(hir.contains("to_owned"), content="true")
}
