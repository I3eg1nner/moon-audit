///|
test "planner quoting preserves paths and never evaluates shell text" {
  assert_eq(
    @project_driver.plan_words("moonc check 'a b.mbt' '$(touch sentinel).mbt'"),
    Some(["moonc", "check", "a b.mbt", "$(touch sentinel).mbt"]),
  )
  assert_eq(
    @project_driver.plan_words("moonc check 'it'\\''s.mbt'"),
    Some(["moonc", "check", "it's.mbt"]),
  )
  assert_eq(
    @project_driver.plan_words("moonc check 'C:\\project\\file.mbt'"),
    Some(["moonc", "check", "C:\\project\\file.mbt"]),
  )
  assert_eq(@project_driver.plan_words("moonc check 'unterminated"), None)
}

///|
test "planner selects only compiler operands and discloses unsupported formats" {
  let root = @project_driver.absolute(".")
  let selected = @project_driver.file_plan(
    "moonc.exe check 'a b.mbt' .mooncakes/lib/dep.mbt doc.mbt.md -o out.mi", root,
  )
  assert_eq(selected, Some(([root + "/a b.mbt"], [root + "/doc.mbt.md"])))
  assert_eq(@project_driver.file_plan("new unknown plan format", root), None)
  assert_eq(
    @project_driver.file_plan("moonc check a.mbt\nmoonc check a.mbt", root),
    Some(([root + "/a.mbt"], [])),
  )
}
