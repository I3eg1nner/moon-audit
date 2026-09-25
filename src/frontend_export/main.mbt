///|
fn main {
  let args = @env.args()
  if args.length() != 2 {
    println("argument_error: expected one source path")
    @sys.exit(2)
    return
  }
  let path = args[1]
  let source = @fs.read_file_to_string(path) catch {
    _ => {
      println("read_error")
      @sys.exit(2)
      return
    }
  }
  let (items, reports) = @parser.parse_string(
    source,
    name=path,
    parser=Handrolled,
  )
  if !reports.is_empty() {
    println(reports.to_json().stringify())
    @sys.exit(3)
    return
  }
  let output = @basic.show_loc.protect(Json, fn() {
    items.map(fn(item) { item.json_repr() }).to_json().stringify()
  })
  println(output)
}
