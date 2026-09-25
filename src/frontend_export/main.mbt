///|
fn main {
  let args = @env.args()
  let compat = args.length() == 3 && args[1] == "--compat"
  if args.length() != 2 && !compat {
    println("argument_error: expected [--compat] source path")
    @sys.exit(2)
    return
  }
  let path = args[if compat { 2 } else { 1 }]
  let source = @fs.read_file_to_string(path) catch {
    _ => {
      println("read_error")
      @sys.exit(2)
      return
    }
  }
  if compat {
    let (items, reports) = @compat_parser.parse_string(
      source,
      name=path,
      parser=Handrolled,
    )
    if !reports.is_empty() {
      println(reports.to_json().stringify())
      @sys.exit(3)
      return
    }
    println(
      @basic.show_loc.protect(Json, fn() {
        items.map(fn(item) { item.json_repr() }).to_json().stringify()
      }),
    )
    return
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
