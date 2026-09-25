///|
extern "C" fn helper(child : Int) -> Int = "audit_acceptance_helper"

///|
fn main {
  let args = @env.args()
  if args.length() > 1 && args[1] == "version" {
    println("moon native-acceptance-helper")
  } else {
    let child = if args.length() > 1 && args[1] == "--child" { 1 } else { 0 }
    @sys.exit(helper(child))
  }
}
