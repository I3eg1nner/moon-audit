///|
extern "C" fn helper(child : Int) -> Int = "audit_acceptance_helper"

///|
async fn main {
  let args = @env.args()
  if @env.get_env_var("MOON_AUDIT_TEST_MODE") == Some("semantic-memory") {
    if args.length() > 1 && args[1] == "ide" {
      @sys.exit(helper(2))
    } else {
      let moon = @env.get_env_var("MOON_AUDIT_TEST_REAL_MOON").unwrap()
      let code = @process.run(moon, args[1:].to_owned()) catch { _ => 125 }
      @sys.exit(code)
    }
    return
  }
  if args.length() > 1 && args[1] == "version" {
    println("moon native-acceptance-helper")
  } else {
    let child = if args.length() > 1 && args[1] == "--child" { 1 } else { 0 }
    @sys.exit(helper(child))
  }
}
