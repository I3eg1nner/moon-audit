// Source: moonbitlang/openseek desktop/frontend/action_menu/action_menu.mbt
// Verdict: likely_false_positive (cast preceded by is_string() type guard)
// Value validated with is_string()/is_number() before each cast()

struct Value {
  val : String
}

fn Value::is_string(self : Value) -> Bool {
  true
}

fn Value::cast(self : Value) -> String {
  self.val
}

pub fn parse_target(target : Value) -> String? {
  guard target.is_string() else { return None }
  Some(target.cast())
}
