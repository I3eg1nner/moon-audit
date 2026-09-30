// Source: moonbitlang/openseek src/update.mbt
// Verdict: likely_false_positive
// String comparison via has_suffix, not path construction

pub fn matches(text : String, name : String) -> Bool {
  text == name || text.has_suffix("/" + name)
}
