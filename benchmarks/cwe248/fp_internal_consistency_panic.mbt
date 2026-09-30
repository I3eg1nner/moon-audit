// Source: bobzhang/toml internal/tokenize/tokenize.mbt
// Verdict: likely_false_positive (abort guards logically unreachable branch)
// Pattern match already covers all cases; abort is defensive internal assertion

pub fn read_number(input : String) -> Int {
  match input {
    "-" => -1
    "+" => 1
    _ => abort("Internal error: pattern matching inconsistency")
  }
}
