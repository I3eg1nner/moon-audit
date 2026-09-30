// Source: mizchi/actrun src/executor.mbt
// Verdict: likely_false_positive
// Git ref string construction, not filesystem path

pub fn branch_ref(branch_name : String) -> String {
  "refs/heads/" + branch_name
}
