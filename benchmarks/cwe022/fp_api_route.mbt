// Source: mizchi/actrun src/store_protocol.mbt
// Verdict: likely_false_positive (LLM confirmed)
// API route path construction, not filesystem path

pub fn output_path(run_id : String, step_id : String) -> String {
  "/runs/" + run_id + "/steps/" + step_id + "/outputs"
}
