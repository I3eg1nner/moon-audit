// Source: mizchi/actrun src/wasm_sandbox.mbt
// Verdict: supported_concern (LLM confirmed)
// Environment variable PPID concatenated into /tmp path

pub fn create_sandbox(safe_id : String) -> String {
  let pid = "12345"
  let tempdir = "/tmp/actrun-wasm-" + pid + "-" + safe_id
  tempdir
}
