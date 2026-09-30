// Source: mizchi/actrun src/e2e/main/main.mbt
// Verdict: needs_review (audit_hint — abort on file read failure)
// User-supplied path triggers abort if file missing; crash reachable from input

fn read_file_to_string(path : String) -> String? {
  None
}

pub fn e2e_read_text(path : String) -> String {
  match read_file_to_string(path) {
    Some(s) => s
    None => abort("failed to read: " + path)
  }
}
