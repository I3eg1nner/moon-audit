// Source: mizchi/luna.mbt sol/src/runtime_static_serving.mbt
// Verdict: supported_concern (LLM confirmed)
// filename parameter concatenated into filesystem paths without traversal check

fn read_file_text(path : String) -> String? {
  None
}

pub fn serve_static(filename : String) -> String? {
  let sol_dev_path = ".sol/dev/static/" + filename
  let sol_prod_path = ".sol/prod/static/" + filename
  match read_file_text(sol_dev_path) {
    Some(c) => Some(c)
    None => read_file_text(sol_prod_path)
  }
}
