// Source: moonbitlang/async src/internal/event_loop/stdio.mbt
// Verdict: likely_false_positive (value validated before unsafe conversion)
// Return value checked for error before calling unsafe_from_int

pub enum FileKind {
  Regular
  Directory
  Other
}

fn unsafe_from_int(kind : Int) -> FileKind {
  match kind {
    0 => Regular
    1 => Directory
    _ => Other
  }
}

pub fn detect_file_kind(fd : Int) -> FileKind? {
  let kind = fd % 3
  if kind < 0 {
    return None
  }
  Some(unsafe_from_int(kind))
}
