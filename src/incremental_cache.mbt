// F2 (T7.2): in-process function-level result cache with invalidation.
//
// Cache unit: one top-level function (qual-name + containing file).
// Key validity: (body_hash, symbols_fingerprint) pair — both must match.
//   body_hash      : FNV-1a of the function's source text (loc range)
//   symbols_fp     : ProgramWorld symbol fingerprint (value-sensitive, T7.3)
//
// Invalidation:
//   - symbols change  → ALL entries invalid (symbols_fp is a cache generation
//     marker; it already covers every symbol table with values)
//   - body change     → only that function's entry invalid; SCC neighbours
//     re-analyze via the normal SCC pre-pass (summaries are rebuilt from
//     scratch each scan — the cache only skips the per-fn rule execution,
//     not the global summary solve; this is the honest thin-slice boundary)
//
// Scope: in-process only (single moon-audit invocation). Cross-process
// persistence (serializing to disk) is a follow-up — documented in ROADMAP-T.

///|
pub(all) struct FnCacheEntry {
  body_hash : String // FNV-1a of fn source text at cache time
  symbols_fp : String // ProgramWorld fingerprint at cache time
  findings : Array[Finding] // this fn's finding contribution
  env_keys : Int // taint env terminal-state size (diagnostic)
}

///|
pub(all) struct FnCache {
  entries : Map[String, FnCacheEntry] // "file|fn_name" -> entry
  mut hits : Int
  mut misses : Int
}

///|
pub fn FnCache::new() -> FnCache {
  { entries: Map([]), hits: 0, misses: 0, }
}

///|
pub fn FnCache::key(file : String, fn_name : String) -> String {
  file + "|" + fn_name
}

///|
pub fn FnCache::lookup(
  self : FnCache,
  file : String,
  fn_name : String,
  body_hash : String,
  symbols_fp : String,
) -> Array[Finding]? {
  let k = FnCache::key(file, fn_name)
  match self.entries.get(k) {
    Some(e) =>
      if e.body_hash == body_hash && e.symbols_fp == symbols_fp {
        self.hits += 1
        Some(e.findings)
      } else {
        self.misses += 1
        None
      }
    None => {
      self.misses += 1
      None
    }
  }
}

///|
pub fn FnCache::store(
  self : FnCache,
  file : String,
  fn_name : String,
  body_hash : String,
  symbols_fp : String,
  findings : Array[Finding],
  env_keys : Int,
) -> Unit {
  self.entries[FnCache::key(file, fn_name)] = {
    body_hash,
    symbols_fp,
    findings,
    env_keys,
  }
}

///|
pub fn FnCache::invalidate_all(self : FnCache) -> Unit {
  self.entries.clear()
}

///|
pub fn FnCache::size(self : FnCache) -> Int {
  self.entries.length()
}

// fn source-text hash: FNV-1a over the source lines spanned by fn loc.
// loc = fun_decl.loc (or method_name.loc): we approximate by hashing the
// full line containing the declaration through the fn's extent — using the
// file source and start line. For a thin slice, hash the fn name + params
// + body hash obtained from the caller (which has the parsed Expr).

///|
pub fn fn_body_hash(fn_name : String, body_repr : String) -> String {
  fnv1a_str(fn_name + "::" + body_repr)
}

///|
fn fnv1a_str(s : String) -> String {
  // reuse the fingerprint helper (acceptance.mbt fnv1a is private)
  let mut h : Int = 0x811C9DC5
  for ch in s {
    h = h ^ ch.to_int()
    h = h * 16777619
  }
  h.to_string()
}

// env terminal-state size for diagnostic purposes

///|
pub fn env_terminal_size(env : Map[String, Taint]) -> Int {
  env.length()
}
