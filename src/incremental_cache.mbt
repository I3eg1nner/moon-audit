// F2 (T7.2): in-process function-level result cache with invalidation.
//
// Cache unit: one top-level function (qual-name + containing file).
// Key validity: (body_hash, analysis-context fingerprint) must both match.
//   body_hash : declaration source lines and positions (including parameters)
//   symbols_fp: symbols, rules, severity, output-sink policy, callee summaries
//
// Invalidation:
//   - symbols change  → ALL entries invalid (symbols_fp is a cache generation
//     marker; it already covers every symbol table with values)
//   - body/position change → that declaration's entry invalid
//   - summary/rule/policy change → all affected-context entries invalid
//     Summaries are rebuilt before the per-function rule execution. Their
//     contents enter the key so unchanged callers cannot replay stale results.
//
// Scope: in-process only (single moon-audit invocation). Cross-process
// persistence (serializing to disk) is a follow-up — documented in ROADMAP-T.

///|
pub(all) struct FnCacheEntry {
  body_hash : String // FNV-1a of fn source text at cache time
  symbols_fp : String // combined analysis-context fingerprint at cache time
  findings : Array[Finding] // this fn's finding contribution
  env_keys : Int // taint env terminal-state size (diagnostic)
}

///|
pub(all) struct FnCache {
  entries : Map[String, FnCacheEntry] // framed (file, fn_name) -> entry
  mut hits : Int
  mut misses : Int
}

///|
pub fn FnCache::new() -> FnCache {
  { entries: Map([]), hits: 0, misses: 0, }
}

///|
pub fn FnCache::key(file : String, fn_name : String) -> String {
  cache_parts_repr([file, fn_name])
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
        Some(e.findings.copy())
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
    findings: findings.copy(),
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

// Length-prefix every component: separators can occur in source or paths.

///|
fn cache_parts_repr(parts : Array[String]) -> String {
  let out = StringBuilder()
  for part in parts {
    out.write_string(part.length().to_string())
    out.write_string(":")
    out.write_string(part)
  }
  out.to_string()
}

///|
pub fn fn_body_hash(fn_name : String, body_repr : String) -> String {
  fnv1a([fn_name, body_repr])
}

///|
fn fn_source_repr(loc : @basic.Location, lines : Array[String]) -> String {
  let parts = [
    loc.start.lnum.to_string(),
    loc.start.column().to_string(),
    loc.end.lnum.to_string(),
    loc.end.column().to_string(),
  ]
  // Findings expose complete source lines as snippets. Include those lines,
  // including text outside the declaration on a shared line, to keep cached
  // snippets/fingerprints current after adjacent edits.
  for i = loc.start.lnum - 1; i < loc.end.lnum; i = i + 1 {
    if i >= 0 && i < lines.length() {
      parts.push(lines[i])
    }
  }
  cache_parts_repr(parts)
}

///|
fn taint_rules_cache_repr(rules : TaintRuleset) -> String {
  let parts : Array[String] = []
  for group in [rules.sources, rules.sinks, rules.sanitizers] {
    let entries : Array[String] = []
    for rule in group {
      entries.push(
        cache_parts_repr([
          rule.method_name,
          rule.kind,
          rule.value_slot.to_string(),
        ]),
      )
    }
    parts.push(cache_parts_repr(entries))
  }
  parts.push(
    cache_parts_repr(rules.fn_types.map(fn(p) { cache_parts_repr([p.0, p.1]) })),
  )
  parts.push(
    cache_parts_repr(
      rules.callbacks.map(fn(p) {
        cache_parts_repr([p.0, cache_parts_repr(p.1)])
      }),
    ),
  )
  parts.push(cache_parts_repr(rules.extends))
  parts.push(
    cache_parts_repr(
      rules.cb_timing.map(fn(p) {
        cache_parts_repr([
          p.0,
          match p.1 {
            Immediate => "immediate"
            Deferred => "deferred"
          },
        ])
      }),
    ),
  )
  parts.push(
    cache_parts_repr(
      rules.trait_edges.map(fn(edge) {
        cache_parts_repr([edge.lib_method, edge.trait_method, edge.note])
      }),
    ),
  )
  cache_parts_repr(parts)
}

///|
fn taint_context_cache_repr(ictx : InterProceduralContext?) -> String {
  match ictx {
    None => "none"
    Some(ctx) => {
      let summaries : Array[String] = []
      ctx.summaries.each(fn(name, summary) {
        let sinks : Array[String] = []
        summary.param_sinks.each(fn(param, kinds) {
          sinks.push(
            cache_parts_repr([
              param,
              cache_parts_repr(kinds.map(taint_sink_str)),
            ]),
          )
        })
        sinks.sort()
        let fields : Array[String] = []
        summary.field_taint.each(fn(param, writes) {
          fields.push(
            cache_parts_repr([
              param,
              cache_parts_repr(
                writes.map(fn(p) { cache_parts_repr([p.0, p.1]) }),
              ),
            ]),
          )
        })
        fields.sort()
        summaries.push(
          cache_parts_repr([
            name,
            summary.name,
            summary.file,
            summary.line.to_string(),
            cache_parts_repr(summary.params),
            cache_parts_repr(sinks),
            cache_parts_repr(summary.ret_from),
            cache_parts_repr(fields),
            cache_parts_repr(
              summary.param_field_sinks.map(fn(p) {
                cache_parts_repr([p.0, p.1])
              }),
            ),
          ]),
        )
      })
      summaries.sort()
      cache_parts_repr(["some", cache_parts_repr(summaries)])
    }
  }
}

///|
fn taint_analysis_fingerprint(
  symbols_fp : String,
  severity : Severity,
  rules : TaintRuleset,
  output_sinks : Bool,
  ictx : InterProceduralContext?,
) -> String {
  fnv1a([
    ANALYZER_VERSION,
    PARSER_VERSION_KEY,
    symbols_fp,
    severity_str(severity),
    output_sinks.to_string(),
    taint_rules_cache_repr(rules),
    taint_context_cache_repr(ictx),
  ])
}

// env terminal-state size for diagnostic purposes

///|
pub fn env_terminal_size(env : Map[String, Taint]) -> Int {
  env.length()
}
