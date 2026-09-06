// M2: flow-sensitive intra-procedural taint engine.
// Structured CFG walk (branch fork/join) over the official AST — the
// "HIR-lite" layer. Replaces textual heuristics with dataflow facts:
//   - taint state per variable, ordered by control flow
//   - branch merge (union) for if/match/try
//   - guard/validation refinement: validated vars become clean in the
//     taken branch (the key precision upgrade over the old rule)

///|
priv enum Taint {
  Clean
  Tainted // tainted, origin unknown (env/param/callback)
  TaintedParam(String) // tainted, originated from this fn parameter
  // field read of a param-typed receiver: taint is CONDITIONAL on the
  // caller actually passing an object with a tainted field — no local
  // finding; recorded as a param-field summary and re-checked at call sites
  TaintedFieldRef(String, String) // (param, field)
} derive(Eq)

///|
fn taint_or(a : Taint, b : Taint) -> Taint {
  // T3.1: delegates to the SecurityFact lattice (join = set union, algebraic
  // by construction) and re-projects through the legacy view rules. Zero
  // behavior change: locked by t3a_differential_16_pairs_vs_legacy_table
  // (232 tests incl. the full legacy-table matrix).
  taint_view_of(taint_to_fact(a).join(taint_to_fact(b)))
}

///|
fn taint_to_fact(t : Taint) -> SecurityFact {
  match t {
    Clean => SecurityFact::clean()
    Tainted => SecurityFact::tainted_unknown()
    TaintedParam(p) => fact_of_tainted_param(p)
    TaintedFieldRef(p, f) => fact_of_field_ref(p, f)
  }
}

///|
fn taint_view_of(f : SecurityFact) -> Taint {
  // view rules (verbatim reproduction of the pre-T3.1 join table's outcome):
  //   single plain source keeps attribution even when unknown taint joined
  //   (legacy `(_, P(p)) => P(p)`); single field source is conditional;
  //   mixed (>=2) or unknown-only drops attribution
  let n = f.src.length()
  if !f.unknown && n == 0 {
    return Clean
  }
  if n == 0 {
    return Tainted
  }
  if n == 1 {
    let s = f.src[0]
    let dot = find_first_dot(s)
    if dot >= 0 {
      return if f.unknown {
        Tainted
      } else {
        TaintedFieldRef(Show::to_string(s[:dot]), Show::to_string(s[dot + 1:]))
      }
    }
    return TaintedParam(s)
  }
  Tainted
}

///|
fn is_tainted(t : Taint) -> Bool {
  t != Clean
}

// T3.3: loop-fixpoint budget bookkeeping — package-level (src/ is one
// package). `exhausted` counts bodies that hit the iteration cap (env may
// be incomplete; disclosed in the analysis-scope line). `last_iters` is
// the iteration count of the most recent loop solve (test observation).

///|
priv struct LoopBudget {
  mut exhausted : Int
  mut last_iters : Int
}

///|
let loop_budget : LoopBudget = { exhausted: 0, last_iters: 0, }

// test/observation hook: iteration count of the most recent loop solve

///|
pub fn loop_fixpoint_last_iterations() -> Int {
  loop_budget.last_iters
}

// test/observation hook: total budget-exhausted loops this project

///|
pub fn loop_fixpoint_exhausted_count() -> Int {
  loop_budget.exhausted
}

// test hook: reset the per-project budget bookkeeping

///|
pub fn loop_budget_reset() -> Unit {
  loop_budget.exhausted = 0
  loop_budget.last_iters = 0
}

// statement-ish node count of a loop body: the budget unit (cap uses
// min(count + 2, LOOP_CAP_MAX)); counts Let/assign/call/control-flow nodes,
// not every sub-expression

///|
fn loop_budget_units(e : @syntax.Expr) -> Int {
  match e {
    Sequence(exprs~, last_expr~, ..) => {
      let mut n = 1
      for x in exprs {
        n += loop_budget_units(x)
      }
      n += loop_budget_units(last_expr)
      n
    }
    Let(..)
    | LetMut(..)
    | LetAnd(..)
    | LetFn(..)
    | Assign(..)
    | Mutate(..)
    | ArraySet(..)
    | ArrayAugmentedSet(..)
    | Apply(..)
    | DotApply(..)
    | While(..)
    | For(..)
    | ForEach(..)
    | If(..)
    | Match(..)
    | Try(..)
    | Return(..)
    | Raise(..)
    | Break(..)
    | Continue(..) => 1
    LabelledBlock(body~, ..) => loop_budget_units(body)
    Group(expr~, ..) => loop_budget_units(expr)
    _ => 0
  }
}

// T3.3 monotone loop fixpoint (replaces the 3-pass magic number):
//   - stability is judged on SecurityFact JOIN results (env + carried
//     loop exits), not on string fingerprints
//   - one pass runs, then facts are compared; unstable => rerun
//   - budget = min(body_units + 2, 8); exhaustion marks the env
//     incomplete via loop_budget.exhausted (scope disclosure)

///|
fn loop_fixpoint_snapshot(
  ctx : FlowCtx,
  base_exits : Int,
) -> Array[(String, SecurityFact)] {
  // SEMANTIC state view: LIVE scope slots resolved through name_map to
  // their latest declaration. Raw env keys cannot be compared across
  // passes: R3 declaration ids are per-execution (each re-run of a body
  // allocates fresh d-keys), so key sets only grow. The resolved view of
  // live slots is the actual analysis state and IS monotone.
  let live : Map[Int, Bool] = Map([])
  for id in ctx.scope_stack {
    live[id] = true
  }
  let slots : Array[String] = []
  ctx.name_map.each(fn(slot, _) { slots.push(slot) })
  slots.sort()
  let snap : Array[(String, SecurityFact)] = []
  for slot in slots {
    // slot = "s<scope-id>:<name>"
    let colon = find_last(slot, ":")
    if colon < 0 {
      continue
    }
    let sid_txt = Show::to_string(slot[1:colon])
    let sid = parse_int_or_neg(sid_txt)
    if sid < 0 || !live.contains(sid) {
      continue // stale slot of a popped inner scope
    }
    match ctx.name_map.get(slot) {
      Some(dkey) =>
        snap.push((slot, taint_to_fact(or_clean_taint(ctx.env.get(dkey)))))
      None => ()
    }
  }
  // exits slice is folded into ONE join fact: appending the same value
  // again (re-executed break across passes) does not change the join —
  // stability stays monotone under duplicate exits
  let mut exits_fact = SecurityFact::bottom()
  let mut i = base_exits
  while i < ctx.loop_exits.length() {
    exits_fact = exits_fact.join(taint_to_fact(ctx.loop_exits[i]))
    i += 1
  }
  snap.push(("#exits", exits_fact))
  // heap facts (site -> field -> taint): keys are syntactic alloc sites
  // (file:line) so they are stable across passes; a still-growing heap
  // must keep the solve running (stopping early would under-approximate
  // field-propagated taint)
  let heap_keys : Array[String] = []
  ctx.heap.each(fn(site, _) { heap_keys.push(site) })
  heap_keys.sort()
  for site in heap_keys {
    match ctx.heap.get(site) {
      Some(fields) => {
        let fnames : Array[String] = []
        fields.each(fn(f, _) { fnames.push(f) })
        fnames.sort()
        for f in fnames {
          match fields.get(f) {
            Some(v) => snap.push(("h:" + site + ":" + f, taint_to_fact(v)))
            None => ()
          }
        }
      }
      None => ()
    }
  }
  snap
}

///|
fn facts_stable(
  before : Array[(String, SecurityFact)],
  after : Array[(String, SecurityFact)],
) -> Bool {
  // join-stability: equal cardinality + leq in BOTH directions per key
  // (leq both ways == equality on this lattice; keys are canonical)
  if before.length() != after.length() {
    return false
  }
  for pair in before {
    let (k, f) = pair
    let after_fact : SecurityFact? = None
    let mut found : SecurityFact? = after_fact
    for pair2 in after {
      let (k2, f2) = pair2
      if k2 == k {
        found = Some(f2)
        break
      }
    }
    match found {
      Some(g) => if !(f.leq(g) && g.leq(f)) { return false }
      None => return false
    }
  }
  true
}

///|
let loop_cap_max : Int = 8

// small non-raising int parse for scope-slot ids ("s12:x" -> 12)

///|
fn parse_int_or_neg(s : String) -> Int {
  if s.length() == 0 {
    return -1
  }
  let mut v = 0
  for ch in s {
    let d = ch.to_int() - 48
    if d < 0 || d > 9 {
      return -1
    }
    v = v * 10 + d
  }
  v
}

///|
fn flow_to_fixpoint(e : @syntax.Expr, ctx : FlowCtx, base_exits : Int) -> Unit {
  let cap = {
    let units = loop_budget_units(e)
    if units + 2 < loop_cap_max {
      units + 2
    } else {
      loop_cap_max
    }
  }
  let findings_start = ctx.findings.length()
  let mut iterations = 0
  while iterations < cap {
    let before = loop_fixpoint_snapshot(ctx, base_exits)
    let _ = flow(e, ctx)
    iterations += 1
    if facts_stable(before, loop_fixpoint_snapshot(ctx, base_exits)) {
      break
    }
  }
  if iterations == cap {
    loop_budget.exhausted += 1 // env may be incomplete: disclosed upstream
  }
  loop_budget.last_iters = iterations
  // re-executed passes re-report the same sink sites: keep the FIRST
  // finding per line (same rule + line = same site; matches the outer
  // scan dedup granularity). Later passes only ADD new lines.
  let dedup : Map[Int, Bool] = Map([])
  let out : Array[Finding] = []
  let mut idx = findings_start
  while idx < ctx.findings.length() {
    let f = ctx.findings[idx]
    if !dedup.contains(f.line) {
      dedup[f.line] = true
      out.push(f)
    }
    idx += 1
  }
  while ctx.findings.length() > findings_start {
    let _ = ctx.findings.pop()
  }
  for f in out {
    ctx.findings.push(f)
  }
}

///|
fn or_clean_taint(t : Taint?) -> Taint {
  match t {
    Some(v) => v
    None => Clean
  }
}

///|
priv struct FlowCtx {
  env : Map[String, Taint]
  findings : Array[Finding]
  file : String
  source : String
  severity : Severity
  mut record_sinks : Array[String]? // M3 summary recording channel
  mut record_returns : Array[String]? // P3: params flowing to return value
  mut record_fields : Array[String]? // P3: "r|field|src-param" field writes
  ictx : InterProceduralContext? // P3: summaries consumed at call sites
  // bounded heap slice (M4-lite): var -> alloc-site id ("file:line")
  sites : Map[String, String]
  // alloc-site -> field -> taint. G4: PER-BRANCH fork/join (weak merge at
  // join points via fact-level join); monotone growth keeps joins sound.
  // (Historical note: pre-G4 this map was deliberately shared across
  // branch copies — see ROADMAP-T G4 for the c5 counterexample that
  // forced isolation.)
  heap : Map[String, Map[String, Taint]]
  // site of the literal just evaluated, consumed at the next binding point
  mut alloc_result : String?
  // T2.1 scope identity: env keys are "<scope-id>:<name>"; the stack is
  // per-ctx (branch copies are independent), the counter is a shared box
  // so ids stay unique across sibling branches
  scope_stack : Array[Int]
  scope_counter : Array[Int]
  // R3 declaration identity: name_map maps "s<scope>:<name>" to the LATEST
  // declaration key "d<decl-id>" for that scope slot; decl_counter is a
  // shared box so ids are unique across branches and never reset — each
  // `let`/pattern bind is a NEW declaration (its own env/sites/comps slot);
  // assignment mutates the EXISTING declaration slot instead
  name_map : Map[String, String]
  decl_counter : Array[Int]
  // T2.3 direct raise payloads: every Raise pushes its value taint here;
  // the enclosing Try unions the buffer into its error payload (shared
  // reference across branch copies, like heap)
  raise_buffer : Array[Taint]
  // T2.3 structured value positions: decl key -> ctor ("#tuple" for plain
  // tuples) -> component taints. Projections address (decl, ctor, idx) —
  // the G2 shadowing counterexample projects the exact component, and
  // enum payload positions survive rebinding (stale decls unreachable)
  struct_comps : Map[String, Map[String, Array[Taint]]]
  // T2.1 HIR statement trace (shared reference: branch copies append to
  // the same sequence) + temp id counter (shared for uniqueness)
  hir_trace : Array[Stmt]
  hir_temp_ctr : Array[Int]
  // T2.5 closure bindings: let-bound closures are REGISTERED at creation
  // (captures frozen: value taints copied, struct sites shared via the
  // name-keyed site map) and their body flows ONLY at a call site
  // (create != execute). Shared across branch copies: bindings are
  // immutable after registration (one-shot invoke guard on first call).
  closures : Map[String, ClosureBinding]
  // param-field sink recording channel ("param|field") for summaries
  mut record_field_sinks : Array[String]?
  // T2.2 defer exit sequence: registered by the Defer arm, executed LIFO
  // at the enclosing block exit (Defer arm tail), at Return, and at the
  // function tail for uncaught raises — shared by branch copies on purpose
  defers : Array[@syntax.Expr]
  // T2.2 loop exit accumulator: break(value)/continue(args) taints join at
  // the enclosing loop's merge point (shared ref across branch copies)
  loop_exits : Array[Taint]
  taint_rules : TaintRuleset // project DSL entries (ADD to built-ins)
  // CWE-116/tainted-output gate: fires only from DSL/lib-model Output sinks;
  // default enabled (no builtin sink carries kind Output, so projects
  // without a model/config are unaffected)
  output_sinks_enabled : Bool
}

///|
// T2.2: execute pending deferred expressions LIFO at a block/function exit

///|
fn run_defers(ctx : FlowCtx) -> Unit {
  while ctx.defers.length() > 0 {
    let e = ctx.defers.pop() |> or_unit
    let _ = flow(e, ctx)
  }
}

///|
fn or_unit(v : @syntax.Expr?) -> @syntax.Expr {
  match v {
    Some(e) => e
    None =>
      // unreachable: pop on non-empty array
      Unit(loc=dummy_flow_loc(), faked=true)
  }
}

///|
fn FlowCtx::copy(self : FlowCtx) -> FlowCtx {
  let env : Map[String, Taint] = Map([])
  self.env.each(fn(k, v) { env[k] = v })
  let name_map : Map[String, String] = Map([])
  self.name_map.each(fn(k, v) { name_map[k] = v })
  let sites : Map[String, String] = Map([])
  self.sites.each(fn(k, v) { sites[k] = v })
  let scope_stack : Array[Int] = []
  for id in self.scope_stack {
    scope_stack.push(id)
  }
  let struct_comps : Map[String, Map[String, Array[Taint]]] = Map([])
  self.struct_comps.each(fn(k, m) {
    let mcopy : Map[String, Array[Taint]] = Map([])
    m.each(fn(ctor, arr) {
      let ccopy : Array[Taint] = []
      for c in arr {
        ccopy.push(c)
      }
      mcopy[ctor] = ccopy
    })
    struct_comps[k] = mcopy
  })
  // G4 branch-heap isolation: heap facts are PER-BRANCH state. A branch
  // copy owns a deep copy of the fork-point heap; strong field writes
  // (Mutate) stay local to the branch, and join points weak-merge facts
  // (field-key taint_or) — one branch can no longer erase another's
  // taint by overwriting the same field.
  let heap : Map[String, Map[String, Taint]] = Map([])
  self.heap.each(fn(site, fm) {
    let fcopy : Map[String, Taint] = Map([])
    fm.each(fn(f, ft) { fcopy[f] = ft })
    heap[site] = fcopy
  })
  // record channels/raise buffer/scope+decl counters remain shared
  // references by design (monotone facts + id uniqueness; R6 scopes the
  // raise buffer manually). hir_trace and hir_temp_ctr are references
  // too: the statement sequence is global to the function analysis (the
  // trace observes all branches)
  {
    ..self,
    env,
    name_map,
    sites,
    scope_stack,
    struct_comps,
    closures: self.closures,
    heap,
    alloc_result: None,
  }
}

// ── T2.1 scoped variable identity ────────────────────────────────────────
// env keys are "<scope>:<name>"; lookup walks the stack inner-first, new
// bindings shadow in the current scope, assignments update the defining
// scope's slot. Same-name destructuring can no longer alias the outer var.

///|
fn scope_push(ctx : FlowCtx) -> Unit {
  ctx.scope_counter[0] += 1
  ctx.scope_stack.push(ctx.scope_counter[0])
}

///|
fn scope_pop(ctx : FlowCtx) -> Unit {
  ignore(ctx.scope_stack.pop())
}

///|
fn scope_lookup_key(ctx : FlowCtx, name : String) -> String? {
  let mut i = ctx.scope_stack.length() - 1
  while i >= 0 {
    let nkey = "s" + ctx.scope_stack[i].to_string() + ":" + name
    match ctx.name_map.get(nkey) {
      Some(dkey) => if ctx.env.contains(dkey) { return Some(dkey) }
      None => ()
    }
    i -= 1
  }
  None
}

///|
fn env_bind(ctx : FlowCtx, name : String, t : Taint) -> String {
  // R3: a NEW declaration gets a fresh id (never reused, never reset);
  // same-scope same-name rebinds chain through name_map, so stale facts
  // (env value, tuple components, alloc-site binding) become unreachable
  ctx.decl_counter[0] += 1
  let dkey = "d" + ctx.decl_counter[0].to_string()
  ctx.name_map["s" + current_scope_id(ctx).to_string() + ":" + name] = dkey
  ctx.env[dkey] = t
  dkey
}

///|
fn current_scope_id(ctx : FlowCtx) -> Int {
  match ctx.scope_stack.length() {
    0 => 0
    n => ctx.scope_stack[n - 1]
  }
}

///|
fn env_assign(ctx : FlowCtx, name : String, t : Taint) -> Unit {
  // assignment MUTATES the defining declaration's slot (no new id)
  match scope_lookup_key(ctx, name) {
    Some(key) => ctx.env[key] = t
    None => ignore(env_bind(ctx, name, t))
  }
}

///|
fn env_lookup(ctx : FlowCtx, name : String) -> Taint? {
  match scope_lookup_key(ctx, name) {
    Some(key) => ctx.env.get(key)
    None => None
  }
}

// R3: alloc-site bindings share the declaration identity — lookup/set
// resolve a bare name to its CURRENT declaration slot (stale slots of
// shadowed declarations are unreachable, so rebinding invalidates them)

///|
// G4 c5: a receiver WITHOUT a visible alloc-site (e.g. obtained from an
// opaque call `let b = mk()`) still gets field-sensitive treatment: the
// variable's declaration slot is used as a VIRTUAL site. Aliases are not
// tracked (documented approximation) — writes/reads through the same
// binding see the same facts, and branch fork/join isolates them.

///|
fn heap_site_of(ctx : FlowCtx, name : String) -> String? {
  match sites_get(ctx, name) {
    Some(s) => Some(s)
    None =>
      match scope_lookup_key(ctx, name) {
        Some(k) => Some("var:" + k)
        None => None
      }
  }
}

///|
fn sites_get(ctx : FlowCtx, name : String) -> String? {
  match scope_lookup_key(ctx, name) {
    Some(k) => ctx.sites.get(k)
    None => ctx.sites.get(name)
  }
}

///|
fn sites_set(ctx : FlowCtx, name : String, site : String) -> Unit {
  match scope_lookup_key(ctx, name) {
    Some(k) => ctx.sites[k] = site
    None => ctx.sites[name] = site
  }
}

// record tuple-literal components for a simple Var binding (scoped)

// scoped tuple component lookup

///|
fn tuple_comp_lookup(ctx : FlowCtx, name : String, idx : Int) -> Taint? {
  // T2.3: projection addressed by (decl, "#tuple", idx)
  match scope_lookup_key(ctx, name) {
    Some(key) => comps_get(ctx, key, "#tuple", idx)
    None => None
  }
}

///|
fn ctor_payload_lookup(
  ctx : FlowCtx,
  name : String,
  ctor : String,
  idx : Int,
) -> Taint? {
  match scope_lookup_key(ctx, name) {
    Some(key) => comps_get(ctx, key, ctor, idx)
    None => None
  }
}

// bind a Constr pattern against recorded (decl, ctor, idx) positions;
// returns false when no position info exists (caller falls back to whole)

///|
fn project_ctor_positions(
  scrut_expr : @syntax.Expr,
  pattern : @syntax.Pattern,
  ctx : FlowCtx,
  whole : Taint,
) -> Bool {
  match (scrut_expr, pattern) {
    (Ident(id~, ..), Constr(constr~, args~, ..)) => {
      // scrutinee must be a simple identifier with recorded positions
      let scrut_name = match id.name {
        Ident(name~) => name
        Dot(..) => return false
      }
      let matched : Bool = match args {
        Some(list) => list.length() > 0
        None => false
      }
      if !matched {
        return false
      }
      let list = match args {
        Some(l) => l
        None => return false
      }
      // every sub-pattern must itself be a simple Var (position projection)
      let mut all_var = true
      for arg in list {
        match arg.pat {
          Var(_) => ()
          _ => all_var = false
        }
      }
      if !all_var {
        return false
      }
      let mut i = 0
      for arg in list {
        match arg.pat {
          Var(binder) =>
            match ctor_payload_lookup(ctx, scrut_name, constr.name.name, i) {
              Some(t) => ignore(env_bind(ctx, binder.name, t))
              None =>
                // position unknown: fall back to whole for this binder
                ignore(env_bind(ctx, binder.name, whole))
            }
          _ => ()
        }
        i += 1
      }
      true
    }
    _ => false
  }
}

// T2.1 trace emission: materialize arg temps + the call statement

///|
fn hir_emit_call(ctx : FlowCtx, target : String, temps : Array[Int]) -> Unit {
  ctx.hir_trace.push(CallStmt(target, temps.copy()))
}

///|
fn hir_temps_from_pairs(ctx : FlowCtx, n : Int) -> Array[Int] {
  let temps : Array[Int] = []
  for i in 0..<n {
    let tid = hir_fresh_temp(ctx)
    ctx.hir_trace.push(LetEvalTemp(tid, i))
    temps.push(tid)
  }
  temps
}

///|
fn hir_emit_sink(ctx : FlowCtx, kind : String, temps : Array[Int]) -> Unit {
  ctx.hir_trace.push(SinkStmt(kind, temps.copy()))
}

// ── entry: analyze one top-level function ─────────────────────────────────

///|
pub fn run_flow_taint_func(
  params : @list.List[@syntax.Parameter]?,
  body : @syntax.Expr,
  file : String,
  source : String,
  severity : Severity,
  findings : Array[Finding],
  ictx? : InterProceduralContext,
  rules? : TaintRuleset,
  output_sinks_enabled? : Bool,
  fn_name? : String, // T3.4: live-vars driver labels the trace
  hir_out? : Array[(String, Array[Stmt])], // append (name, trace) at exit
) -> Unit {
  let ctx : FlowCtx = {
    env: Map([]),
    findings,
    file,
    source,
    severity,
    record_sinks: None,
    record_returns: None,
    record_fields: None,
    sites: Map([]),
    heap: Map([]),
    alloc_result: None,
    scope_stack: [],
    scope_counter: [0],
    name_map: Map([]),
    decl_counter: [0],
    raise_buffer: [],
    struct_comps: Map([]),
    hir_trace: [],
    hir_temp_ctr: [0],
    closures: Map([]),
    record_field_sinks: None,
    defers: [],
    loop_exits: [],
    ictx,
    taint_rules: match rules {
      Some(r) => r
      None => TaintRuleset::empty()
    },
    output_sinks_enabled: match output_sinks_enabled {
      Some(b) => b
      None => true
    },
  }
  scope_push(ctx) // function scope
  // T2.2 safety net: pending defers (e.g. from an uncaught raise path)
  // execute at function exit
  // fn parameters carry param provenance: direct param flow reaches
  // sinks (report), but field access on a param is a config-like read
  // (Clean) — provenance-aware field propagation (review counterexample)
  match params {
    Some(ps) =>
      for param in ps {
        match param {
          Positional(binder~, ..)
          | Labelled(binder~, ..)
          | Optional(binder~, ..)
          | QuestionOptional(binder~, ..) =>
            ignore(env_bind(ctx, binder.name, TaintedParam(binder.name)))
          DiscardPositional(..) => ()
        }
      }
    None => ()
  }
  let _ = flow(body, ctx)
  // T2.2: function exit — execute still-pending defers (uncaught-raise
  // path); defers from completed blocks already ran at their block tail
  run_defers(ctx)
  ctx.raise_buffer.clear() // raises escaping this function: error exit (P3)
  scope_pop(ctx)
  match hir_out {
    Some(out) => {
      let name = match fn_name {
        Some(n) => n
        None => "<anon>"
      }
      out.push((name, ctx.hir_trace.copy()))
    }
    None => ()
  }
}

///|
pub fn run_flow_taint_func_top(
  body : @syntax.Expr,
  file : String,
  source : String,
  severity : Severity,
  findings : Array[Finding],
  rules? : TaintRuleset,
  output_sinks_enabled? : Bool,
) -> Unit {
  let ctx : FlowCtx = {
    env: Map([]),
    findings,
    file,
    source,
    severity,
    record_sinks: None,
    record_returns: None,
    record_fields: None,
    sites: Map([]),
    heap: Map([]),
    alloc_result: None,
    scope_stack: [],
    scope_counter: [0],
    name_map: Map([]),
    decl_counter: [0],
    raise_buffer: [],
    struct_comps: Map([]),
    hir_trace: [],
    hir_temp_ctr: [0],
    closures: Map([]),
    record_field_sinks: None,
    defers: [],
    loop_exits: [],
    ictx: None,
    taint_rules: match rules {
      Some(r) => r
      None => TaintRuleset::empty()
    },
    output_sinks_enabled: match output_sinks_enabled {
      Some(b) => b
      None => true
    },
  }
  scope_push(ctx) // function scope
  let _ = flow(body, ctx)
  // T2.2: function exit — execute still-pending defers (uncaught-raise
  // path); defers from completed blocks already ran at their block tail
  run_defers(ctx)
  ctx.raise_buffer.clear()
  scope_pop(ctx)
}

// ── T2.5 closure conversion (thin) ─────────────────────────────────────────

///|
priv struct ClosureBinding {
  func : @syntax.Func
  capture_names : Array[String]
  frozen_taints : Map[String, Taint] // value-copy snapshot at CREATION
  frozen_sites : Map[String, String] // struct objects: shared via heap site
  mut invoked : Bool // one-shot: the first call site wins (parity with
  // the call-graph's lazy rescan semantics)
}

// collect simple identifier names from an expression tree (frequent forms;
// anything exotic is simply not captured — conservative-free because a
// missed capture only loses an in-closure read of an outer value)

///|
pub fn collect_idents(expr : @syntax.Expr, out : Array[String]) -> Unit {
  match expr {
    Ident(id~, ..) =>
      match id.name {
        Ident(name~) => if !out.contains(name) { out.push(name) }
        Dot(..) => ()
      }
    Apply(func~, args~, ..) => {
      collect_idents(func, out)
      for arg in args {
        collect_idents(arg.value, out)
      }
    }
    DotApply(self~, args~, ..) => {
      collect_idents(self, out)
      for arg in args {
        collect_idents(arg.value, out)
      }
    }
    Field(record~, ..) => collect_idents(record, out)
    Mutate(record~, field~, ..) => {
      collect_idents(record, out)
      collect_idents(field, out)
    }
    Infix(lhs~, rhs~, ..)
    | Pipe(lhs~, rhs~, ..)
    | RevPipe(lhs~, rhs~, ..)
    | Implies(lhs~, rhs~, ..) => {
      collect_idents(lhs, out)
      collect_idents(rhs, out)
    }
    Unary(expr~, ..) => collect_idents(expr, out)
    Tuple(exprs~, ..) =>
      for e in exprs {
        collect_idents(e, out)
      }
    Array(exprs~, ..) =>
      for e in exprs {
        collect_idents(e, out)
      }
    Sequence(exprs~, last_expr~, ..) => {
      for e in exprs {
        collect_idents(e, out)
      }
      collect_idents(last_expr, out)
    }
    If(cond~, ifso~, ifnot~, ..) => {
      collect_idents(cond, out)
      collect_idents(ifso, out)
      match ifnot {
        Some(e) => collect_idents(e, out)
        None => ()
      }
    }
    Match(expr~, cases~, ..) => {
      collect_idents(expr, out)
      for case in cases {
        collect_idents(case.body, out)
        match case.guard_ {
          Some(g) => collect_idents(g, out)
          None => ()
        }
      }
    }
    Let(expr~, ..) => collect_idents(expr, out)
    LetMut(expr~, ..) => collect_idents(expr, out)
    Assign(expr~, ..) => collect_idents(expr, out)
    Interp(elems~, ..) =>
      for elem in elems {
        match elem {
          Expr(expr~, ..) => collect_idents(expr, out)
          _ => ()
        }
      }
    _ => ()
  }
}

// register a let-bound closure: freeze captures, DEFER the body walk

///|
fn register_closure_binding(
  ctx : FlowCtx,
  name : String,
  func : @syntax.Func,
) -> Unit {
  let param_names : Array[String] = []
  for p in func.parameters {
    match p {
      Positional(binder~, ..)
      | Labelled(binder~, ..)
      | Optional(binder~, ..)
      | QuestionOptional(binder~, ..) => param_names.push(binder.name)
      DiscardPositional(..) => ()
    }
  }
  let idents : Array[String] = []
  collect_idents(func.body, idents)
  let caps : Array[String] = []
  let ft : Map[String, Taint] = Map([])
  let fs : Map[String, String] = Map([])
  for n in idents {
    if param_names.contains(n) || caps.contains(n) {
      continue
    }
    // only names with a LIVE outer declaration are captures
    match env_lookup(ctx, n) {
      Some(_) => {
        caps.push(n)
        ft[n] = or_clean(env_lookup(ctx, n))
        match sites_get(ctx, n) {
          Some(s) => fs[n] = s
          None => ()
        }
      }
      None => ()
    }
  }
  ctx.closures[name] = {
    func,
    capture_names: caps,
    frozen_taints: ft,
    frozen_sites: fs,
    invoked: false,
  }
}

// execute a registered closure AT ITS CALL SITE: params receive call-site
// argument taints (labelled matched by name), captures replay the frozen
// snapshot — struct captures re-bind the SAME alloc-site, so field writes
// inside the body are visible to the caller through the shared heap

///|
fn call_closure_binding(
  ctx : FlowCtx,
  name : String,
  cb : ClosureBinding,
  arg_pairs : Array[ArgTaint],
) -> Taint {
  if cb.invoked {
    return Clean // one-shot: first call site wins (lazy-rescan parity)
  }
  cb.invoked = true
  hir_emit_call(
    ctx,
    "$closure:" + name,
    hir_temps_from_pairs(ctx, arg_pairs.length()),
  )
  scope_push(ctx)
  let mut pos = 0
  for p in cb.func.parameters {
    match p {
      Positional(binder~, ..) => {
        let t : Taint = if pos < arg_pairs.length() {
          arg_pairs[pos].taint
        } else {
          Tainted
        }
        ignore(env_bind(ctx, binder.name, t))
        pos += 1
      }
      Labelled(binder~, ..) => {
        let mut t : Taint = Tainted
        for pr in arg_pairs {
          match pr.label_value {
            Some(l) => if l == binder.name { t = pr.taint }
            None => ()
          }
        }
        ignore(env_bind(ctx, binder.name, t))
      }
      Optional(binder~, ..) | QuestionOptional(binder~, ..) =>
        ignore(env_bind(ctx, binder.name, Tainted))
      DiscardPositional(..) => ()
    }
  }
  for n in cb.capture_names {
    ignore(env_bind(ctx, n, or_clean(cb.frozen_taints.get(n))))
    match cb.frozen_sites.get(n) {
      Some(s) => sites_set(ctx, n, s)
      None => ()
    }
  }
  let r = flow(cb.func.body, ctx)
  scope_pop(ctx)
  r
}

// ── bounded heap helpers ──────────────────────────────────────────────────

// site for a binding RHS: fresh literal site (consumed) or alias of a var

///|
fn resolve_binding_site(expr : @syntax.Expr, ctx : FlowCtx) -> String? {
  let fresh = ctx.alloc_result
  ctx.alloc_result = None
  match fresh {
    Some(s) => Some(s)
    None =>
      match expr {
        Ident(id~, ..) =>
          match id.name {
            Ident(name~) => sites_get(ctx, name)
            Dot(..) => None
          }
        Field(record~, ..) =>
          // o.g.h chain: inherit the base object's site (path-insensitive)
          resolve_binding_site(record, ctx)
        _ => None
      }
  }
}

// bind an alloc-site to a pattern's simple Var binders

///|
fn bind_site_to_pattern(
  pat : @syntax.Pattern,
  site : String?,
  ctx : FlowCtx,
) -> Unit {
  match (pat, site) {
    (Var(binder), Some(s)) => sites_set(ctx, binder.name, s)
    (Alias(pat~, alias_~, ..), Some(s)) => {
      bind_site_to_pattern(pat, site, ctx)
      sites_set(ctx, alias_.name, s)
    }
    _ => ()
  }
}

// field taint of a heap object; None = no fact for this site/field

///|
fn heap_read(ctx : FlowCtx, site : String, field : String) -> Taint? {
  match ctx.heap.get(site) {
    Some(fm) => fm.get(field)
    None => None
  }
}

///|
fn heap_write(ctx : FlowCtx, site : String, field : String, t : Taint) -> Unit {
  match ctx.heap.get(site) {
    Some(fm) => fm[field] = t
    None => {
      let fm : Map[String, Taint] = Map([])
      fm[field] = t
      ctx.heap[site] = fm
    }
  }
}

// ── structured walk ───────────────────────────────────────────────────────

///|
fn flow(expr : @syntax.Expr, ctx : FlowCtx) -> Taint {
  match expr {
    Constant(..) | Unit(..) | Hole(..) => Clean
    MultilineString(elems~, ..) => {
      let mut t = Clean
      for elem in elems {
        match elem {
          Interp(list) =>
            for ie in list {
              match ie {
                Expr(expr~, ..) => t = taint_or(t, flow(expr, ctx))
                _ => ()
              }
            }
          _ => ()
        }
      }
      t
    }
    Interp(elems~, ..) => {
      let mut t = Clean
      for elem in elems {
        match elem {
          Expr(expr~, ..) => t = taint_or(t, flow(expr, ctx))
          // lexer-level holes (simple identifiers) are stored as raw
          // source: any interpolation hole is dynamic content
          Source(src) => {
            let s = src.source.trim()
            if s.length() > 0 {
              let c0 = s[0]
              let ua : UInt16 = 65
              let uz : UInt16 = 90
              if c0 >= ua && c0 <= uz {
                t = taint_or(t, Clean) // constant identifier (e.g. MaxAge)
              } else {
                t = taint_or(t, Tainted)
              }
            } else {
              t = taint_or(t, Tainted)
            }
          }
          _ => ()
        }
      }
      t
    }
    BytesInterp(..) => Clean
    Ident(id~, ..) => {
      let name = longident_str(id.name)
      or_clean(env_lookup(ctx, name))
    }
    Method(..) => Clean
    Apply(func~, args~, ..) => {
      // T2.1: every argument expression flows exactly once
      let arg_pairs = flow_args_pairs(args, ctx)
      // statement layer: temps + call trace (args already flowed once)
      let hir_target = match apply_func_name(func) {
        Some(n) => n
        None => "<computed>"
      }
      let hir_temps = hir_temps_from_pairs(ctx, arg_pairs.length())
      hir_emit_call(ctx, hir_target, hir_temps)
      let arg_taint_arr : Array[Taint] = []
      for p in arg_pairs {
        arg_taint_arr.push(p.taint)
      }
      let arg_taint = pairs_aggregate(arg_pairs)
      // T2.5: calling a REGISTERED closure binding — execute its body HERE
      // (call-site argument taints seed the params; frozen captures replay;
      // shared struct captures re-bind the same alloc-site so field writes
      // inside the body are visible to the caller via the heap)
      let closure_ret : Taint? = match func {
        Ident(id~, ..) => {
          let name = longident_str(id.name)
          match ctx.closures.get(name) {
            Some(cb) => Some(call_closure_binding(ctx, name, cb, arg_pairs))
            None => None
          }
        }
        _ => None
      }
      match closure_ret {
        Some(t) => t
        None => {
          // P3: consume field-write summaries — if the callee writes a tainted
          // param into a field of another param, the receiver argument becomes
          // tainted in the caller (source-derived provenance so later field
          // reads propagate per the provenance-aware Field rule)
          apply_field_taint_side_effect(func, args, ctx, arg_taint_arr)
          // M4-lite: conditional field sinks — callee reads `param.field`
          // into a sink; confirm against this caller's heap field facts
          apply_param_field_sinks(func, args, ctx, expr)
          let ret = match apply_func_name(func) {
            Some(name) => {
              let is_sink = is_header_setter(name) ||
                ctx.taint_rules.header_sink_hit(name)
              if is_sink {
                let slot = or_slot(ctx.taint_rules.sink_value_slot(name))
                let value_taint = value_taint_at(arg_pairs, slot)
                if is_tainted(value_taint) {
                  hir_emit_sink(ctx, "header:" + name, hir_temps)
                  report_cwe113(ctx, expr, value_taint)
                }
              }
              if ctx.output_sinks_enabled &&
                ctx.taint_rules.output_sink_hit(name) {
                let slot = or_slot(ctx.taint_rules.output_sink_slot(name))
                let value_taint = value_taint_at(arg_pairs, slot)
                if is_tainted(value_taint) {
                  report_output_sink(ctx, expr, value_taint, name)
                }
              }
              if is_sanitize_call_name(name) ||
                ctx.taint_rules.sanitizer_hit(name) {
                Clean
              } else {
                match classify_source_method(name) {
                  Some(_) => Tainted
                  None =>
                    if ctx.taint_rules.source_hit(name) {
                      Tainted
                    } else {
                      // T4.1: consume ret_from when a summary binds —
                      // refinement over the args-union fallback
                      match apply_ret_from(func, args, arg_pairs, ctx) {
                        Some(t) => t
                        None => arg_taint
                      }
                    }
                }
              }
            }
            None =>
              match apply_ret_from(func, args, arg_pairs, ctx) {
                Some(t) => t
                None => arg_taint
              }
          }
          let _ = flow(func, ctx)
          // T4.2 transitivity: callee param_sinks projected onto the caller
          maybe_record_transitive_sink(func, args, arg_pairs, ctx)
          ret
        }
      }
    }
    DotApply(self~, method_name~, args~, ..) => {
      let recv_taint = flow(self, ctx)
      // T2.1: every argument expression flows exactly once
      let arg_pairs = flow_args_pairs(args, ctx)
      // statement layer: receiver temp first, then args (method-call form)
      let hir_temps = hir_temps_from_pairs(ctx, arg_pairs.length() + 1)
      hir_emit_call(ctx, method_name.name, hir_temps)
      let arg_taint = pairs_aggregate(arg_pairs)
      let combined = taint_or(recv_taint, arg_taint)
      let mname = method_name.name
      // T4.1: method-form summary consumption (receiver binds param 0)
      apply_field_taint_side_effect_dot(
        mname, self, args, ctx, arg_pairs, recv_taint,
      )
      apply_param_field_sinks_dot(mname, self, args, ctx, expr)
      let is_sink = is_header_setter(mname) ||
        ctx.taint_rules.header_sink_hit(mname)
      let ret = if is_sink {
        // only the header VALUE (positional 1 / labelled `value`, or the
        // DSL value_slot) matters; the header NAME slot and the response
        // receiver are expected to carry request-derived state
        let slot = or_slot(ctx.taint_rules.sink_value_slot(mname))
        let value_taint = value_taint_at(arg_pairs, slot)
        if is_tainted(value_taint) {
          hir_emit_sink(ctx, "header:" + mname, hir_temps)
          report_cwe113(ctx, expr, value_taint)
        }
        Clean
      } else if ctx.output_sinks_enabled &&
        ctx.taint_rules.output_sink_hit(mname) {
        // output channel sink (lib model / DSL kind "Output") -> CWE-116
        let slot = or_slot(ctx.taint_rules.output_sink_slot(mname))
        let value_taint = value_taint_at(arg_pairs, slot)
        if is_tainted(value_taint) {
          report_output_sink(ctx, expr, value_taint, mname)
        }
        Clean
      } else if is_sanitize_call_name(mname) ||
        ctx.taint_rules.sanitizer_hit(mname) ||
        is_crlf_strip_chain(mname, args, self) {
        Clean
      } else {
        match classify_source_method(mname) {
          Some(_) => Tainted
          None =>
            if ctx.taint_rules.source_hit(mname) {
              Tainted
            } else {
              // T4.1: method form consumes ret_from with the receiver
              // bound to param 0 (self), positional args shifted by one
              match
                apply_ret_from_dot(mname, args, arg_pairs, ctx, recv_taint) {
                Some(t) => t
                None => combined
              }
            }
        }
      }
      ret
    }
    Infix(op~, lhs~, rhs~, ..) => {
      // T2.2 short-circuit: && / || evaluate rhs ONLY on the deciding path.
      // Statically-decided lhs skips rhs entirely (its sinks never run);
      // otherwise rhs runs on a branch copy and states merge.
      let lt = flow(lhs, ctx)
      let opname = infix_op_name(op)
      if opname == "&&" || opname == "and" {
        if is_false_const(lhs) {
          Clean // rhs never executes
        } else if is_true_const(lhs) {
          flow(rhs, ctx)
        } else {
          let branch = ctx.copy()
          let rt = flow(rhs, branch)
          merge_env(ctx, branch, ctx)
          taint_or(lt, rt)
        }
      } else if opname == "||" || opname == "or" {
        if is_true_const(lhs) {
          Clean // rhs never executes
        } else if is_false_const(lhs) {
          flow(rhs, ctx)
        } else {
          let branch = ctx.copy()
          let rt = flow(rhs, branch)
          merge_env(ctx, branch, ctx)
          taint_or(lt, rt)
        }
      } else {
        taint_or(lt, flow(rhs, ctx))
      }
    }
    Unary(expr~, ..) => flow(expr, ctx)
    Array(exprs~, ..) => fold_taint(exprs, ctx)
    ArraySpread(elems~, ..) => {
      let mut t = Clean
      for elem in elems {
        match elem {
          Regular(e) => t = taint_or(t, flow(e, ctx))
          Spread(expr~, ..) => t = taint_or(t, flow(expr, ctx))
        }
      }
      t
    }
    ArrayGet(array~, index~, ..) => {
      let t = flow(array, ctx)
      let _ = flow(index, ctx)
      t
    }
    ArrayGetSlice(array~, start_index~, end_index~, ..) => {
      let t = flow(array, ctx)
      let _ = start_index.map(fn(e) { flow(e, ctx) })
      let _ = end_index.map(fn(e) { flow(e, ctx) })
      t
    }
    ArraySet(array~, index~, value~, ..) => {
      let _ = flow(array, ctx)
      let _ = flow(index, ctx)
      flow(value, ctx)
    }
    ArrayAugmentedSet(array~, index~, value~, ..) => {
      let _ = flow(array, ctx)
      let _ = flow(index, ctx)
      flow(value, ctx)
    }
    ListComprehension(guard_~, body~, ..) => {
      let mut t = Clean
      let _ = guard_.map(fn(e) { t = taint_or(t, flow(e, ctx)) })
      taint_or(t, flow(body, ctx))
    }
    Constraint(expr~, ..) => flow(expr, ctx)
    Constr(..) => Clean
    LabelledBlock(body~, ..) => {
      // R4: block expressions introduce a scope — `let` inside the block
      // must not shadow outer bindings beyond the block (review c11)
      scope_push(ctx)
      let t = flow(body, ctx)
      scope_pop(ctx)
      t
    }
    While(loop_cond~, loop_body~, ..) => {
      let _ = flow(loop_cond, ctx)
      // fixpoint: taint written in iteration N must be visible to the
      // sink executed in iteration N+1 (review counterexample b)
      scope_push(ctx)
      let base = ctx.loop_exits.length()
      flow_to_fixpoint(loop_body, ctx, base)
      let join = join_loop_exits(ctx, base)
      scope_pop(ctx)
      join
    }
    Function(func~, ..) => {
      // closure params: conservatively tainted (framework-supplied input);
      // body runs in its OWN scope — captures resolve via the stack
      scope_push(ctx)
      for param in func.parameters {
        match param {
          Positional(binder~, ..)
          | Labelled(binder~, ..)
          | Optional(binder~, ..)
          | QuestionOptional(binder~, ..) =>
            ignore(env_bind(ctx, binder.name, Tainted))
          DiscardPositional(..) => ()
        }
      }
      let _ = flow(func.body, ctx)
      scope_pop(ctx)
      Clean
    }
    If(cond~, ifso~, ifnot~, ..) => {
      let _ = flow(cond, ctx)
      let refined = validated_var(cond)
      let then_ctx = ctx.copy()
      match refined {
        Some(name) => env_assign(then_ctx, name, Clean)
        None => ()
      }
      scope_push(then_ctx)
      let then_t = flow(ifso, then_ctx)
      scope_pop(then_ctx)
      let else_ctx = ctx.copy()
      let else_t = match ifnot {
        Some(e) => {
          scope_push(else_ctx)
          let et = flow(e, else_ctx)
          scope_pop(else_ctx)
          et
        }
        None => Clean
      }
      merge_env(ctx, then_ctx, else_ctx)
      taint_or(then_t, else_t)
    }
    Guard(cond~, body~, ..) => {
      // guard COND else OTHERWISE; BODY runs when cond holds
      let _ = flow(cond, ctx)
      let refined = validated_var(cond)
      match refined {
        Some(name) => env_assign(ctx, name, Clean)
        None => ()
      }
      scope_push(ctx)
      let gt = flow(body, ctx)
      scope_pop(ctx)
      gt
    }
    Is(expr~, ..) => {
      let _ = flow(expr, ctx)
      Clean
    }
    RegexMatch(expr~, bindings~, ..) => {
      let _ = flow(expr, ctx)
      // captures derived from the matched input
      match flow(expr, ctx) {
        t => {
          for binding in bindings {
            match binding.1 {
              Some(binder) => ignore(env_bind(ctx, binder.name, t))
              None => ignore(env_bind(ctx, binding.0.name, t))
            }
          }
          Clean
        }
      }
    }
    Defer(expr~, body~, ..) => {
      // T2.2 exit-path semantics: register into the scope exit sequence;
      // the enclosing block's tail executes them LIFO (inner defers first).
      // Return drains for the direct-exit path; uncaught raises drain at
      // the function tail; caught raises continue with defers intact.
      ctx.defers.push(expr)
      let t = flow(body, ctx)
      run_defers(ctx)
      t
    }
    LetFn(name~, func~, body~, ..) => {
      // R4: the binding group is scoped to its body (block semantics)
      // T2.5: register + defer — the local fn body flows at its call site
      scope_push(ctx)
      register_closure_binding(ctx, name.name, func)
      ignore(env_bind(ctx, name.name, Clean))
      let t = flow(body, ctx)
      scope_pop(ctx)
      t
    }
    LetAnd(bindings~, body~, ..) => {
      // R4: the binding group is scoped to its body (block semantics)
      scope_push(ctx)
      for binding in bindings {
        let (binder, _, func) = binding
        register_closure_binding(ctx, binder.name, func)
        ignore(env_bind(ctx, binder.name, Clean))
      }
      let bt = flow(body, ctx)
      scope_pop(ctx)
      bt
    }
    Let(pattern~, expr~, body~, ..) => {
      // value-structure contract (third review) + R3/R4/R5 (fifth review):
      //   - RHS components are evaluated COMPLETELY before any binding
      //     (single evaluation; `let (x, v) = ("safe", x)` reads the OUTER x)
      //   - a Var bound to a tuple literal records components under the
      //     declaration's OWN id — rebinding the same name allocates a new
      //     declaration, so stale components become unreachable (R5)
      scope_push(ctx) // R4: the binding is scoped to the let body
      match (pattern, expr) {
        (Var(binder), Function(func~, ..)) => {
          // T2.5 create != execute: register the closure (captures frozen
          // at creation) — the body flows only at a call site; a closure
          // that is never called has zero analysis side effects
          register_closure_binding(ctx, binder.name, func)
          ignore(env_bind(ctx, binder.name, Clean))
        }
        (Var(binder), Tuple(exprs~, ..)) => {
          // T2.1+T2.3: lower through the statement layer — each component
          // evaluated ONCE into a temp, then positions bound to the decl
          let comps : Array[Taint] = []
          let temps : Array[Int] = []
          let mut arg_idx = 0
          for e in exprs {
            let tid = hir_fresh_temp(ctx)
            ctx.hir_trace.push(LetEvalTemp(tid, arg_idx))
            let t = flow(e, ctx)
            comps.push(t)
            temps.push(tid)
            arg_idx += 1
          }
          let mut fold = Clean
          for c in comps {
            fold = taint_or(fold, c)
          }
          let dkey = env_bind(ctx, binder.name, fold)
          ctx.hir_trace.push(BindTuplePositions(dkey, temps.copy()))
          comps_set(ctx, dkey, "#tuple", comps)
        }
        (Var(binder), Apply(func=Constr(constr~, ..), args~, ..)) => {
          // T2.3: enum payload positions — `let v = Some(dirty)` parses as
          // Apply(Constr(Some), [dirty]); record (decl, "Some", 0) so
          // later Constr patterns project the exact payload position
          let payload : Array[Taint] = []
          let temps : Array[Int] = []
          let mut i = 0
          for arg in args {
            let tid = hir_fresh_temp(ctx)
            ctx.hir_trace.push(LetEvalTemp(tid, i))
            payload.push(flow(arg.value, ctx))
            temps.push(tid)
            i += 1
          }
          let mut fold = Clean
          for p in payload {
            fold = taint_or(fold, p)
          }
          let dkey = env_bind(ctx, binder.name, fold)
          ctx.hir_trace.push(BindCtorPositions(dkey, constr.name.name, temps))
          if payload.length() > 0 {
            comps_set(ctx, dkey, constr.name.name, payload)
          }
        }
        _ => bind_let_taint(pattern, expr, ctx)
      }
      bind_site_to_pattern(pattern, resolve_binding_site(expr, ctx), ctx)
      let t = flow(body, ctx)
      scope_pop(ctx)
      t
    }
    LetMut(binder~, expr~, body~, ..) => {
      // R4: binding scoped to the let body (same block semantics as Let)
      scope_push(ctx)
      let t = flow(expr, ctx)
      ignore(env_bind(ctx, binder.name, t))
      match resolve_binding_site(expr, ctx) {
        Some(s) => sites_set(ctx, binder.name, s)
        None => ()
      }
      let bt = flow(body, ctx)
      scope_pop(ctx)
      bt
    }
    Sequence(exprs~, last_expr~, ..) => {
      // R4: a statement block introduces a scope — `let` bindings inside
      // `{ let x = "safe"; x }` do not leak outward (review c11). Function
      // bodies, if/match branches and loop bodies arrive as Sequences too;
      // an inner scope per block is exactly MoonBit's let-scoping rule.
      scope_push(ctx)
      for e in exprs {
        let _ = flow(e, ctx)
      }
      let t = flow(last_expr, ctx)
      scope_pop(ctx)
      t
    }
    Tuple(exprs~, ..) => fold_taint(exprs, ctx)
    Record(fields~, ..) => {
      // allocation site: record per-field taint at construction
      let site = ctx.file + ":" + expr.loc().start.lnum.to_string()
      let fm : Map[String, Taint] = Map([])
      let mut t = Clean
      for field in fields {
        let ft = flow(field.expr, ctx)
        fm[field.label.name] = ft
        t = taint_or(t, ft)
      }
      ctx.heap[site] = fm
      ctx.alloc_result = Some(site)
      t
    }
    RecordUpdate(record~, fields~, ..) => {
      let mut t = flow(record, ctx)
      for field in fields {
        t = taint_or(t, flow(field.expr, ctx))
      }
      t
    }
    Field(record~, accessor~, ..) =>
      // precedence 1: heap read — receiver var with a known alloc-site
      //   (field facts from construction and Mutate writes)
      // precedence 2: provenance-aware fallback (review counterexample a):
      //   receiver tainted FROM A SOURCE  -> field carries the taint
      //   receiver tainted AS A DIRECT PARAM (config-like) -> field read
      //     is CONDITIONAL: no local finding (legacy parity, test c), but
      //     recorded as (param, field) for call-site re-check
      match accessor {
        Label(l) => {
          let heap_hit : Taint? = match flow_var_name(record) {
            Some(v) =>
              match heap_site_of(ctx, v) {
                Some(s) => heap_read(ctx, s, l.name)
                None => None
              }
            None => None
          }
          // merge: heap fact AND provenance fallback both apply —
          // e.g. a clean-at-construction field later tainted via a
          // field-write summary keeps its taint (P3 test parity)
          let fallback : Taint = {
            let t = flow(record, ctx)
            match t {
              Tainted => Tainted
              TaintedParam(p) => TaintedFieldRef(p, l.name)
              Clean => Clean
              TaintedFieldRef(_, _) => t
            }
          }
          match heap_hit {
            Some(ft) => taint_or(ft, fallback)
            None => fallback
          }
        }
        Index(tuple_index~, ..) =>
          // bounded value structure: `pair.1` projects the recorded
          // component when the base var holds a tuple LITERAL
          match flow_var_name(record) {
            Some(v) =>
              match tuple_comp_lookup(ctx, v, tuple_index) {
                Some(ct) => ct
                None => flow(record, ctx)
              }
            None => flow(record, ctx)
          }
        _ => flow(record, ctx)
      }
    As(expr~, ..) => flow(expr, ctx)
    Mutate(record~, accessor~, field~, ..) => {
      // P3: field-write summary event — `r.f = value` where value carries
      // param provenance p records "r|f|p" (approximation: base var only,
      // no alias tracking — documented in CONTEXT)
      let base = flow_var_name(record)
      let ft = flow(field, ctx)
      // bounded heap: record the field fact on the receiver's alloc-site
      match base {
        Some(v) =>
          match heap_site_of(ctx, v) {
            Some(s) =>
              match accessor {
                Label(l) => heap_write(ctx, s, l.name, ft)
                _ => ()
              }
            None => ()
          }
        None => ()
      }
      match (base, ft) {
        (Some(r), TaintedParam(p)) =>
          match ctx.record_fields {
            Some(arr) => {
              let entry = r + "|" + accessor_label(accessor) + "|" + p
              if !arr.contains(entry) {
                arr.push(entry)
              }
            }
            None => ()
          }
        _ => ()
      }
      let _ = flow(record, ctx)
      ft
    }
    Match(expr~, cases~, ..) => {
      let scrut = flow(expr, ctx)
      let branch_envs : Array[FlowCtx] = []
      let mut result = Clean
      for case in cases {
        let case_ctx = ctx.copy()
        // R4: branch scope FIRST, then pattern + guard binding —
        // `match "safe" { x => ... }` must not shadow the outer x
        // beyond the branch (review c10)
        scope_push(case_ctx)
        // T2.3: exact payload projection — a Constr pattern over a Var
        // scrutinee with recorded positions binds each sub-pattern to
        // its (decl, ctor, idx) component instead of the whole taint
        if !project_ctor_positions(expr, case.pattern, case_ctx, scrut) {
          bind_pattern_taint(case.pattern, scrut, case_ctx)
        }
        // constant patterns refine: `x is Some(...)`, literals
        let _ = case.guard_.map(fn(e) { flow(e, case_ctx) })
        result = taint_or(result, flow(case.body, case_ctx))
        scope_pop(case_ctx)
        branch_envs.push(case_ctx)
      }
      merge_envs(ctx, branch_envs)
      result
    }
    LexMatch(expr~, cases~, ..) => {
      let t = flow(expr, ctx)
      for case in cases {
        let _ = flow(case.body, ctx)
      }
      t
    }
    LexScan(expr~, cases~, ..) => {
      let t = flow(expr, ctx)
      for case in cases {
        let _ = flow(case.body, ctx)
      }
      t
    }
    Pipe(lhs~, rhs~, ..) => taint_or(flow(lhs, ctx), flow(rhs, ctx))
    RevPipe(lhs~, rhs~, ..) => taint_or(flow(lhs, ctx), flow(rhs, ctx))
    Assign(var_~, expr~, ..) => {
      let t = flow(expr, ctx)
      let name = longident_str(var_.name)
      env_assign(ctx, name, t)
      match resolve_binding_site(expr, ctx) {
        Some(s) => sites_set(ctx, name, s)
        None => () // stale site kept: bounded approximation (documented)
      }
      Clean
    }
    Return(return_value~, ..) => {
      // T2.2: a return exits every enclosing block — drain pending defers
      // after the return value is evaluated (value sees pre-defer state)
      match return_value {
        Some(e) => {
          let t = flow(e, ctx)
          run_defers(ctx)
          // P3: record param provenance flowing into the return value
          match t {
            TaintedParam(p) =>
              match ctx.record_returns {
                Some(arr) => if !arr.contains(p) { arr.push(p) }
                None => ()
              }
            _ => ()
          }
        }
        None => ()
      }
      Clean
    }
    Raise(err_value~, ..) => {
      // T2.3 direct error payload: the raised VALUE carries its own taint;
      // the enclosing Try consumes it (no environment guessing needed for
      // the primary path — env union remains only as the conservative
      // supplement)
      let t = flow(err_value, ctx)
      ctx.raise_buffer.push(t)
      Clean
    }
    Quantifier(body~, ..) => flow(body, ctx)
    Implies(lhs~, rhs~, ..) => {
      let _ = flow(lhs, ctx)
      flow(rhs, ctx)
    }
    ProofAssert(..) => Clean
    ProofLet(expr~, ..) => flow(expr, ctx)
    Break(arg~, ..) => {
      // T2.2: break(value) carries its taint to the loop merge point
      let t = match arg {
        Some(e) => flow(e, ctx)
        None => Clean
      }
      ctx.loop_exits.push(t)
      Clean
    }
    Continue(args~, ..) => {
      // T2.2: continue(args) carries joined arg taint to the next iteration
      let mut t = Clean
      for a in args {
        t = taint_or(t, flow(a, ctx))
      }
      ctx.loop_exits.push(t)
      Clean
    }
    For(binders~, continue_block~, body~, ..) => {
      for pair in binders {
        let _ = flow(pair.1, ctx)
      }
      for pair in continue_block {
        let _ = flow(pair.1, ctx)
      }
      let base = ctx.loop_exits.length()
      flow_to_fixpoint(body, ctx, base)
      join_loop_exits(ctx, base)
    }
    ForEach(binders~, expr~, init~, continue_block~, body~, ..) => {
      // T2.2: break/continue carried taints join at the loop merge point
      let t = flow(expr, ctx)
      for b in binders {
        match b {
          Some(binder) => ignore(env_bind(ctx, binder.name, t))
          None => ()
        }
      }
      for pair in init {
        let _ = flow(pair.1, ctx)
      }
      for pair in continue_block {
        let _ = flow(pair.1, ctx)
      }
      let base = ctx.loop_exits.length()
      flow_to_fixpoint(body, ctx, base)
      join_loop_exits(ctx, base)
    }
    Try(body~, catch_~, try_else~, ..) => {
      // Error-flow contract: body, catches, and the noraise arm are separate
      // exit states that MERGE (third review). Catches observe the pre-raise
      // state (approximated by the post-body env); the error payload may
      // carry body-derived data (conservative: body result ∪ any body taint).
      let body_ctx = ctx.copy()
      // R6 error-exit isolation: this Try gets a FRESH raise scope for its
      // own body; raises already recorded by the ENCLOSING try (earlier
      // statements/branches of its body) are snapshotted and restored — a
      // nested try can never wipe facts that belong to its parent.
      let outer_raises : Array[Taint] = []
      for pt in ctx.raise_buffer {
        outer_raises.push(pt)
      }
      ctx.raise_buffer.clear()
      scope_push(body_ctx)
      let body_t = flow(body, body_ctx)
      scope_pop(body_ctx)
      // direct raise payloads (primary) ∪ body value ∪ env taint (conservative)
      let own_raises : Array[Taint] = []
      for pt in ctx.raise_buffer {
        own_raises.push(pt)
      }
      let mut err_t = taint_or(body_t, env_any_taint(body_ctx))
      for pt in own_raises {
        err_t = taint_or(err_t, pt)
      }
      ctx.raise_buffer.clear()
      // restore the enclosing facts, then propagate our own raises ONLY if
      // this Try does not fully catch everything (an irrefutable catch
      // pattern consumes all raise types; constructor-only catches leave
      // unmatched types free to escape — keeping the taint is sound)
      for pt in outer_raises {
        ctx.raise_buffer.push(pt)
      }
      if !try_fully_catches(catch_) {
        for pt in own_raises {
          ctx.raise_buffer.push(pt)
        }
      }
      let branch_envs : Array[FlowCtx] = [body_ctx]
      let mut result = body_t
      for case in catch_ {
        let case_ctx = ctx.copy()
        merge_env(case_ctx, body_ctx, case_ctx) // entry ∪ post-body state
        // R4: branch scope before pattern binding (same as Match)
        scope_push(case_ctx)
        bind_pattern_taint(case.pattern, err_t, case_ctx)
        let t = flow(case.body, case_ctx)
        scope_pop(case_ctx)
        result = taint_or(result, t)
        branch_envs.push(case_ctx)
      }
      match try_else {
        Some(arms) =>
          for case in arms {
            // noraise arm binds the SUCCESS value and runs on the happy path
            let arm_ctx = ctx.copy()
            merge_env(arm_ctx, body_ctx, arm_ctx)
            // R4: branch scope before pattern binding (same as Match)
            scope_push(arm_ctx)
            bind_pattern_taint(case.pattern, body_t, arm_ctx)
            let t = flow(case.body, arm_ctx)
            scope_pop(arm_ctx)
            result = taint_or(result, t)
            branch_envs.push(arm_ctx)
          }
        None => ()
      }
      merge_envs(ctx, branch_envs)
      result
    }
    TryOperator(body~, ..) => flow(body, ctx)
    Map(elems~, ..) => {
      let mut t = Clean
      for elem in elems {
        t = taint_or(t, flow(elem.expr, ctx))
      }
      t
    }
    Group(expr~, ..) => flow(expr, ctx)
    TemplateWriting(expr~, template~, ..) => {
      let _ = flow(expr, ctx)
      flow(template, ctx)
    }
    StaticAssert(..) => Clean
  }
}

///|
fn dummy_flow_loc() -> @basic.Location {
  {
    start: { fname: "", lnum: 0, bol: 0, cnum: 0, },
    end: { fname: "", lnum: 0, bol: 0, cnum: 0, },
  }
}

///|
fn or_clean(t : Taint?) -> Taint {
  match t {
    Some(v) => v
    None => Clean
  }
}

// per-argument taints in argument order (single flow pass, no re-visits)

///|
fn fold_taint(exprs : @list.List[@syntax.Expr], ctx : FlowCtx) -> Taint {
  let mut t = Clean
  for e in exprs {
    t = taint_or(t, flow(e, ctx))
  }
  t
}

///|
// R6: does this catch list consume ALL raise types? An irrefutable
// pattern (binder/underscore/Any) catches everything; constructor-only
// patterns (Constr/SpecialConstr) leave unmatched types free to escape.
fn try_fully_catches(catches : @list.List[@syntax.Case]) -> Bool {
  if catches.length() == 0 {
    return false
  }
  let mut irrefutable = false
  for case in catches {
    match case.pattern {
      Var(_) => irrefutable = true // binder/underscore: binds the whole error
      Any(..) => irrefutable = true
      _ => ()
    }
  }
  irrefutable
}

///|
fn bind_pattern_taint(pat : @syntax.Pattern, t : Taint, ctx : FlowCtx) -> Unit {
  match pat {
    Any(..) => ()
    Var(binder) => ignore(env_bind(ctx, binder.name, t))
    Alias(pat~, alias_~, ..) => {
      bind_pattern_taint(pat, t, ctx)
      ignore(env_bind(ctx, alias_.name, t))
    }
    Constraint(pat~, ..) => bind_pattern_taint(pat, t, ctx)
    Tuple(pats~, ..) =>
      for p in pats {
        bind_pattern_taint(p, t, ctx)
      }
    Constr(args~, ..) =>
      match args {
        Some(list) =>
          for arg in list {
            bind_pattern_taint(arg.pat, t, ctx)
          }
        None => ()
      }
    SpecialConstr(binder~, args~, ..) => {
      ignore(env_bind(ctx, binder.name, t))
      for arg in args {
        bind_pattern_taint(arg.pat, t, ctx)
      }
    }
    Record(fields~, ..) =>
      for fp in fields {
        bind_pattern_taint(fp.pattern, t, ctx)
      }
    Or(pat1~, pat2~, ..) => {
      bind_pattern_taint(pat1, t, ctx)
      bind_pattern_taint(pat2, t, ctx)
    }
    With(pat~, ..) => bind_pattern_taint(pat, t, ctx)
    Array(pats~, ..) =>
      match pats {
        Closed(list) =>
          for ap in list {
            match ap {
              Pattern(p) => bind_pattern_taint(p, t, ctx)
              _ => ()
            }
          }
        Open(before, after, _) => {
          for ap in before {
            match ap {
              Pattern(p) => bind_pattern_taint(p, t, ctx)
              _ => ()
            }
          }
          for ap in after {
            match ap {
              Pattern(p) => bind_pattern_taint(p, t, ctx)
              _ => ()
            }
          }
        }
      }
    Constant(..) | Map(..) | Range(..) => ()
  }
}

// union-merge branch states back into ctx

///|
// Positional tuple binding: (tainted, "safe") binds per component so the
// clean component stays clean; mismatched shapes fall back to whole-taint

///|
fn bind_let_taint(
  pattern : @syntax.Pattern,
  expr : @syntax.Expr,
  ctx : FlowCtx,
) -> Unit {
  match (pattern, expr) {
    (Tuple(pats~, ..), Tuple(exprs~, ..)) => {
      let parr = pats.to_array()
      let earr = exprs.to_array()
      if parr.length() == earr.length() {
        // R4: evaluate the WHOLE right-hand side BEFORE binding any pattern
        // variable — `let (x, value) = ("safe", x)` must read the outer x
        // in the second component, not the freshly shadowed one
        let ts : Array[Taint] = []
        for e in earr {
          ts.push(flow(e, ctx))
        }
        let mut i = 0
        while i < parr.length() {
          bind_pattern_taint(parr[i], ts[i], ctx)
          i += 1
        }
      } else {
        let t = flow(expr, ctx)
        bind_pattern_taint(pattern, t, ctx)
      }
    }
    _ => {
      let t = flow(expr, ctx)
      bind_pattern_taint(pattern, t, ctx)
    }
  }
}

// conservative aggregate: Tainted if any tracked var is tainted in the state
// (used for error payloads that may carry body-derived data)

///|
fn env_any_taint(ctx : FlowCtx) -> Taint {
  let mut any = Clean
  ctx.env.each(fn(_k, v) { if v != Clean { any = Tainted } })
  any
}

///|
// G4: weak heap join at control-flow merge points — per field key the
// joined fact is taint_or over all branch heaps (lattice join: facts
// from a branch that overwrote a field never erase another branch's)

///|
fn merge_heap_into(dst : FlowCtx, srcs : Array[FlowCtx]) -> Unit {
  for src in srcs {
    src.heap.each(fn(site, fm) {
      match dst.heap.get(site) {
        Some(dfm) =>
          fm.each(fn(f, ft) { dfm[f] = taint_or(or_clean(dfm.get(f)), ft) })
        None => {
          let fcopy : Map[String, Taint] = Map([])
          fm.each(fn(f, ft) { fcopy[f] = ft })
          dst.heap[site] = fcopy
        }
      }
    })
  }
}

///|
fn merge_env(ctx : FlowCtx, a : FlowCtx, b : FlowCtx) -> Unit {
  let keys : Array[String] = []
  a.env.each(fn(k, _) { keys.push(k) })
  b.env.each(fn(k, _) { keys.push(k) })
  for k in keys {
    ctx.env[k] = taint_or(or_clean(a.env.get(k)), or_clean(b.env.get(k)))
  }
  // G4: heap facts join weakly at this merge point
  merge_heap_into(ctx, [a, b])
  // R3: name resolution joins too — declarations only visible on one side
  // are simply carried over (their env slot was joined above)
  let nkeys : Array[String] = []
  a.name_map.each(fn(k, _) { nkeys.push(k) })
  b.name_map.each(fn(k, _) { nkeys.push(k) })
  for k in nkeys {
    match a.name_map.get(k) {
      Some(v) => ctx.name_map[k] = v
      None =>
        match b.name_map.get(k) {
          Some(v) => ctx.name_map[k] = v
          None => ()
        }
    }
  }
}

///|
fn merge_envs(ctx : FlowCtx, branches : Array[FlowCtx]) -> Unit {
  if branches.length() == 0 {
    return
  }
  // G4: heap facts join weakly at this merge point
  merge_heap_into(ctx, branches)
  let keys : Array[String] = []
  for br in branches {
    br.env.each(fn(k, _) { keys.push(k) })
  }
  for k in keys {
    let mut t = Clean
    for br in branches {
      t = taint_or(t, or_clean(br.env.get(k)))
    }
    ctx.env[k] = t
  }
}

// taint of the header VALUE argument only (parity with the legacy rule)

///|
// T2.1 single-evaluation contract: argument expressions flow EXACTLY ONCE.
// Pairs capture (kind, taint); slot selection is a pure function over them.

///|
priv struct ArgTaint {
  is_positional : Bool
  label_value : String? // labelled "value"-style slot name, if labelled
  taint : Taint
}

// flow each argument exactly once, preserving kind info for slot selection

///|
fn flow_args_pairs(
  args : @list.List[@syntax.Argument],
  ctx : FlowCtx,
) -> Array[ArgTaint] {
  let pairs : Array[ArgTaint] = []
  for arg in args {
    let t = flow(arg.value, ctx)
    match arg.kind {
      Labelled(label) =>
        pairs.push({
          is_positional: false,
          label_value: Some(label.name),
          taint: t,
        })
      LabelledPun(label) =>
        pairs.push({
          is_positional: false,
          label_value: Some(label.name),
          taint: t,
        })
      LabelledOption(label~, ..) =>
        pairs.push({
          is_positional: false,
          label_value: Some(label.name),
          taint: t,
        })
      LabelledOptionPun(label~, ..) =>
        pairs.push({
          is_positional: false,
          label_value: Some(label.name),
          taint: t,
        })
      _ => pairs.push({ is_positional: true, label_value: None, taint: t, })
    }
  }
  pairs
}

// pure selection: labelled `value` slot, else positional value_slot index

///|
fn value_taint_at(pairs : Array[ArgTaint], value_slot : Int) -> Taint {
  let mut pos_idx = 0
  let mut result = Clean
  for p in pairs {
    if p.is_positional {
      if pos_idx == value_slot {
        result = taint_or(result, p.taint)
      }
      pos_idx += 1
    } else {
      match p.label_value {
        Some(l) => if l == "value" { result = taint_or(result, p.taint) }
        None => ()
      }
    }
  }
  result
}

// aggregate taint over already-flowed pairs (no re-evaluation)

///|
fn pairs_aggregate(pairs : Array[ArgTaint]) -> Taint {
  let mut t = Clean
  for p in pairs {
    t = taint_or(t, p.taint)
  }
  t
}

// `x.replace_all(old="\r", new="")` strips CRLF: a sanitizer

///|
fn is_crlf_strip_chain(
  mname : String,
  args : @list.List[@syntax.Argument],
  recv : @syntax.Expr,
) -> Bool {
  let (cr, lf, crlf) = crlf_strip_coverage(mname, args, recv)
  crlf || (cr && lf)
}

// coverage triples of a strip chain: (removed

///|
fn crlf_strip_coverage(
  mname : String,
  args : @list.List[@syntax.Argument],
  recv : @syntax.Expr,
) -> (Bool, Bool, Bool) {
  if mname != "replace_all" {
    return (false, false, false)
  }
  let mut has_cr = false
  let mut has_lf = false
  let mut has_crlf = false
  // STRICT argument roles: only the OLD slot (labelled `old` or positional
  // 0) removes content; CRLF in the NEW slot INTRODUCES the danger and
  // poisons the chain (never a sanitizer).
  let mut pos = 0
  let mut poisoned = false
  for arg in args {
    let is_old_slot = match arg.kind {
      Labelled(label) => label.name == "old"
      _ => pos == 0 // positional: first arg is the searched pattern
    }
    let is_new_slot = match arg.kind {
      Labelled(label) => label.name == "new"
      _ => pos == 1
    }
    match arg.value {
      Constant(c=String(s), ..) => {
        let cr = s == "\\r" || s == "\r"
        let lf = s == "\\n" || s == "\n"
        let crlf = s == "\\r\\n" || s == "\r\n"
        if is_new_slot && (cr || lf || crlf) {
          poisoned = true
        }
        if is_old_slot {
          if crlf {
            has_crlf = true
          }
          if cr {
            has_cr = true
          }
          if lf {
            has_lf = true
          }
        }
      }
      _ => ()
    }
    pos += 1
  }
  if poisoned {
    return (false, false, false)
  }
  match recv {
    DotApply(self~, method_name~, args~, ..) => {
      let (r_cr, r_lf, r_crlf) = crlf_strip_coverage(
        method_name.name,
        args,
        self,
      )
      (has_cr || r_cr, has_lf || r_lf, has_crlf || r_crlf)
    }
    _ => (has_cr, has_lf, has_crlf)
  }
}

// ── guard/validation refinement ───────────────────────────────────────────

///|
fn infix_op_name(v : @syntax.Var) -> String {
  match v.name {
    Ident(name~) => name
    Dot(..) => ""
  }
}

///|
fn is_true_const(e : @syntax.Expr) -> Bool {
  match e {
    Constant(c=Bool(true), ..) => true
    _ => false
  }
}

///|
// T2.2: join break/continue carried taints pushed after `base`, truncate

///|
fn join_loop_exits(ctx : FlowCtx, base : Int) -> Taint {
  let mut t = Clean
  while ctx.loop_exits.length() > base {
    t = taint_or(t, ctx.loop_exits.pop() |> or_clean2)
  }
  t
}

///|
fn or_clean2(v : Taint?) -> Taint {
  match v {
    Some(x) => x
    None => Clean
  }
}

///|
fn is_false_const(e : @syntax.Expr) -> Bool {
  match e {
    Constant(c=Bool(false), ..) => true
    _ => false
  }
}

// If cond validates a variable (e.g. `x.contains("\r") == false`,
// `!x.has_crlf()`, `x =~ re"[a-z]+"`), the taken branch may treat it clean.

///|
fn validated_var(cond : @syntax.Expr) -> String? {
  // STRICT polarity: the taken branch is clean ONLY when the condition
  // asserts safety:
  //   - whitelist validator holds:      x.is_ascii(), x =~ re"[...]"
  //   - dangerous content ABSENT:       !x.contains(CRLF), x.contains(CRLF) == false
  // `x.contains(CRLF)` (positive) = danger IS present: not clean.
  // `!x.is_ascii()` (negated whitelist): not clean.
  match cond {
    Unary(op~, expr~, ..) =>
      if is_not_op(op) {
        dangerous_contains_var(expr)
      } else {
        None
      }
    Infix(op~, lhs~, rhs~, ..) =>
      if is_eq_op(op) {
        if is_false_const(lhs) {
          dangerous_contains_var(rhs)
        } else if is_false_const(rhs) {
          dangerous_contains_var(lhs)
        } else {
          None
        }
      } else {
        None
      }
    RegexMatch(expr~, ..) => flow_var_name(expr)
    DotApply(self~, method_name~, ..) =>
      if is_whitelist_validator(method_name.name) {
        flow_var_name(self)
      } else {
        None
      }
    _ => None
  }
}

// `x.contains(CRLF literal)`: var whose DANGEROUS content is tested
// (clean only under negation)

///|
fn dangerous_contains_var(expr : @syntax.Expr) -> String? {
  match expr {
    DotApply(self~, method_name~, ..) => {
      let m = method_name.name
      if (m == "contains" || m == "has_prefix" || m == "has_suffix") &&
        args_have_crlf_literal(expr) {
        flow_var_name(self)
      } else {
        None
      }
    }
    _ => None
  }
}

///|
fn args_have_crlf_literal(e : @syntax.Expr) -> Bool {
  match e {
    DotApply(args~, ..) => {
      let mut found = false
      for arg in args {
        match arg.value {
          // NOTE: parser Constant strings hold RAW source text, so CRLF
          // appears as the 2-char escape sequences, not control bytes
          Constant(c=String(s), ..) =>
            if s.contains("\\r") ||
              s.contains("\\n") ||
              s.contains("\r") ||
              s.contains("\n") {
              found = true
            }
          _ => ()
        }
      }
      found
    }
    _ => false
  }
}

///|
fn is_not_op(v : @syntax.Var) -> Bool {
  match v.name {
    Ident(name~) => name == "not" || name == "!"
    Dot(..) => false
  }
}

///|
fn is_eq_op(v : @syntax.Var) -> Bool {
  match v.name {
    Ident(name~) => name == "=="
    Dot(..) => false
  }
}

// whitelist validators: passing implies the value is safe for headers

///|
fn is_whitelist_validator(name : String) -> Bool {
  match name {
    "is_ascii"
    | "is_alnum"
    | "is_digit"
    | "is_lower"
    | "is_upper"
    | "is_whitespace"
    | "is_valid"
    | "validate"
    | "sanitized"
    | "is_safe" => true
    _ => false
  }
}

// positive validation form: the tested variable is the receiver/arg

///|
fn flow_var_name(expr : @syntax.Expr) -> String? {
  match expr {
    Ident(id~, ..) =>
      match id.name {
        Ident(name~) => Some(name)
        Dot(..) => None
      }
    Field(record~, ..) => flow_var_name(record)
    _ => None
  }
}

// ── sink reporting ────────────────────────────────────────────────────────

///|
// field label of a Mutate accessor ("?" for non-label forms)

///|
fn accessor_label(accessor : @syntax.Accessor) -> String {
  match accessor {
    Label(l) => l.name
    _ => "?"
  }
}

///|
fn param_index(params : Array[String], name : String) -> Int? {
  let mut found : Int? = None
  for i in 0..<params.length() {
    if params[i] == name && found == None {
      found = Some(i)
    }
  }
  found
}

// P3: call-site consumption of field-write summaries.
// If summary says callee writes taint from param p into a field of param r,
// and the caller passes a tainted value at p's position, then the variable
// passed at r's position becomes tainted (source-derived provenance).
// arg_taints are the single-pass flow results in argument order.

///|
// T4.1: callee name for summary lookup — free functions (Ident) and the
// static method form `Type::method` (Method callee); DotApply callers pass
// the method name directly

///|
fn callee_summary_name(func : @syntax.Expr) -> String? {
  match func {
    Ident(id~, ..) =>
      match id.name {
        Ident(name~) => Some(name)
        Dot(id~, ..) => Some(id)
      }
    Method(type_name~, method_name~, ..) => {
      // summaries are keyed by short name (T1.4 will qualify); resolve
      // "Type::method" to its long form and fall back to the short key
      let tn = match type_name.name {
        Ident(name~) => name
        Dot(pkg~, id~) => pkg + "::" + id
      }
      Some(tn + "::" + method_name.name)
    }
    _ => None
  }
}

// summary lookup with short-name fallback: long "Type::method" keys hit
// the collection-side short keys ("method")

///|
fn summary_lookup(
  ictx : InterProceduralContext,
  name : String,
) -> FuncTaintSummary? {
  match ictx.summaries.get(name) {
    Some(s) => Some(s)
    None => {
      let idx = find_last(name, "::")
      if idx > 0 {
        ictx.summaries.get(Show::to_string(name[idx + 2:]))
      } else {
        None
      }
    }
  }
}

// T4.1: consume ret_from at a call site — surgical refinement over the
// args-union fallback. When a summary exists AND at least one argument
// binds to a ret_from param, the refined return value is the join over
// those args only (provenance preserved), so unrelated args no longer
// taint the result. No binding hit -> None (caller keeps the fallback:
// unresolved callees are never refined — honest under-resolution).

///|
fn apply_ret_from(
  func : @syntax.Expr,
  args : @list.List[@syntax.Argument],
  arg_pairs : Array[ArgTaint],
  ctx : FlowCtx,
) -> Taint? {
  let ictx = match ctx.ictx {
    Some(i) => i
    None => return None
  }
  let name = match callee_summary_name(func) {
    Some(n) => n
    None => return None
  }
  let summary = match summary_lookup(ictx, name) {
    Some(s) => s
    None => return None
  }
  ret_from_join(summary, args, arg_pairs, 0)
}

// T4.2: during SUMMARY COLLECTION only (record_sinks channel armed), a
// callee whose param i reaches a header sink taints the CALLER's param
// bound at argument position i — recursive sink chains then converge
// under the SCC driver. Scan mode (record_sinks=None) is unaffected.

///|
fn maybe_record_transitive_sink(
  func : @syntax.Expr,
  args : @list.List[@syntax.Argument],
  arg_pairs : Array[ArgTaint],
  ctx : FlowCtx,
) -> Unit {
  let arr = match ctx.record_sinks {
    Some(a) => a
    None => return
  }
  let ictx = match ctx.ictx {
    Some(i) => i
    None => return
  }
  let name = match callee_summary_name(func) {
    Some(n) => n
    None => return
  }
  let summary = match summary_lookup(ictx, name) {
    Some(s) => s
    None => return
  }
  if summary.param_sinks.length() == 0 {
    return
  }
  let taint_at = args_taint_at_params(summary, args, arg_pairs, 0)
  summary.param_sinks.each(fn(p, _sinks) {
    let pi = match param_index(summary.params, p) {
      Some(i) => i
      None => return
    }
    if pi >= taint_at.length() {
      return
    }
    match taint_at[pi] {
      TaintedParam(cp) => if !arr.contains(cp) { arr.push(cp) }
      _ => ()
    }
  })
}

// shared join core; `offset` shifts positional args past an implicit
// receiver param (DotApply: receiver binds param 0)

///|
fn ret_from_join(
  summary : FuncTaintSummary,
  args : @list.List[@syntax.Argument],
  arg_pairs : Array[ArgTaint],
  offset : Int,
) -> Taint? {
  if summary.ret_from.length() == 0 {
    return None
  }
  let taint_at = args_taint_at_params(summary, args, arg_pairs, offset)
  let mut refined : Taint? = None
  let mut mapped_any = false
  for p in summary.ret_from {
    let pi = match param_index(summary.params, p) {
      Some(i) => i
      None => continue
    }
    if pi >= taint_at.length() {
      continue
    }
    mapped_any = true
    refined = Some(taint_or(or_taint(refined), taint_at[pi]))
  }
  if mapped_any {
    refined
  } else {
    None
  }
}

// T4.1: DotApply ret_from — receiver binds param 0, args shifted by one

///|
fn apply_ret_from_dot(
  mname : String,
  args : @list.List[@syntax.Argument],
  arg_pairs : Array[ArgTaint],
  ctx : FlowCtx,
  recv_taint : Taint,
) -> Taint? {
  let ictx = match ctx.ictx {
    Some(i) => i
    None => return None
  }
  let summary = match summary_lookup(ictx, mname) {
    Some(s) => s
    None => return None
  }
  let no_recv_args : @list.List[@syntax.Argument] = args
  let joined = ret_from_join(summary, no_recv_args, arg_pairs, 1)
  // receiver taint contributes when param 0 (self) is in ret_from
  let mut result = joined
  if summary.ret_from.length() > 0 &&
    summary.params.length() > 0 &&
    summary.ret_from.contains(summary.params[0]) {
    result = Some(taint_or(or_taint(result), recv_taint))
  }
  result
}

// per-param taints from already-flowed pairs (labelled by name,
// positional by order; `offset` reserves leading params for the receiver)

///|
fn args_taint_at_params(
  summary : FuncTaintSummary,
  args : @list.List[@syntax.Argument],
  arg_pairs : Array[ArgTaint],
  offset : Int,
) -> Array[Taint] {
  let taint_at : Array[Taint] = []
  let mut n = 0
  while n < summary.params.length() {
    taint_at.push(Clean)
    n += 1
  }
  let mut pos = offset
  let mut ai = 0
  for arg in args {
    let t = if ai < arg_pairs.length() { arg_pairs[ai].taint } else { Clean }
    let pidx = match arg.kind {
      Labelled(l) | LabelledPun(l) => param_index(summary.params, l.name)
      _ => if pos < summary.params.length() { Some(pos) } else { None }
    }
    match pidx {
      Some(pi) => if pi < taint_at.length() { taint_at[pi] = t }
      None => ()
    }
    match arg.kind {
      Labelled(_)
      | LabelledPun(_)
      | LabelledOption(..)
      | LabelledOptionPun(..) => ()
      _ => pos += 1
    }
    ai += 1
  }
  taint_at
}

///|
fn or_taint(t : Taint?) -> Taint {
  match t {
    Some(v) => v
    None => Clean
  }
}

///|
fn apply_param_field_sinks(
  func : @syntax.Expr,
  args : @list.List[@syntax.Argument],
  ctx : FlowCtx,
  call_expr : @syntax.Expr,
) -> Unit {
  let ictx = match ctx.ictx {
    Some(i) => i
    None => return
  }
  let name = match callee_summary_name(func) {
    Some(n) => n
    None => return
  }
  let summary = match summary_lookup(ictx, name) {
    Some(s) => s
    None => return
  }
  if summary.param_field_sinks.length() == 0 {
    return
  }
  // positional param index -> argument expression (bounded: positional
  // args only; labelled lookups follow the same convention as
  // apply_field_taint_side_effect)
  let arg_exprs : Array[@syntax.Expr?] = []
  let mut pos = 0
  for arg in args {
    match arg.kind {
      Labelled(_)
      | LabelledPun(_)
      | LabelledOption(..)
      | LabelledOptionPun(..) => arg_exprs.push(None)
      _ => {
        ignore(pos)
        arg_exprs.push(Some(arg.value))
        pos += 1
      }
    }
  }
  for pair in summary.param_field_sinks {
    let (p, f) = pair
    let pi = match param_index(summary.params, p) {
      Some(i) => i
      None => continue
    }
    let arg_e = match (pi < arg_exprs.length(), arg_exprs[pi]) {
      (true, Some(e)) => e
      _ => continue
    }
    // bounded heap lookup: simple var argument with a known alloc-site
    match flow_var_name(arg_e) {
      Some(v) =>
        match sites_get(ctx, v) {
          Some(s) =>
            match heap_read(ctx, s, f) {
              Some(ft) =>
                // conditional taint CONFIRMED by the caller's heap fact
                match ft {
                  TaintedFieldRef(_, _) => () // still conditional: skip
                  _ => if is_tainted(ft) { report_cwe113(ctx, call_expr, ft) }
                }
              None => ()
            }
          None => ()
        }
      None => ()
    }
  }
}

// T4.1: method-form conditional field sinks — receiver binds param 0,
// positional args map to params 1..; heap confirm identical to the
// free-function form

///|
fn apply_param_field_sinks_dot(
  mname : String,
  recv_expr : @syntax.Expr,
  args : @list.List[@syntax.Argument],
  ctx : FlowCtx,
  call_expr : @syntax.Expr,
) -> Unit {
  let ictx = match ctx.ictx {
    Some(i) => i
    None => return
  }
  let summary = match summary_lookup(ictx, mname) {
    Some(s) => s
    None => return
  }
  if summary.param_field_sinks.length() == 0 {
    return
  }
  for pair in summary.param_field_sinks {
    let (p, f) = pair
    let pi = match param_index(summary.params, p) {
      Some(i) => i
      None => continue
    }
    // param 0 -> receiver expression; param i>0 -> positional arg i-1
    let arg_e = if pi == 0 {
      Some(recv_expr)
    } else {
      nth_positional_arg(args, pi - 1)
    }
    match arg_e {
      Some(e) => confirm_field_sink(ctx, e, f, call_expr)
      None => ()
    }
  }
}

// T4.1: method-form field-write side effect — receiver binds param 0

///|
fn apply_field_taint_side_effect_dot(
  mname : String,
  recv_expr : @syntax.Expr,
  args : @list.List[@syntax.Argument],
  ctx : FlowCtx,
  arg_pairs : Array[ArgTaint],
  recv_taint : Taint,
) -> Unit {
  let ictx = match ctx.ictx {
    Some(i) => i
    None => return
  }
  let summary = match summary_lookup(ictx, mname) {
    Some(s) => s
    None => return
  }
  if summary.field_taint.length() == 0 {
    return
  }
  // taint per param: receiver -> param 0, args -> params 1..N
  let taint_at = args_taint_at_params(summary, args, arg_pairs, 1)
  if summary.params.length() > 0 {
    taint_at[0] = recv_taint
  }
  summary.field_taint.each(fn(r, entries) {
    let ri = match param_index(summary.params, r) {
      Some(i) => i
      None => return // continue outer
    }
    if ri >= taint_at.length() {
      return
    }
    // receiver param r must map to a simple var here (bounded model)
    let r_expr = if ri == 0 {
      Some(recv_expr)
    } else {
      nth_positional_arg(args, ri - 1)
    }
    let r_var = match r_expr {
      Some(e) => flow_var_name(e)
      None => return
    }
    for entry in entries {
      let (f, src) = entry
      let si = match param_index(summary.params, src) {
        Some(i) => i
        None => continue
      }
      if si < taint_at.length() && is_tainted(taint_at[si]) {
        // taint flows: src param -> field f of receiver-side param r
        match r_var {
          Some(v) => apply_field_write_to_var(ctx, v, f, taint_at[si])
          None => ()
        }
      }
    }
  })
}

// record a field write on the caller side: var's alloc-site field becomes
// tainted (source-derived provenance preserved)

///|
fn apply_field_write_to_var(
  ctx : FlowCtx,
  v : String,
  f : String,
  t : Taint,
) -> Unit {
  match sites_get(ctx, v) {
    Some(s) => heap_write(ctx, s, f, t)
    None => ()
  }
}

// extract the expr for positional arg index n (0-based), skipping labelled

///|
fn nth_positional_arg(
  args : @list.List[@syntax.Argument],
  n : Int,
) -> @syntax.Expr? {
  let mut pos = 0
  for arg in args {
    match arg.kind {
      Labelled(_)
      | LabelledPun(_)
      | LabelledOption(..)
      | LabelledOptionPun(..) => ()
      _ => {
        if pos == n {
          return Some(arg.value)
        }
        pos += 1
      }
    }
  }
  None
}

// bounded heap lookup: simple var with a known alloc-site whose field fact
// confirms the conditional sink — shared by both call forms

///|
fn confirm_field_sink(
  ctx : FlowCtx,
  arg_e : @syntax.Expr,
  f : String,
  call_expr : @syntax.Expr,
) -> Unit {
  match flow_var_name(arg_e) {
    Some(v) =>
      match sites_get(ctx, v) {
        Some(s) =>
          match heap_read(ctx, s, f) {
            Some(ft) =>
              match ft {
                TaintedFieldRef(_, _) => () // still conditional: skip
                _ => if is_tainted(ft) { report_cwe113(ctx, call_expr, ft) }
              }
            None => ()
          }
        None => ()
      }
    None => ()
  }
}

///|
fn apply_field_taint_side_effect(
  func : @syntax.Expr,
  args : @list.List[@syntax.Argument],
  ctx : FlowCtx,
  arg_taints : Array[Taint],
) -> Unit {
  let ictx = match ctx.ictx {
    Some(i) => i
    None => return
  }
  let name = match callee_summary_name(func) {
    Some(n) => n
    None => return
  }
  let summary = match summary_lookup(ictx, name) {
    Some(s) => s
    None => return
  }
  if summary.field_taint.length() == 0 {
    return
  }
  // argument-order index -> param index (labelled match by name,
  // positional by param order)
  let arg_param_idx : Array[Int?] = []
  let mut pos = 0
  let mut i = 0
  for arg in args {
    let pidx = match arg.kind {
      Labelled(l) | LabelledPun(l) => param_index(summary.params, l.name)
      _ => if pos < summary.params.length() { Some(pos) } else { None }
    }
    arg_param_idx.push(pidx)
    match arg.kind {
      Labelled(_)
      | LabelledPun(_)
      | LabelledOption(..)
      | LabelledOptionPun(..) => ()
      _ => pos += 1
    }
    i += 1
  }
  ignore(i)
  // taint per param position (from the precomputed single-pass taints)
  let taint_at : Array[Taint] = []
  let var_at : Array[String?] = []
  let mut n = 0
  while n < summary.params.length() {
    taint_at.push(Clean)
    var_at.push(None)
    n += 1
  }
  let mut ai = 0
  for arg in args {
    match arg_param_idx[ai] {
      Some(pi) =>
        if pi < taint_at.length() && ai < arg_taints.length() {
          taint_at[pi] = arg_taints[ai]
          var_at[pi] = flow_var_name(arg.value)
        }
      None => ()
    }
    ai += 1
  }
  summary.field_taint.each(fn(recv_param, entries) {
    match param_index(summary.params, recv_param) {
      Some(ri) => {
        // any tainted source-param argument triggers the field write
        let mut triggered = false
        for entry in entries {
          match param_index(summary.params, entry.1) {
            Some(si) =>
              if si < taint_at.length() && is_tainted(taint_at[si]) {
                triggered = true
              }
            None => ()
          }
        }
        if triggered && ri < var_at.length() {
          match var_at[ri] {
            Some(var_name) => {
              let cur = or_clean_taint(env_lookup(ctx, var_name))
              env_assign(ctx, var_name, taint_or(cur, Tainted))
            }
            None => ()
          }
        }
      }
      None => ()
    }
  })
}

///|
fn report_output_sink(
  ctx : FlowCtx,
  expr : @syntax.Expr,
  t : Taint,
  sink_name : String,
) -> Unit {
  let origin = match t {
    TaintedParam(p) => " (via parameter `" + p + "`)"
    _ => ""
  }
  ctx.findings.push(
    make_finding(
      { cwe: 116, variant: "tainted-output", },
      ctx.severity,
      Medium,
      "Tainted data written to output channel `" +
      sink_name +
      "` without neutralization" +
      origin +
      ". User-controlled content that reaches an FFI/network output can enable injection attacks.",
      ctx.file,
      ctx.source,
      expr.loc(),
    ),
  )
}

///|
fn report_cwe113(ctx : FlowCtx, expr : @syntax.Expr, t : Taint) -> Unit {
  let origin = match t {
    TaintedParam(p) => " (via parameter `" + p + "`)"
    _ => ""
  }
  // conditional field-ref sink: NO local finding (config-like read);
  // record (param, field) for call-site re-check via summaries
  match t {
    TaintedFieldRef(p, f) => {
      match ctx.record_field_sinks {
        Some(arr) => {
          let entry = p + "|" + f
          if !arr.contains(entry) {
            arr.push(entry)
          }
        }
        None => ()
      }
      return
    }
    _ => ()
  }
  // M3 summary event: record which parameter reached a header sink
  match t {
    TaintedParam(p) =>
      match ctx.record_sinks {
        Some(arr) => if !arr.contains(p) { arr.push(p) }
        None => ()
      }
    _ => ()
  }
  ctx.findings.push(
    make_finding(
      { cwe: 113, variant: "crlf-injection", },
      ctx.severity,
      Medium,
      "Response header set with tainted value without CRLF sanitization" +
      origin +
      ". Attacker can inject \\r\\n to split the HTTP response, enabling session fixation or XSS.",
      ctx.file,
      ctx.source,
      expr.loc(),
    ),
  )
}

// ── M3: structural function summaries from the flow engine ───────────────
// Replaces the text-scanning Phase 1 of taint_interprocedural.mbt while
// keeping the InterProceduralContext API unchanged (scanner phase 2 and
// run_cross_func_taint keep working as-is).

///|
pub fn collect_func_summaries_flow(
  impls : @list.List[@syntax.Impl],
  file : String,
  ictx : InterProceduralContext,
  rules? : TaintRuleset,
) -> Unit {
  ignore(rules) // summaries use built-in classification; DSL affects rule scan only
  for item in impls {
    match item {
      TopFuncDef(fun_decl~, decl_body~, ..) => {
        let name = fun_decl.name.name
        let params : Array[String] = []
        let pnames : Array[String] = []
        match fun_decl.decl_params {
          Some(ps) =>
            for p in ps {
              match p {
                Positional(binder~, ..)
                | Labelled(binder~, ..)
                | Optional(binder~, ..)
                | QuestionOptional(binder~, ..) => pnames.push(binder.name)
                DiscardPositional(..) => ()
              }
            }
          None => ()
        }
        match decl_body {
          DeclBody(expr=Function(func~, ..)) =>
            collect_summary_func(
              Some(func.parameters),
              func.body,
              name,
              fun_decl.loc.start.lnum,
              file,
              ictx,
            )
          DeclBody(expr=body) => {
            for p in pnames {
              params.push(p)
            }
            collect_summary_func(
              fun_decl.decl_params,
              body,
              name,
              fun_decl.loc.start.lnum,
              file,
              ictx,
            )
          }
          _ => ()
        }
      }
      TopImpl(method_name~, params~, body~, ..) =>
        match body {
          DeclBody(expr=Function(func~, ..)) =>
            collect_summary_func(
              Some(func.parameters),
              func.body,
              method_name.name,
              method_name.loc.start.lnum,
              file,
              ictx,
            )
          DeclBody(expr=body) =>
            collect_summary_func(
              Some(params),
              body,
              method_name.name,
              method_name.loc.start.lnum,
              file,
              ictx,
            )
          _ => ()
        }
      _ => ()
    }
  }
}

///|
fn collect_summary_func(
  params : @list.List[@syntax.Parameter]?,
  body : @syntax.Expr,
  name : String,
  line : Int,
  file : String,
  ictx : InterProceduralContext,
) -> Unit {
  let param_names : Array[String] = []
  let sinks : Array[String] = []
  let returns : Array[String] = []
  let fields : Array[String] = []
  let field_sinks : Array[String] = [] // "param|field" conditional sinks
  let ctx : FlowCtx = {
    env: Map([]),
    findings: [],
    file,
    source: "",
    severity: Info,
    record_sinks: None,
    record_returns: None,
    record_fields: None,
    sites: Map([]),
    heap: Map([]),
    alloc_result: None,
    scope_stack: [],
    scope_counter: [0],
    name_map: Map([]),
    decl_counter: [0],
    raise_buffer: [],
    struct_comps: Map([]),
    hir_trace: [],
    hir_temp_ctr: [0],
    closures: Map([]),
    record_field_sinks: None,
    defers: [],
    loop_exits: [],
    // T4.2: collection consumes callee summaries so recursive chains
    // converge under the SCC driver (ret_from + param_sinks transitivity)
    ictx: Some(ictx),
    taint_rules: TaintRuleset::empty(),
    output_sinks_enabled: true,
  }
  scope_push(ctx) // function scope for summary collection
  match params {
    Some(ps) =>
      for p in ps {
        match p {
          Positional(binder~, ..)
          | Labelled(binder~, ..)
          | Optional(binder~, ..)
          | QuestionOptional(binder~, ..) => {
            param_names.push(binder.name)
            ignore(env_bind(ctx, binder.name, TaintedParam(binder.name)))
          }
          DiscardPositional(..) => ()
        }
      }
    None => ()
  }
  let final_taint = record_param_sinks(
    body, ctx, sinks, returns, field_sinks, fields,
  )
  scope_pop(ctx)
  // final-expression return taint (expression-oriented bodies): a body
  // whose value carries param provenance means "param flows to return"
  match final_taint {
    TaintedParam(p) =>
      if param_names.contains(p) && !returns.contains(p) {
        returns.push(p)
      }
    _ => ()
  }
  // dedup return channel against param set
  let ret_from : Array[String] = []
  for p in returns {
    if param_names.contains(p) && !ret_from.contains(p) {
      ret_from.push(p)
    }
  }
  // precise sink mapping: ONLY parameters that actually reached a sink
  let param_sinks : Map[String, Array[TaintSink]] = Map([])
  for pn in sinks {
    if param_names.contains(pn) && !param_sinks.contains(pn) {
      param_sinks[pn] = [HeaderValue]
    }
  }
  // field writes: recorded as "r|field|src-param" strings
  let field_taint : Map[String, Array[(String, String)]] = Map([])
  for entry in fields {
    let first_bar = find_bar(entry)
    let second_bar = find_bar_from(entry, first_bar + 1)
    if first_bar > 0 && second_bar > first_bar {
      let r = Show::to_string(entry[:first_bar])
      let fname = Show::to_string(entry[first_bar + 1:second_bar])
      let src = Show::to_string(entry[second_bar + 1:])
      if param_names.contains(r) && param_names.contains(src) {
        match field_taint.get(r) {
          Some(arr) => {
            let pair = (fname, src)
            if !arr.contains(pair) {
              arr.push(pair)
            }
          }
          None => field_taint[r] = [(fname, src)]
        }
      }
    }
  }
  // conditional field sinks: "param|field" -> (param, field) pairs
  let param_field_sinks : Array[(String, String)] = []
  for entry in field_sinks {
    let bar = find_bar(entry)
    if bar > 0 {
      let p = Show::to_string(entry[:bar])
      let f = Show::to_string(entry[bar + 1:])
      if param_names.contains(p) {
        let pair = (p, f)
        if !param_field_sinks.contains(pair) {
          param_field_sinks.push(pair)
        }
      }
    }
  }
  if param_sinks.length() > 0 ||
    ret_from.length() > 0 ||
    field_taint.length() > 0 ||
    param_field_sinks.length() > 0 {
    ictx.summaries[name] = {
      name,
      file,
      line,
      params: param_names,
      param_sinks,
      ret_from,
      field_taint,
      param_field_sinks,
    }
  }
}

// walk collecting which params reach header sinks (M3 slice: HeaderValue;
// P3 adds return-value and field-write recording channels)

///|
fn record_param_sinks(
  expr : @syntax.Expr,
  ctx : FlowCtx,
  sinks : Array[String],
  returns : Array[String],
  field_sinks : Array[String],
  fields : Array[String],
) -> Taint {
  ctx.record_sinks = Some(sinks)
  ctx.record_returns = Some(returns)
  ctx.record_fields = Some(fields)
  ctx.record_field_sinks = Some(field_sinks)
  let final_taint = flow(expr, ctx)
  ctx.record_sinks = None
  ctx.record_returns = None
  ctx.record_fields = None
  ctx.record_field_sinks = None
  final_taint
}

// byte offset helpers for "r|field|p" entries

///|
fn find_bar(s : String) -> Int {
  find_bar_from(s, 0)
}

///|
fn find_bar_from(s : String, from : Int) -> Int {
  let mut i = from
  while i < s.length() {
    if s[i] == '|' {
      return i
    }
    i += 1
  }
  -1
}

// T2a: run the flow engine and return the HIR statement trace (whitebox
// entry for tests and future diagnostics; mirrors run_flow_taint_func)

///|
pub fn run_flow_taint_trace(
  params : @list.List[@syntax.Parameter]?,
  body : @syntax.Expr,
  file : String,
  source : String,
  severity : Severity,
  findings : Array[Finding],
) -> Array[Stmt] {
  let ctx : FlowCtx = {
    env: Map([]),
    findings,
    file,
    source,
    severity,
    record_sinks: None,
    record_returns: None,
    record_fields: None,
    sites: Map([]),
    heap: Map([]),
    alloc_result: None,
    scope_stack: [],
    scope_counter: [0],
    name_map: Map([]),
    decl_counter: [0],
    raise_buffer: [],
    struct_comps: Map([]),
    hir_trace: [],
    hir_temp_ctr: [0],
    closures: Map([]),
    record_field_sinks: None,
    defers: [],
    loop_exits: [],
    ictx: None,
    taint_rules: TaintRuleset::empty(),
    output_sinks_enabled: true,
  }
  scope_push(ctx) // function scope
  match params {
    Some(ps) =>
      for param in ps {
        match param {
          Positional(binder~, ..)
          | Labelled(binder~, ..)
          | Optional(binder~, ..)
          | QuestionOptional(binder~, ..) =>
            ignore(env_bind(ctx, binder.name, TaintedParam(binder.name)))
          DiscardPositional(..) => ()
        }
      }
    None => ()
  }
  let _ = flow(body, ctx)
  // T2.2: function exit — execute still-pending defers (uncaught-raise
  // path); defers from completed blocks already ran at their block tail
  run_defers(ctx)
  ctx.raise_buffer.clear()
  scope_pop(ctx)
  ctx.hir_trace
}

///|
pub fn collect_mutate_receivers(
  expr : @syntax.Expr,
  out : Array[String],
) -> Unit {
  // receivers of field-mutation writes (`obj.f = v`): the captured object
  // is REFERENCE-SHARED (writes visible to the creator), unlike value
  // captures which are frozen snapshots
  match expr {
    Mutate(record~, ..) => {
      match flow_var_name(record) {
        Some(n) => if !out.contains(n) { out.push(n) }
        None => ()
      }
      collect_mutate_receivers(record, out)
    }
    Apply(func~, args~, ..) => {
      collect_mutate_receivers(func, out)
      for arg in args {
        collect_mutate_receivers(arg.value, out)
      }
    }
    DotApply(self~, ..) => collect_mutate_receivers(self, out)
    If(ifso~, ifnot~, ..) => {
      collect_mutate_receivers(ifso, out)
      match ifnot {
        Some(e) => collect_mutate_receivers(e, out)
        None => ()
      }
    }
    Match(cases~, ..) =>
      for case in cases {
        collect_mutate_receivers(case.body, out)
      }
    Sequence(exprs~, last_expr~, ..) => {
      for e in exprs {
        collect_mutate_receivers(e, out)
      }
      collect_mutate_receivers(last_expr, out)
    }
    Let(body~, ..) => collect_mutate_receivers(body, out)
    LetFn(body~, ..) => collect_mutate_receivers(body, out)
    LetAnd(body~, ..) => collect_mutate_receivers(body, out)
    _ => ()
  }
}

// ── T3.4 driver: per-function HIR traces for the live-vars analysis ──────
// Mirrors run_cwe113's top-level iteration; findings go to a scratch array
// (trace collection only — the scan pipeline is unaffected).

///|
pub fn collect_fn_traces(
  impls : @list.List[@syntax.Impl],
  file : String,
  source : String,
) -> Array[(String, Array[Stmt])] {
  let out : Array[(String, Array[Stmt])] = []
  let scratch : Array[Finding] = []
  for item in impls {
    match item {
      TopFuncDef(fun_decl~, decl_body~, ..) =>
        match decl_body {
          DeclBody(expr=Function(func~, ..)) =>
            run_flow_taint_func(
              Some(func.parameters),
              func.body,
              file,
              source,
              Info,
              scratch,
              fn_name=fun_decl.name.name,
              hir_out=out,
            )
          DeclBody(expr=body) =>
            run_flow_taint_func(
              fun_decl.decl_params,
              body,
              file,
              source,
              Info,
              scratch,
              fn_name=fun_decl.name.name,
              hir_out=out,
            )
          _ => ()
        }
      TopImpl(method_name~, params~, body~, ..) =>
        match body {
          DeclBody(expr=Function(func~, ..)) =>
            run_flow_taint_func(
              Some(func.parameters),
              func.body,
              file,
              source,
              Info,
              scratch,
              fn_name=method_name.name,
              hir_out=out,
            )
          DeclBody(expr=body) =>
            run_flow_taint_func(
              Some(params),
              body,
              file,
              source,
              Info,
              scratch,
              fn_name=method_name.name,
              hir_out=out,
            )
          _ => ()
        }
      TopExpr(expr~, ..) =>
        run_flow_taint_func(
          None,
          expr,
          file,
          source,
          Info,
          scratch,
          fn_name="<top>",
          hir_out=out,
        )
      _ => ()
    }
  }
  out
}
