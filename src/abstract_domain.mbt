// T3.1 thin slice: SecurityFact lattice — the abstract domain substrate.
//
// Design (ROADMAP-T T3.1 / review G1):
//   reach   : Reachable | Unreachable   (control-flow reachability; Unreachable
//             is the join identity/bottom)
//   src     : ordered, deduplicated source set (param provenance `p`,
//             param-field conditional refs encoded `p.f`)
//   unknown : true = tainted from an unknown origin (env/callback/derive)
//
// join is set-union + boolean-or + reach-join => idempotent, commutative and
// associative BY CONSTRUCTION (property-tested in abstract_domain_test.mbt).
//
// The legacy `Taint` enum (taint_flow.mbt) becomes a VIEW over SecurityFact:
//   Clean          <-> {src=[], unknown=false}
//   TaintedParam(p)<-> {src=[p]}
//   TaintedFieldRef(p,f) <-> {src=["p.f"]}  (conditional taint, no local finding)
//   Tainted        <-> {unknown=true}
// with the view rules reproducing the legacy taint_or table exactly
// (differential-locked in abstract_domain_test.mbt::differential_16_pairs).

///|
pub(all) enum Reach {
  Reachable
  Unreachable
} derive(Eq, Debug)

///|
fn Reach::join(self : Reach, other : Reach) -> Reach {
  // Unreachable is bottom: once any side is reachable the join is reachable
  match (self, other) {
    (Unreachable, r) => r
    (r, Unreachable) => r
    (Reachable, Reachable) => Reachable
  }
}

///|
pub(all) struct SecurityFact {
  reach : Reach
  src : Array[String] // ordered, deduplicated source identities
  unknown : Bool // tainted from unknown origin
} derive(Eq, Debug)

///|
pub fn SecurityFact::clean() -> SecurityFact {
  { reach: Reachable, src: [], unknown: false, }
}

///|
pub fn SecurityFact::bottom() -> SecurityFact {
  { reach: Unreachable, src: [], unknown: false, }
}

///|
pub fn SecurityFact::tainted_unknown() -> SecurityFact {
  { reach: Reachable, src: [], unknown: true, }
}

///|
pub fn SecurityFact::from_source(src : String) -> SecurityFact {
  { reach: Reachable, src: [src], unknown: false, }
}

// ── ordered-dedup set ops (kept private: src is maintained by join only) ──

///|
fn set_insert(arr : Array[String], s : String) -> Unit {
  // ordered insert keeps representation canonical (Eq stays meaningful)
  if arr.contains(s) {
    return
  }
  let mut i = 0
  while i < arr.length() && arr[i] < s {
    i += 1
  }
  arr.insert(i, s)
}

///|
fn set_union(a : Array[String], b : Array[String]) -> Array[String] {
  let out = a.copy()
  for s in b {
    set_insert(out, s)
  }
  out
}

// ── the lattice join ──────────────────────────────────────────────────────

///|
pub fn SecurityFact::join(
  self : SecurityFact,
  other : SecurityFact,
) -> SecurityFact {
  {
    reach: self.reach.join(other.reach),
    src: set_union(self.src, other.src),
    unknown: self.unknown || other.unknown,
  }
}

///|
pub fn SecurityFact::leq(self : SecurityFact, other : SecurityFact) -> Bool {
  // partial order for the lattice (used by monotonicity tests)
  if self.reach == Reachable && other.reach == Unreachable {
    return false
  }
  for s in self.src {
    if !other.src.contains(s) {
      return false
    }
  }
  !self.unknown || other.unknown
}

///|
pub fn SecurityFact::is_tainted(self : SecurityFact) -> Bool {
  self.src.length() > 0 || self.unknown
}

// ── view mapping onto the legacy Taint domain ────────────────────────────
// Field-ref sources are encoded "param.field" (see encode/decode below).

///|
pub fn fact_of_taint_clean() -> SecurityFact {
  SecurityFact::clean()
}

///|
pub fn fact_of_tainted_param(p : String) -> SecurityFact {
  SecurityFact::from_source(encode_param(p))
}

///|
pub fn fact_of_tainted_unknown() -> SecurityFact {
  SecurityFact::tainted_unknown()
}

///|
pub fn fact_of_field_ref(p : String, f : String) -> SecurityFact {
  SecurityFact::from_source(encode_field_ref(p, f))
}

///|
fn encode_param(p : String) -> String {
  // plain identity: no '.' separator (params cannot contain '.' in practice;
  // if they did, encoding is still injective for the view decode below)
  p
}

///|
fn encode_field_ref(p : String, f : String) -> String {
  p + "." + f
}

///|
fn is_field_src(s : String) -> Bool {
  find_first_dot(s) >= 0
}

///|
fn find_first_dot(s : String) -> Int {
  let bytes = s.to_array()
  for i in 0..<bytes.length() {
    if bytes[i] == '.' {
      return i
    }
  }
  -1
}

// Legacy taint_or semantics reproduced as view rules over the join result:
//   unknown present          -> Tainted, EXCEPT a single plain param keeps
//                                its attribution (legacy `(_, P(p)) => P(p)`)
//   exactly one plain source -> TaintedParam
//   exactly one field source -> TaintedFieldRef (conditional, no local find)
//   mixed (>=2 sources)      -> Tainted (drop attribution)
//   empty + no unknown       -> Clean

///|
pub fn SecurityFact::to_taint_view(self : SecurityFact) -> String {
  // symbolic view for tests ("clean"/"tainted"/"p:name"/"f:p.field");
  // production Taint lives in taint_flow.mbt and is rebuilt via the same
  // rules in taint_or (differential-locked).
  let n = self.src.length()
  if !self.unknown && n == 0 && self.reach != Unreachable {
    return "clean"
  }
  if n == 0 {
    return "tainted"
  }
  if n == 1 {
    if is_field_src(self.src[0]) {
      return if self.unknown { "tainted" } else { "f:" + self.src[0] }
    }
    return "p:" + self.src[0]
  }
  "tainted"
}
