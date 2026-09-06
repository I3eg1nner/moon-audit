// T3.1 thin slice: algebraic property tests for the SecurityFact lattice.
// Manual example sets (per task spec; quickcheck wiring is a later step).

///|
fn example_facts() -> Array[SecurityFact] {
  [
    SecurityFact::clean(),
    SecurityFact::bottom(),
    SecurityFact::tainted_unknown(),
    SecurityFact::from_source("req"),
    SecurityFact::from_source("user"),
    SecurityFact::from_source("req.body"),
    SecurityFact::from_source("user.token"),
    SecurityFact::from_source("req").join(SecurityFact::tainted_unknown()),
    SecurityFact::from_source("req").join(SecurityFact::from_source("user")),
    SecurityFact::from_source("req").join(SecurityFact::from_source("req.body")),
  ]
}

///|
fn sym(a : SecurityFact, b : SecurityFact) -> Bool {
  a.join(b) == b.join(a)
}

///|
test "t3a_join_idempotent" {
  for a in example_facts() {
    inspect(a.join(a) == a, content="true")
  }
}

///|
test "t3a_join_commutative" {
  let facts = example_facts()
  for a in facts {
    for b in facts {
      inspect(sym(a, b), content="true")
    }
  }
}

///|
test "t3a_join_associative" {
  let facts = example_facts()
  for a in facts {
    for b in facts {
      for c in facts {
        inspect(a.join(b).join(c) == a.join(b.join(c)), content="true")
      }
    }
  }
}

///|
test "t3a_join_identity_and_monotonicity" {
  // clean() is the join identity on the REACHABLE domain; bottom is its own
  // identity (bottom + clean = clean — reachability joins upward)
  for a in example_facts() {
    let expect_identity = a.reach == Reachable
    inspect(
      (a.join(SecurityFact::clean()) == a) == expect_identity,
      content="true",
    )
    inspect(a.leq(a.join(SecurityFact::from_source("extra"))), content="true")
  }
  // bottom is the lattice bottom
  for a in example_facts() {
    inspect(SecurityFact::bottom().leq(a), content="true")
  }
}

// differential lock: legacy taint_or table vs SecurityFact join + view rules.
// 16-pair matrix over {Clean, Tainted, P(req), P(user), F(req,body), F(user,token)}
// (same-name and cross-name variants included) — zero behavior change proof
// for the taint_flow.mbt rewiring.

///|
fn legacy_taint_or_sym(a : String, b : String) -> String {
  // verbatim transcription of the pre-T3.1 taint_or table (taint_flow.mbt)
  fn is_p(s : String) -> Bool {
    s.has_prefix("p:")
  }

  fn is_f(s : String) -> Bool {
    s.has_prefix("f:")
  }

  if a == "clean" {
    return b
  }
  if b == "clean" {
    return a
  }
  if is_p(a) && is_p(b) {
    if a == b {
      return a
    }
    return "tainted"
  }
  if is_f(a) && is_f(b) {
    if a == b {
      return a
    }
    return "tainted"
  }
  if is_f(a) || is_f(b) {
    return "tainted"
  }
  if is_p(a) {
    return a
  }
  if is_p(b) {
    return b
  }
  "tainted"
}

///|
fn fact_of_sym(s : String) -> SecurityFact {
  if s == "clean" {
    SecurityFact::clean()
  } else if s == "tainted" {
    SecurityFact::tainted_unknown()
  } else if s.has_prefix("p:") {
    SecurityFact::from_source(Show::to_string(s[2:]))
  } else {
    // f:param.field
    // f:p.f identity is already "p.f" after stripping the "f:" prefix
    SecurityFact::from_source(Show::to_string(s[2:]))
  }
}

///|
test "t3a_differential_16_pairs_vs_legacy_table" {
  let syms : Array[String] = [
    "clean", "tainted", "p:req", "p:user", "f:req.body", "f:user.token",
  ]
  for a in syms {
    for b in syms {
      let legacy = legacy_taint_or_sym(a, b)
      let via_fact = fact_of_sym(a).join(fact_of_sym(b)).to_taint_view()
      // on mismatch the inspected label shows all three values
      inspect(
        (if legacy == via_fact {
          "same"
        } else {
          "MISMATCH legacy=" + legacy + " fact=" + via_fact
        }) +
        " [" +
        a +
        " | " +
        b +
        "]",
        content="same [" + a + " | " + b + "]",
      )
    }
  }
}

///|
test "t3a_view_rules_documented_shapes" {
  inspect(SecurityFact::clean().to_taint_view(), content="clean")
  inspect(SecurityFact::tainted_unknown().to_taint_view(), content="tainted")
  inspect(SecurityFact::from_source("req").to_taint_view(), content="p:req")
  inspect(
    SecurityFact::from_source("req.body").to_taint_view(),
    content="f:req.body",
  )
  // single plain param keeps attribution even when unknown taint joins in
  // (legacy `(_, P(p)) => P(p)` rule)
  inspect(
    SecurityFact::from_source("req")
    .join(SecurityFact::tainted_unknown())
    .to_taint_view(),
    content="p:req",
  )
  // mixed provenance drops attribution (legacy P(p)+P(q) => Tainted)
  inspect(
    SecurityFact::from_source("req")
    .join(SecurityFact::from_source("user"))
    .to_taint_view(),
    content="tainted",
  )
}
