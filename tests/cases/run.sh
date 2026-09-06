#!/usr/bin/env bash
# R2: real assertion gate for the counterexample corpus (tests/cases).
#
# Exit codes:
#   0  all expectations met (PASS cases exact; EXPECT-FAIL gaps unchanged)
#   1  expectation mismatch — a PASS case regressed, or an EXPECT-FAIL
#      flipped to reporting (update ROADMAP-T status + case header)
#   2  infrastructure failure — analyzer missing, cases project does not
#      compile, or the scan itself failed
#
# EXPECT-FAIL cases are registered with (current, wanted) counts: they are
# KNOWN misses tracked in docs/ir/ROADMAP-T.md; the gate fails when the gap
# changes in EITHER direction so status can never drift silently.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
ANALYZER="${ANALYZER:-$REPO/_build/native/debug/build/src/main/main.exe}"
export PATH="$HOME/.moon-latest/bin:$PATH"
export MOON_HOME="${MOON_HOME:-$HOME/.moon-latest}"

fail() { echo "GATE-FAIL($1): $2" >&2; exit "$1"; }

# ── infra: analyzer must exist and be executable ──────────────────────────
[ -f "$ANALYZER" ] || fail 2 "analyzer not found: $ANALYZER"
[ -x "$ANALYZER" ] || fail 2 "analyzer not executable: $ANALYZER"

# ── infra: cases project must compile ────────────────────────────────────
echo "== cases project compiles =="
( cd "$HERE" && timeout 300 moon check 2>&1 | tail -1 ) | grep -q "0 errors" \
  || fail 2 "cases project failed to compile"

# ── scan ──────────────────────────────────────────────────────────────────
echo "== scan (analyzer: $ANALYZER) =="
OUT="$(timeout 300 "$ANALYZER" "$HERE" 2>/dev/null)" \
  || fail 2 "analyzer run failed"
echo "$OUT" | grep -q "files scanned" || fail 2 "analyzer produced no scan summary"
echo "$OUT" | tail -3

# R2/R4: per-case ISOLATED scans — a single project-wide scan dedups
# identical sink snippets within a file (fingerprint = rule+snippet, no
# line), which silently collapses same-shaped cases (c9 control+original,
# c10/c11 both `sink(x)`). Each case therefore runs in its own project.
count() {
  local f="$1" tmp
  tmp="$(mktemp -d)"
  printf 'name = "iso-case"\nversion = "0.1.0"\n' > "$tmp/moon.mod"
  : > "$tmp/moon.pkg"
  cp "$HERE/taint-rules.json" "$tmp/taint-rules.json" 2>/dev/null || true
  cp "$HERE/c0_helpers.mbt" "$HERE/$f" "$tmp/" 2>/dev/null || true
  timeout 300 "$ANALYZER" "$tmp" 2>/dev/null | grep -c "$f:" || true
  rm -rf "$tmp"
}

# ── expectation table ─────────────────────────────────────────────────────
# format: file|status|current|wanted|gap-attribution
#   status=PASS: gate requires count == current (== wanted)
#   status=XFAIL: known miss; gate requires count == current; flipping to
#                 `wanted` (or any other change) fails with a hint to update
TABLE="
c1_shadowed_component.mbt|PASS|0|0|-
c2_double_evaluation.mbt|PASS|1|1|-
c3_raise_payload.mbt|PASS|2|2|-
c4_loop_propagation.mbt|PASS|1|1|-
c5_branch_heap.mbt|XFAIL|0|1|G4
c6_uncalled_closure.mbt|PASS|0|0|-
c7_defer_order.mbt|PASS|0|0|-
c8_default_param_call.mbt|PASS|0|0|-
c9_orig_same_name_destructure.mbt|PASS|2|2|-
c10_c12_scope_cases.mbt|PASS|3|3|-
c13_c14_error_and_dispatch.mbt|PASS|1|1|-
"

rc=0
echo
echo "== per-case assertions =="
# here-string (NOT a pipeline): the loop must run in THIS shell so that
# rc=1 from any mismatch survives to the exit gate below (gate7 P0)
while IFS='|' read -r file status cur want gap; do
  [ -n "$file" ] || continue
  actual=$(count "$file")
  if [ "$status" = "PASS" ]; then
    if [ "$actual" != "$cur" ]; then
      echo "  FAIL  $file: expected $cur, got $actual"
      rc=1
    else
      echo "  ok    $file: $actual/$cur (PASS)"
    fi
  else # XFAIL
    if [ "$actual" = "$cur" ]; then
      echo "  xfail $file: $actual findings, wanted $want (gap: $gap — tracked in ROADMAP-T)"
    else
      echo "  FLIP  $file: EXPECT-FAIL count changed $cur -> $actual (wanted-if-fixed: $want)"
      [ "$actual" = "$want" ] && echo "        -> fixed! update ROADMAP-T $gap status + flip case header to PASS"
      rc=1
    fi
  fi
done <<< "$TABLE"
[ "$rc" -eq 0 ] || fail 1 "expectation mismatch (see above)"

# ── C8: default-param call sites must be in the call graph (T0.2(a)) ─────
echo
echo "== C8 default-param sites enter ir-stats =="
IR="$(timeout 300 "$ANALYZER" ir-stats "$HERE" 2>/dev/null)" || fail 2 "ir-stats failed"
SITES=$(echo "$IR" | grep -oE "call sites: +[0-9]+" | grep -oE "[0-9]+" || true)
BOUND=$(echo "$IR" | grep -oE "bound sites: +[0-9]+/[0-9]+" | grep -oE "[0-9]+" | head -1 || true)
[ -n "$SITES" ] && [ "$SITES" -gt 0 ] || fail 1 "ir-stats: no call sites counted"
[ -n "$BOUND" ] && [ "$BOUND" -ge 1 ] || fail 1 "ir-stats: default-param call site not bound (C8 regression)"
echo "  ok    call sites=$SITES bound=$BOUND"

# ── C14: empty candidate set ⇒ unknown, not covered (R7) ──────────────
echo
echo "== C14 empty-candidate dispatch classification (R7) =="
C14T="$(mktemp -d)"
printf 'name = "c14iso"\nversion = "0.1.0"\n' > "$C14T/moon.mod"
: > "$C14T/moon.pkg"
cat > "$C14T/lib.mbt" <<'MBOF'
trait NoImplAction {
  act(Self) -> Unit
}
fn case14(a : &NoImplAction) -> Unit {
  a.act()
}
MBOF
CG="$(timeout 300 "$ANALYZER" call-graph "$C14T" 2>/dev/null)" || fail 2 "call-graph failed"
rm -rf "$C14T"
echo "$CG" | grep -q "site coverage:      0/1 = 0%" \
  || fail 1 "C14: empty candidate set no longer classified unknown (R7 regression)"
echo "  ok    empty candidate set → 0/1 coverage (unknown, no-impls)"

# ── scope disclosure must not fake measurements ───────────────────────────
echo "$OUT" | grep -q "unsupported-semantics=unknown(not-measured)" \
  || fail 1 "scope disclosure no longer reports unknown(not-measured)"

echo
echo "GATE-OK: all PASS exact, all EXPECT-FAIL gaps unchanged ($(echo "$TABLE" | grep -c XFAIL || true) tracked misses)"
exit 0
