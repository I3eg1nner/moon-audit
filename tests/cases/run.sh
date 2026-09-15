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
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
ANALYZER="${ANALYZER:-$REPO/_build/native/debug/build/src/main/main.exe}"
# Respect the selected toolchain and permit an explicit compiler override.
MOON="${MOON_BIN:-moon}"
if ! command -v "$MOON" >/dev/null && [ -z "${MOON_BIN:-}" ]; then
  for candidate in "${MOON_HOME:-$HOME/.moon-latest}/bin/moon" "$HOME/.moon/bin/moon"; do
    if [ -x "$candidate" ]; then MOON="$candidate"; break; fi
  done
fi
COMMAND_TIMEOUT="${COMMAND_TIMEOUT:-300}"

fail() { echo "GATE-FAIL($1): $2" >&2; exit "$1"; }
command -v "$MOON" >/dev/null || fail 2 "moon compiler not found: $MOON"
if command -v timeout >/dev/null; then
  TIMEOUT=timeout
elif command -v gtimeout >/dev/null; then
  TIMEOUT=gtimeout
else
  fail 2 "timeout or gtimeout is required"
fi
[[ "$COMMAND_TIMEOUT" =~ ^[1-9][0-9]*$ ]] || fail 2 "COMMAND_TIMEOUT must be a positive integer"
WORK_DIR="$(mktemp -d)" || fail 2 "cannot create temporary directory"
trap 'rm -rf "$WORK_DIR"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
run_timed() { "$TIMEOUT" "$COMMAND_TIMEOUT" "$@"; }

# ── infra: analyzer must exist and be executable ──────────────────────────
[ -f "$ANALYZER" ] || fail 2 "analyzer not found: $ANALYZER"
[ -x "$ANALYZER" ] || fail 2 "analyzer not executable: $ANALYZER"

# ── infra: cases project must compile ────────────────────────────────────
echo "== cases project compiles =="
if ! (cd "$HERE" && run_timed "$MOON" check) > "$WORK_DIR/check.log" 2>&1; then
  cat "$WORK_DIR/check.log" >&2
  fail 2 "cases project failed to compile"
fi
tail -1 "$WORK_DIR/check.log"

# ── scan ──────────────────────────────────────────────────────────────────
echo "== scan (analyzer: $ANALYZER) =="
if ! OUT="$(run_timed "$ANALYZER" "$HERE" 2> "$WORK_DIR/scan.stderr")"; then
  cat "$WORK_DIR/scan.stderr" >&2
  fail 2 "analyzer run failed"
fi
echo "$OUT" | grep -q "files scanned" || fail 2 "analyzer produced no scan summary"
echo "$OUT" | tail -3

# R2/R4: per-case ISOLATED scans — a single project-wide scan dedups
# identical sink snippets within a file (fingerprint = rule+snippet, no
# line), which silently collapses same-shaped cases (c9 control+original,
# c10/c11 both `sink(x)`). Each case therefore runs in its own project.
count() {
  local f="$1" tmp="$WORK_DIR/$1"
  mkdir -p "$tmp" || return 2
  printf 'name = "iso-case"\nversion = "0.1.0"\n' > "$tmp/moon.mod" || return 2
  : > "$tmp/moon.pkg" || return 2
  cp "$HERE/taint-rules.json" "$HERE/c0_helpers.mbt" "$HERE/$f" "$tmp/" || return 2
  if ! run_timed "$ANALYZER" "$tmp" > "$tmp/scan.log" 2> "$tmp/scan.stderr"; then
    cat "$tmp/scan.stderr" >&2
    return 2
  fi
  grep -Eq 'files scanned|^No issues found\.$' "$tmp/scan.log" || return 2
  # grep's status 1 means zero matches; all other errors must propagate.
  grep -F -c "$f:" "$tmp/scan.log" || [ "$?" -eq 1 ]
}

# P0: c15 requires --mode deep for summary refinement (quick mode's
# args-union fallback is intentionally conservative for non-web projects)
count_deep() {
  local f="$1" tmp="$WORK_DIR/deep_$1"
  mkdir -p "$tmp" || return 2
  printf 'name = "iso-case"\nversion = "0.1.0"\n' > "$tmp/moon.mod" || return 2
  : > "$tmp/moon.pkg" || return 2
  cp "$HERE/taint-rules.json" "$HERE/c0_helpers.mbt" "$HERE/$f" "$tmp/" || return 2
  if ! run_timed "$ANALYZER" --mode deep "$tmp" > "$tmp/scan.log" 2> "$tmp/scan.stderr"; then
    cat "$tmp/scan.stderr" >&2
    return 2
  fi
  grep -Eq 'files scanned|^No issues found\.$' "$tmp/scan.log" || return 2
  grep -F -c "$f:" "$tmp/scan.log" || [ "$?" -eq 1 ]
}

# ── expectation table ─────────────────────────────────────────────────────
# format: file|status|current|wanted|gap-attribution
#   status=PASS: gate requires count == current (== wanted)
#   status=XFAIL: known miss; gate requires count == current; flipping to
#                 `wanted` (or any other change) fails with a hint to update
# note: c15 uses count_deep (--mode deep) — see function above
TABLE="
c1_shadowed_component.mbt|PASS|0|0|-
c2_double_evaluation.mbt|PASS|1|1|-
c3_raise_payload.mbt|PASS|2|2|-
c4_loop_propagation.mbt|PASS|1|1|-
c5_branch_heap.mbt|PASS|1|1|-
c6_uncalled_closure.mbt|PASS|0|0|-
c7_defer_order.mbt|PASS|0|0|-
c8_default_param_call.mbt|PASS|0|0|-
c9_orig_same_name_destructure.mbt|PASS|2|2|-
c10_c12_scope_cases.mbt|PASS|3|3|-
c13_c14_error_and_dispatch.mbt|PASS|1|1|-
c15_summary_collision.mbt|PASS|2|2|-
"

rc=0
echo
echo "== per-case assertions =="
# here-string (NOT a pipeline): the loop must run in THIS shell so that
# rc=1 from any mismatch survives to the exit gate below (gate7 P0)
while IFS='|' read -r file status cur want gap; do
  [ -n "$file" ] || continue
  # c15 requires --mode deep for summary refinement
  if [[ "$file" == c15_* ]]; then
    actual=$(count_deep "$file") || fail 2 "isolated deep scan failed: $file"
  else
    actual=$(count "$file") || fail 2 "isolated scan failed: $file"
  fi
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
# Reuse C8's isolated project: unrelated calls must not satisfy this gate.
if ! IR="$(run_timed "$ANALYZER" ir-stats "$WORK_DIR/c8_default_param_call.mbt" 2> "$WORK_DIR/ir.stderr")"; then
  cat "$WORK_DIR/ir.stderr" >&2
  fail 2 "ir-stats failed"
fi
SITES=$(printf '%s\n' "$IR" | sed -nE 's/^call sites: +([0-9]+).*$/\1/p')
BOUND=$(printf '%s\n' "$IR" | sed -nE 's/^ +bound sites: +([0-9]+\/[0-9]+).*$/\1/p')
# greet(), ignore(), and decorated() in the default expression must all bind.
[ "$SITES" = 3 ] && [ "$BOUND" = 3/3 ] \
  || fail 1 "C8: expected 3 call sites bound 3/3, got sites=$SITES bound=$BOUND"
echo "  ok    call sites=$SITES bound=$BOUND"

# ── C14: empty candidate set ⇒ unknown, not covered (R7) ──────────────
echo
echo "== C14 empty-candidate dispatch classification (R7) =="
C14T="$WORK_DIR/c14"
mkdir -p "$C14T" || fail 2 "cannot create C14 project"
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
if ! CG="$(run_timed "$ANALYZER" call-graph "$C14T" 2> "$WORK_DIR/callgraph.stderr")"; then
  cat "$WORK_DIR/callgraph.stderr" >&2
  fail 2 "call-graph failed"
fi
echo "$CG" | grep -Eq "site coverage: +0/1 = 0%" \
  || fail 1 "C14: empty candidate set no longer classified unknown (R7 regression)"
echo "  ok    empty candidate set → 0/1 coverage (unknown, no-impls)"

# ── scope disclosure must not fake measurements ───────────────────────────
echo "$OUT" | grep -q "unsupported-semantics=unknown(not-measured)" \
  || fail 1 "scope disclosure no longer reports unknown(not-measured)"

echo
echo "GATE-OK: all PASS exact, all EXPECT-FAIL gaps unchanged ($(echo "$TABLE" | grep -c XFAIL || true) tracked misses)"
exit 0
