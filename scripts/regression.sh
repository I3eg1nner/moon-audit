#!/usr/bin/env bash
# Legacy full-framework gate: requires the pre-redesign analyzer.
# Current syntax-pattern scans do not satisfy these semantic contracts.
# See docs/redesign-2026-09-22.md for the recovery point and active gates.
# Corpus regression harness. Exit 0 on complete measurements, 1 when any
# project/command/report fails, and 2 for setup errors. Findings alone are
# not failures: the corpus includes vulnerable projects.
# Override MOON_AUDIT_BIN, MOON_AUDIT_REPO, CORPUS_DIR, RESULTS_DIR, and
# COMMAND_TIMEOUT (seconds) as needed. Extra projects can be passed as paths.
set -uo pipefail
shopt -s nullglob

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="${MOON_AUDIT_REPO:-$(cd "$HERE/.." && pwd)}"
BIN="${MOON_AUDIT_BIN:-$REPO/_build/native/debug/build/src/main/main.exe}"
CORPUS_DIR="${CORPUS_DIR:-/data/my/corpus}"
RESULTS_DIR="${RESULTS_DIR:-/data/my/corpus-results}"
COMMAND_TIMEOUT="${COMMAND_TIMEOUT:-300}"

fail() { echo "error: $*" >&2; exit 2; }

# --record-commit uses the same corpus override as scanning.
if [ "${1:-}" = "--record-commit" ]; then
  [ "$#" -eq 1 ] || fail "--record-commit does not accept extra arguments"
  pins=()
  for d in "$CORPUS_DIR"/*/; do
    revision=$(git -C "$d" rev-parse HEAD 2>/dev/null) || revision=no-git
    pins+=("  $(basename "$d"): $revision")
  done
  [ "${#pins[@]}" -gt 0 ] || fail "no corpus directories found in $CORPUS_DIR"
  {
    printf '\n## Corpus pins (recorded %s)\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '%s\n' "${pins[@]}"
  } >> "$REPO/docs/ir/regression-baseline.md" || fail "cannot write corpus pins"
  echo "pins recorded"
  exit 0
fi

[ -x "$BIN" ] || fail "moon-audit binary not found at $BIN (build first or set MOON_AUDIT_BIN)"
command -v python3 >/dev/null || fail "python3 is required to validate scan reports"
if command -v timeout >/dev/null; then
  TIMEOUT=timeout
elif command -v gtimeout >/dev/null; then
  TIMEOUT=gtimeout
else
  fail "timeout or gtimeout is required"
fi
[[ "$COMMAND_TIMEOUT" =~ ^[1-9][0-9]*$ ]] || fail "COMMAND_TIMEOUT must be a positive integer"
mkdir -p "$RESULTS_DIR" || fail "cannot create results directory: $RESULTS_DIR"

# Workspace repos may keep moon.mod in a child matching their short name.
# Keep names and paths separate: ':' is a valid character in a project name.
names=()
paths=()
for d in "$CORPUS_DIR"/*/; do
  name=$(basename "$d")
  short=${name#*_}
  if [ -f "$d/moon.mod" ]; then
    names+=("$name")
    paths+=("$d")
  else
    for sub in "$d$short/" "$d"*/; do
      [ -f "${sub}moon.mod" ] || continue
      names+=("$name")
      paths+=("$sub")
      break
    done
  fi
done
# Preserve the historical local extra for the default corpus only. A
# CORPUS_DIR override must not silently add projects from this machine.
if [ "$CORPUS_DIR" = /data/my/corpus ] && [ -f /data/my/moonbit-petgraph/moon.mod ]; then
  names+=(moonbit-petgraph)
  paths+=(/data/my/moonbit-petgraph)
fi
for extra in "$@"; do
  [ -f "$extra/moon.mod" ] || fail "extra project has no moon.mod: $extra"
  name=$(basename "$extra")
  for existing in "${names[@]}"; do
    [ "$existing" != "$name" ] || fail "duplicate project result name: $name"
  done
  names+=("$name")
  paths+=("$extra")
done
[ "${#paths[@]}" -gt 0 ] || fail "no corpus projects found in $CORPUS_DIR"

printf '%-32s %9s %7s %18s %28s  %s\n' project findings files resolv edges status
printf '%80s\n' '' | tr ' ' '-'

rc=0
for i in "${!paths[@]}"; do
  name=${names[$i]}
  path=${paths[$i]}
  out="$RESULTS_DIR/$name"
  mkdir -p "$out" || fail "cannot create project results: $out"
  failed=0
  for mode in scan irstats callgraph; do
    case "$mode" in
      scan) args=(--format json "$path"); report=scan.json ;;
      irstats) args=(ir-stats "$path"); report=irstats.txt ;;
      callgraph) args=(call-graph "$path"); report=callgraph.txt ;;
    esac
    "$TIMEOUT" "$COMMAND_TIMEOUT" "$BIN" "${args[@]}" > "$out/$report" 2> "$out/$mode.stderr"
    command_rc=$?
    printf '%s\n' "$command_rc" > "$out/$mode.exit-code"
    if [ "$command_rc" -ne 0 ]; then
      echo "error: $name $mode exited $command_rc (see $out/$mode.stderr)" >&2
      failed=1
    fi
  done

  # Pass paths as data rather than interpolating them into Python source.
  if metrics=$(python3 - "$out/scan.json" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as source:
        report = json.load(source)
    if not isinstance(report, dict) or not isinstance(report.get("findings"), list):
        raise ValueError("expected an object with a findings array")
    files = report.get("files_scanned")
    if type(files) is not int or files < 0:
        raise ValueError("expected a nonnegative files_scanned integer")
    print(len(report["findings"]), files)
except (OSError, ValueError) as error:
    print(f"error: invalid scan report {sys.argv[1]}: {error}", file=sys.stderr)
    sys.exit(1)
PY
  ); then
    read -r findings files <<< "$metrics"
  else
    findings=-1
    files=-1
    failed=1
  fi
  resolv=$(sed -nE 's/.*(bound sites: +[0-9]+\/[0-9]+).*/\1/p' "$out/irstats.txt" | sed -n '1p' | tr -s ' ')
  edges=$(sed -nE 's/.*(site coverage: +[0-9]+\/[0-9]+ = [0-9]+%).*/\1/p' "$out/callgraph.txt" | sed -n '1p' | tr -s ' ')
  if [ -z "$resolv" ] || [ -z "$edges" ]; then
    echo "error: $name missing ir-stats or call-graph measurements" >&2
    failed=1
  fi
  if [ "$failed" -ne 0 ]; then
    status=ERR
    rc=1
  elif [ "$findings" -eq 0 ]; then
    status=clean
  else
    status=findings
  fi
  printf '%-32s %9s %7s %18s %28s  %s\n' "$name" "$findings" "$files" "${resolv:--}" "${edges:--}" "$status"
done

printf '\nraw outputs: %s/<name>/{scan.json,irstats.txt,callgraph.txt,*.stderr,*.exit-code}\n' "$RESULTS_DIR"
exit "$rc"
