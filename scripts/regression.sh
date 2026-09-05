#!/usr/bin/env bash
# Corpus regression harness for moon-audit.
# Runs (a) security scan (JSON), (b) ir-stats, (c) call-graph on every
# corpus project under /data/my/corpus/ plus local extras, saves raw
# outputs to /data/my/corpus-results/<name>/, and prints a summary table:
#   project | findings | files | resolution | edge-coverage | status
#
# Repeatable: safe to re-run (outputs are overwritten).
# Binary can be overridden: MOON_AUDIT_BIN=/path/to/main.exe

set -u

REPO="${MOON_AUDIT_REPO:-/data/my/moon-audit}"
BIN="${MOON_AUDIT_BIN:-$REPO/_build/native/debug/build/src/main/main.exe}"
CORPUS_DIR="${CORPUS_DIR:-/data/my/corpus}"
RESULTS_DIR="${RESULTS_DIR:-/data/my/corpus-results}"

if [ ! -x "$BIN" ]; then
  echo "error: moon-audit binary not found at $BIN (build first or set MOON_AUDIT_BIN)" >&2
  exit 2
fi

mkdir -p "$RESULTS_DIR"

# collect corpus projects (subdirectories with a moon.mod) + local extras.
# workspace repos (moon.work/apm.yml) keep moon.mod one level down: use the
# subpackage matching the repo short name, else the first one found.
projects=()
for d in "$CORPUS_DIR"/*/; do
  name=$(basename "$d")
  short=${name#*_}   # strip owner prefix: moonbit-community_rabbita -> rabbita
  if [ -f "$d/moon.mod" ]; then
    projects+=("$name:$d")
  else
    for sub in "$d$short/" "$d"*/; do
      [ -f "${sub}moon.mod" ] || continue
      projects+=("$name:$(cd "$sub" && pwd)")
      break
    done
  fi
done
# local extras (outside the corpus clone dir)
for extra in moonbit-petgraph; do
  [ -f "/data/my/$extra/moon.mod" ] && projects+=("$extra:/data/my/$extra")
done

if [ "${#projects[@]}" -eq 0 ]; then
  echo "error: no corpus projects found in $CORPUS_DIR" >&2
  exit 2
fi

printf "%-32s %9s %7s %7s %8s  %s\n" "project" "findings" "files" "resolv" "edges" "status"
printf "%s\n" "$(printf '%0.s-' {1..80})"

for entry in "${projects[@]}"; do
  name="${entry%%:*}"
  path="${entry#*:}"
  out="$RESULTS_DIR/$name"
  mkdir -p "$out"

  # (a) security scan -> scan.json
  "$BIN" --format json "$path" > "$out/scan.json" 2>/dev/null
  # (b) type-reconstruction stats -> irstats.txt
  "$BIN" ir-stats "$path" > "$out/irstats.txt" 2>/dev/null
  # (c) call graph -> callgraph.txt
  "$BIN" call-graph "$path" > "$out/callgraph.txt" 2>/dev/null

  findings=$(python3 -c "
import json,sys
try:
    d=json.load(open('$out/scan.json'))
    print(len(d.get('findings',[])))
except Exception:
    print(-1)
")
  files=$(python3 -c "
import json,sys
try:
    d=json.load(open('$out/scan.json'))
    print(d.get('files_scanned',-1))
except Exception:
    print(-1)
")
  resolv=$(grep -oE 'combined resolution: [0-9]+%' "$out/irstats.txt" | grep -oE '[0-9]+%' | head -1)
  edges=$(grep -oE 'edge coverage:     [0-9]+%' "$out/callgraph.txt" | grep -oE '[0-9]+%' | head -1)
  [ -z "$resolv" ] && resolv="-"
  [ -z "$edges" ] && edges="-"
  if [ "$findings" = "-1" ]; then status="ERR"; else
    if [ "$findings" = "0" ]; then status="clean"; else status="findings"; fi
  fi

  printf "%-32s %9s %7s %7s %8s  %s\n" "$name" "$findings" "$files" "$resolv" "$edges" "$status"
done

echo
echo "raw outputs: $RESULTS_DIR/<name>/{scan.json,irstats.txt,callgraph.txt}"
