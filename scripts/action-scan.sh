#!/usr/bin/env bash
# The composite action passes user inputs through env, never through shell code.
set -euo pipefail

FORMAT="${AUDIT_FORMAT:-sarif}"
SEVERITY="${AUDIT_SEVERITY:-warning}"
UPLOAD_SARIF="${AUDIT_UPLOAD_SARIF:-true}"
FAIL_ON_FINDINGS="${AUDIT_FAIL_ON_FINDINGS:-false}"
case "$FORMAT" in text|json|sarif) ;; *) echo "error: invalid format: $FORMAT" >&2; exit 2 ;; esac
case "$SEVERITY" in error|warning|info) ;; *) echo "error: invalid severity: $SEVERITY" >&2; exit 2 ;; esac
case "$UPLOAD_SARIF:$FAIL_ON_FINDINGS" in true:true|true:false|false:true|false:false) ;; *) echo 'error: boolean inputs must be true or false' >&2; exit 2 ;; esac

cd "$GITHUB_ACTION_PATH"
SCAN_PATH="${AUDIT_PATH:-.}"
if [[ "$SCAN_PATH" != /* ]]; then SCAN_PATH="$GITHUB_WORKSPACE/$SCAN_PATH"; fi
EXT="$FORMAT"
[ "$FORMAT" != text ] || EXT=txt
REPORT_FILE="$GITHUB_WORKSPACE/moon-audit-results.$EXT"
WORK_DIR="$(mktemp -d "$GITHUB_WORKSPACE/.moon-audit.XXXXXX")"
trap 'rm -rf "$WORK_DIR"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Stage on the destination filesystem so publication is atomic. A directory
# target must fail instead of accepting a report inside an old artifact folder.
publish_report() {
  python3 - "$1" "$2" <<'PYTHON'
import os
import sys

try:
    os.replace(sys.argv[1], sys.argv[2])
except OSError as error:
    sys.exit(f"error: cannot publish report: {error}")
PYTHON
}

# Validate the newly generated report before replacing a previous artifact.
moon run src/main -- --format "$FORMAT" --severity "$SEVERITY" -o "$WORK_DIR/report" "$SCAN_PATH"
COUNT=$(python3 "$GITHUB_ACTION_PATH/scripts/count-findings.py" "$FORMAT" "$WORK_DIR/report")
publish_report "$WORK_DIR/report" "$REPORT_FILE"
printf 'report-file=%s\nfindings-count=%s\n' "$REPORT_FILE" "$COUNT" >> "$GITHUB_OUTPUT"
echo "moon-audit: detected $COUNT finding(s)"

if [ "$UPLOAD_SARIF" = true ]; then
  SARIF_FILE="$GITHUB_WORKSPACE/moon-audit-results.sarif"
  if [ "$FORMAT" != sarif ]; then
    moon run src/main -- --format sarif --severity "$SEVERITY" -o "$WORK_DIR/sarif" "$SCAN_PATH"
    python3 "$GITHUB_ACTION_PATH/scripts/count-findings.py" sarif "$WORK_DIR/sarif" > /dev/null
    publish_report "$WORK_DIR/sarif" "$SARIF_FILE"
  fi
  printf 'sarif-file=%s\n' "$SARIF_FILE" >> "$GITHUB_OUTPUT"
fi

if [ "$FAIL_ON_FINDINGS" = true ] && [ "$COUNT" -gt 0 ]; then
  echo "::error::moon-audit detected $COUNT security finding(s)"
  exit 1
fi
