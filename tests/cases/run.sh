#!/usr/bin/env bash
# T0.1 one-command reproduction of all known engine behaviors/gaps.
# Each c{1..8}_*.mbt states 期望/当前 in its header; G# maps to ROADMAP-T.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
ANALYZER="${ANALYZER:-$(cd "$HERE/../.." && pwd)/_build/native/debug/build/src/main/main.exe}"
export PATH="$HOME/.moon-latest/bin:$PATH"
export MOON_HOME="${MOON_HOME:-$HOME/.moon-latest}"
echo "== cases project compiles (repro baseline) =="
( cd "$HERE" && moon check 2>&1 | tail -1 )
echo
echo "== project scan (analyzer: $ANALYZER) =="
"$ANALYZER" "$HERE" 2>/dev/null | tail -3
echo
echo "== C8 default-param call sites enter ir-stats (T0.2(a)) =="
"$ANALYZER" ir-stats "$HERE" 2>/dev/null | grep -E "call sites|bound sites" | head -2
echo
echo "NOTE: 全量状态矩阵以仓库单测为准（t0_*/v1_* 系列）；本脚本供人工快速重现。"
