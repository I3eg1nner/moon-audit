// T0.1 helpers shared by c1..c8 case files (each case = one file; header
// comments state 期望/当前行为 and the G# gap from docs/ir/ROADMAP-T.md).
// One-command reproduction: ./run.sh (builds this project + scans each case)

///|
fn input() -> String {
  "dirty"
}
