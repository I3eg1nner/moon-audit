// P0: summary identity collision — First::pick and Second::pick have
// same method name but different semantics (First returns arg0, Second
// returns arg1). Before the fix, the summary lookup fell back from
// "Second::pick" to short name "pick" which matched First::pick's
// summary, causing: line 9 MISS (Second::pick("safe", input()) should
// alert because Second::pick returns arg1=input()) and line 15 FALSE
// POSITIVE (Second::pick(input(), "safe") should NOT alert because
// Second::pick returns arg1="safe", not the tainted arg0).
//
// After the fix: summaries are keyed by "Type::method" qualified names,
// and the "Type::method → method" short-name fallback is removed.
// Uses shared taint-rules.json (source=input, sink=sink).
//
// Expected: 2 findings — line 9 (collision_should_alert) + line 12
// (unique_should_alert). Line 15 (collision_should_be_clean) is clean.
// Rename test: changing First::pick to First::pick_first must not alter
// results (implicit — the qualified key is independent of other types).

struct First {}
struct Second {}
fn First::pick(a : String, b : String) -> String { ignore(b); a }
fn Second::pick(a : String, b : String) -> String { ignore(a); b }
fn Second::pick_unique(a : String, b : String) -> String { ignore(a); b }
fn sink(value : String) -> Unit { ignore(value) }
fn collision_should_alert() -> Unit {
  sink(Second::pick("safe", input()))
}
fn unique_should_alert() -> Unit {
  sink(Second::pick_unique("safe", input()))
}
fn collision_should_be_clean() -> Unit {
  sink(Second::pick(input(), "safe"))
}
