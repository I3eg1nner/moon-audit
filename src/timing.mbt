// T7.4 thin: stage timing for scan/ir-stats/call-graph.
// Clock: @env.now() = ms since epoch (core env, all backends).
// Recording: load_program_world stamps its internal phases into the global
// `last_timings` (repo-global pattern, cf. loop_budget); the registry
// adapter / CLI stamp analysis and output around their own work. Signatures
// unchanged — this is instrumentation, not a capability.

///|
pub(all) struct StageTimings {
  mut stages : Array[(String, UInt64)] // (stage, elapsed ms)
}

///|
pub fn StageTimings::new() -> StageTimings {
  { stages: [], }
}

///|
pub fn StageTimings::reset(self : StageTimings) -> Unit {
  self.stages.clear()
}

///|
pub fn[T] StageTimings::time(
  self : StageTimings,
  stage : String,
  f : () -> T,
) -> T {
  let t0 = @env.now()
  let r = f()
  let dt = @env.now() - t0
  self.stages.push((stage, dt))
  r
}

///|
pub fn StageTimings::record(
  self : StageTimings,
  stage : String,
  ms : UInt64,
) -> Unit {
  self.stages.push((stage, ms))
}

///|
pub fn StageTimings::render(self : StageTimings) -> String {
  if self.stages.length() == 0 {
    return "timing: (no stages recorded)"
  }
  let parts : Array[String] = []
  let mut total : UInt64 = 0
  for pair in self.stages {
    parts.push(pair.0 + "=" + pair.1.to_string() + "ms")
    total += pair.1
  }
  "timing: " + parts.join(" ") + " total=" + total.to_string() + "ms"
}

// Global record: the most recent load_program_world stages. CLIs read this
// after their own analysis stamp — single source for the --timing line.

///|
pub let last_world_timings : StageTimings = StageTimings::new()
