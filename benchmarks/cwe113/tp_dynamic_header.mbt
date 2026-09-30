// Source: mizchi/luna.mbt sol/src/middleware/security_headers.mbt
// Verdict: needs_review (LLM — config field source unknown)
// Dynamic config value passed to set_header without CRLF sanitization

struct SecurityConfig {
  coop : String
  coep : String
}

struct Ctx {
  mut headers : Array[(String, String)]
}

fn set_header(self : Ctx, name : String, value : String) -> Unit {
  self.headers.push((name, value))
}

pub fn apply_headers(ctx : Ctx, config : SecurityConfig) -> Unit {
  if config.coop.length() > 0 {
    ctx.set_header("Cross-Origin-Opener-Policy", config.coop)
  }
  if config.coep.length() > 0 {
    ctx.set_header("Cross-Origin-Embedder-Policy", config.coep)
  }
}
