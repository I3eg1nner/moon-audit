// Synthetic case based on CWE-113 sanitization check
// Verdict: likely_false_positive
// Value sanitized via CRLF stripping before set_header

struct Ctx {
  mut headers : Array[(String, String)]
}

fn set_header(self : Ctx, name : String, value : String) -> Unit {
  self.headers.push((name, value))
}

pub fn apply_safe_header(ctx : Ctx, raw_value : String) -> Unit {
  let clean = raw_value.replace_all(old="\r", new="").replace_all(old="\n", new="")
  ctx.set_header("X-Custom", clean)
}
