// Verdict: likely_false_positive
// Integer interpolation in header value — no CRLF risk

struct Response {
  mut headers : Array[(String, String)]
}

fn set_header(self : Response, key : String, value : String) -> Unit {
  self.headers.push((key, value))
}

pub fn set_cache_control(resp : Response, max_age : Int) -> Unit {
  resp.set_header("Cache-Control", "max-age=\{max_age}")
}
