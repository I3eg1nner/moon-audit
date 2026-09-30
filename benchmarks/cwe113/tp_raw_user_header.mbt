// Verdict: supported_concern
// User-supplied string directly used as header value without sanitization

struct Response {
  mut headers : Array[(String, String)]
}

fn set_header(self : Response, key : String, value : String) -> Unit {
  self.headers.push((key, value))
}

pub fn set_custom_header(resp : Response, user_agent : String) -> Unit {
  resp.set_header("X-Custom-Agent", user_agent)
}
