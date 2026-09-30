// Verdict: likely_false_positive
// All match branches produce constant strings — no injection

struct Response {
  mut headers : Array[(String, String)]
}

fn set_header(self : Response, key : String, value : String) -> Unit {
  self.headers.push((key, value))
}

pub enum ContentType {
  Json
  Html
  Plain
}

pub fn set_content_type(resp : Response, ct : ContentType) -> Unit {
  let value = match ct {
    Json => "application/json"
    Html => "text/html"
    Plain => "text/plain"
  }
  resp.set_header("Content-Type", value)
}
