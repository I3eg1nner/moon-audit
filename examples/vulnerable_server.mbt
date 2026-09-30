// Example: a small MoonBit web handler with several detectable issues.
//
// Scan with:
//   moon-audit --rule CWE-22/path-concat --rule CWE-113/crlf-injection examples/
//
// Expected: 2 findings (1x CWE-22, 1x CWE-113). The two safe functions
// should NOT trigger any findings.

struct Request {
  query : Map[String, String]
}

struct Response {
  mut headers : Array[(String, String)]
  mut body : String
}

fn set_header(self : Response, key : String, value : String) -> Unit {
  self.headers.push((key, value))
}

fn read_file(path : String) -> String {
  ignore(path)
  ""
}

// CWE-22: user-controlled input concatenated into filesystem path
pub fn serve_static(user_input : String) -> String {
  read_file("uploads/" + user_input)
}

// CWE-113: unsanitized query parameter in response header
pub fn set_download_name(req : Request, resp : Response) -> Unit {
  let filename = req.query["filename"].or("")
  resp.set_header("Content-Disposition", "attachment; filename=" + filename)
}

// Safe: constant header value, should NOT trigger CWE-113
pub fn set_json_content_type(resp : Response) -> Unit {
  resp.set_header("Content-Type", "application/json")
}

// Safe: string comparison, should NOT trigger CWE-22
pub fn is_allowed_path(path : String) -> Bool {
  path.has_suffix("/index.html") || path.has_prefix("/public/")
}
