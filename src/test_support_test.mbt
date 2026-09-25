///|
fn pjoin(base : String, seg : String) -> String {
  @path.Path(
    // OS-native path join: Windows native fs (FindFirstFileW in x/fs) is not
    // reliable with forward-slash string paths; @path.join normalizes them
    base,
  ).join(@path.Path(seg)).0
}

///|
fn test_tmp(sub : String) -> String {
  // cross-platform temp base without @sys (unavailable in lib tests):
  // try /tmp first; on Windows that fails, fall back to a relative dir
  // under the test working directory (writable in CI sandboxes)
  // side-effect-free probe: read_dir succeeds iff /tmp exists & readable
  ignore(
    @fs.read_dir("/tmp") catch {
      _ => {
        // create the fallback base once: tests only create their leaf dir
        @fs.create_dir("./moon_audit_test_tmp") catch {
          _ => ()
        }
        return pjoin("./moon_audit_test_tmp", sub)
      }
    },
  )
  pjoin("/tmp", sub)
}

///|
fn mk_finding(fp : String) -> @src.Finding {
  {
    rule_id: { cwe: 113, variant: "crlf-injection", },
    severity: Error,
    confidence: Medium,
    message: "m",
    file: "a.mbt",
    line: 1,
    column: 1,
    end_line: 1,
    end_column: 2,
    snippet: "s",
    fingerprint: fp,
    evidence: "syntax_hint",
    dataflow: [],
  }
}
