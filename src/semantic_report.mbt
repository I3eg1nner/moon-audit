// Semantic findings keep separate identities from syntax hints and baseline keys.

///|
pub fn semantic_complete(report : Json) -> Bool {
  match report {
    { "errors": Array(errors), "routes": Array(routes), .. } =>
      errors.is_empty() &&
      !routes.is_empty() &&
      routes.all(fn(route) {
        match route {
          { "result": { "status": String("complete"), .. }, .. } => true
          _ => false
        }
      })
    _ => false
  }
}

///|
pub fn semantic_findings(report : Json) -> Array[Finding] {
  let findings : Array[Finding] = []
  guard report is { "routes": Array(routes), .. } else { return findings }
  for route in routes {
    guard route
      is {
        "result": { "status": String(status), "source_paths": Array(paths), .. },
        ..
      } else {
      continue
    }
    for path in paths {
      guard path is Array(segments) else { continue }
      let trace : Array[String] = []
      for segment in segments {
        if segment is String(value) {
          trace.push(value)
        }
      }
      if trace.length() < 2 {
        continue
      }
      let position = trace[trace.length() - 2].split(":").to_array()
      if position.length() < 3 {
        continue
      }
      let file = position[:position.length() - 2]
        .to_owned()
        .map(x => x.to_owned())
        .join(":")
      let line = @string.parse_int(position[position.length() - 2]) catch {
        _ => 1
      }
      let column = @string.parse_int(position[position.length() - 1]) catch {
        _ => 1
      }
      let source = read_regular_text(file) catch { _ => "" }
      let lines = source.split("\n").to_array()
      let snippet = if line > 0 && line <= lines.length() {
        lines[line - 1].to_owned()
      } else {
        ""
      }
      let rule_id = { cwe: 79, variant: "mocket-query-html", }
      findings.push({
        rule_id,
        severity: Error,
        confidence: Medium,
        message: "Query-derived value reaches a returned HTML responder under the declared callback/model assumptions. Review output context; this does not establish browser exploitability.",
        file,
        line,
        column,
        end_line: line,
        end_column: column,
        snippet,
        fingerprint: compute_fingerprint(rule_id, snippet),
        evidence: if status == "complete" {
          "verified_dataflow"
        } else {
          "partial_dataflow"
        },
        dataflow: trace,
      })
    }
  }
  dedup_findings(findings)
}
