// Source: moonbitlang/openseek desktop/frontend/github/body.mbt
// Verdict: needs_review (LLM — can't determine if body_html is pre-sanitized)
// body_html parameter passed to inner_html without visible escaping

pub fn body_view(body_html : String, source_url : String) -> String {
  let attrs = @html.Attrs::build().inner_html(
    body_html_with_absolute_links(body_html, source_url),
  )
  attrs.to_string()
}

fn body_html_with_absolute_links(html : String, source : String) -> String {
  html
}
