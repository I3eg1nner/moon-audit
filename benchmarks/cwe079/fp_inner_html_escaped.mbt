// Source: moonbitlang/openseek desktop/frontend/markdown/markdown.mbt
// Verdict: needs_review (LLM — escape_html present but template has other vars)
// inner_html with escape_html-wrapped content should ideally not trigger

fn escape_html(s : String) -> String {
  s
}

pub fn code_block_view(language : String, source : String) -> String {
  let attrs = @html.Attrs::build().inner_html(
    "<pre><code class=\"language-\{language}\">\{escape_html(source)}</code></pre>",
  )
  attrs.to_string()
}
