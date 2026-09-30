// Source: mizchi/luna.mbt luna/src/dom/client/repair/experimental_hydrate.mbt
// Verdict: needs_review (audit_hint — unguarded .cast() on JS Any)
// data from DOM node cast to String without type check

struct JsAny {
  val : String
}

fn JsAny::cast(self : JsAny) -> String {
  self.val
}

fn get_data(node : JsAny) -> JsAny {
  node
}

pub fn get_text_content(node : JsAny) -> String {
  let data = get_data(node)
  data.cast()
}
