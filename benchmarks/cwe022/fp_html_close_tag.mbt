// Source: paipai-Studio/BioSeqs src/kgml.mbt, phylo_cdao.mbt
// Verdict: likely_false_positive (LLM confirmed)
// HTML/XML close tag building, not filesystem path

pub fn build_close_tag(elem_name : String) -> String {
  let close_tag = "</" + elem_name + ">"
  close_tag
}

pub fn build_template_close(name : String) -> String {
  "</template></" + name + ">"
}
