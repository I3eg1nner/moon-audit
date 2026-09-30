// Source: mizchi/llm src/skills_loader.mbt
// Verdict: supported_concern
// User-supplied skill name concatenated into filesystem path

fn read_file(path : String) -> String? {
  None
}

pub fn load_skill(name : String) -> String? {
  read_file("skills/" + name + "/SKILL.md")
}
