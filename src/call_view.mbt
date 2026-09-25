// A syntax-level view of method calls. This does not prove target binding:
// DotApply has no reliable receiver type until a semantic frontend supplies it.

///|
priv enum CallForm {
  Dot
  Qualified
}

///|
priv struct SyntaxCall {
  form : CallForm
  owner : String?
  name : String
  args : @list.List[@syntax.Argument]
  loc : @basic.Location
}

///|
fn syntax_call(expr : @syntax.Expr) -> SyntaxCall? {
  match expr {
    DotApply(method_name~, args~, loc~, ..) =>
      Some({ form: Dot, owner: None, name: method_name.name, args, loc, })
    Apply(func=Method(type_name~, method_name~, ..), args~, loc~) => {
      let owner = match type_name.name {
        Ident(name~) => Some(name)
        Dot(..) => None
      }
      Some({ form: Qualified, owner, name: method_name.name, args, loc, })
    }
    _ => None
  }
}
