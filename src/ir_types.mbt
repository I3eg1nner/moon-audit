// IR type core for M1 type reconstruction spike.
// Design reference: moonbit-compiler src/core.ml (MCore) — see docs/ir/RESEARCH.md
// M1 scope: parametric-enough lattice for call-site resolution measurement.

///|
pub(all) enum IRType {
  IRUnresolved // no type info yet; M2+ shrinks these toward zero
  IRConcrete(String, Array[IRType]) // ("Request", []) / ("Array", [String])
  IRTraitObj(String) // trait object or generic-constraint receiver (M4)
  IRTypeParam(String) // in-scope generic type parameter
  IRFn // function value / closure
  IRUnit
} derive(Eq, Debug)

///|
pub fn IRType::display(self : IRType) -> String {
  match self {
    IRUnresolved => "?"
    IRConcrete(name, args) =>
      if args.length() == 0 {
        name
      } else {
        let parts : Array[String] = []
        for arg in args {
          parts.push(arg.display())
        }
        name + "[" + parts.join(", ") + "]"
      }
    IRTraitObj(t) => "trait:" + t
    IRTypeParam(p) => "T:" + p
    IRFn => "fn"
    IRUnit => "Unit"
  }
}

///|
pub fn IRType::is_concrete(self : IRType) -> Bool {
  match self {
    IRConcrete(_, _) => true
    _ => false
  }
}
