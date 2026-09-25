// Every production consumer shares this parser and interpolation policy.

///|
pub fn parse_source(
  source : String,
  name? : String = "",
) -> (@list.List[@syntax.Impl], Array[@basic.Report]) {
  let primary = @parser.parse_string(source, name~, parser=Handrolled)
  let selected = if primary.1.is_empty() {
    primary
  } else {
    let fallback = @parser.parse_string(source, name~, parser=MoonYacc)
    if fallback.1.is_empty() {
      fallback
    } else {
      primary
    }
  }
  let expander = InterpolationExpander::{ reports: selected.1, }
  let items = selected.0.map(fn(item) {
    @syntax.MapVisitor::visit_Impl(expander, item)
  })
  (items, expander.reports)
}

///|
priv struct InterpolationExpander {
  reports : Array[@basic.Report]
}

///|
impl @syntax.MapVisitor for InterpolationExpander with fn visit_InterpElem_Source(
  self,
  source : @tokens.InterpSource,
) -> @syntax.InterpElem {
  // Both official top-level parsers retain interpolation holes as text.
  // Parse each hole at its original position before any analysis visits it.
  let lex = @lexer.tokens_from_string(
    source.source,
    start_pos=source.loc.start,
    name=source.loc.start.fname,
    is_interpolation=true,
    comment=true,
  )
  for error in lex.errors {
    self.reports.push({
      loc: { start: error.0, end: error.1, },
      msg: "Interpolation: " + Show::to_string(error.2),
    })
  }
  let (primary, reports) = @handrolled_parser.parse_expr(lex.tokens)
  let expr = if reports.is_empty() {
    primary
  } else {
    let tokens = lex.tokens.filter(fn(token) {
      !(token.0 is NEWLINE || token.0 is COMMENT(_))
    })
    @yacc_parser.expression(tokens, initial_pos=source.loc.start) catch {
      _ => {
        for report in reports {
          self.reports.push(report)
        }
        return Source(source)
      }
    }
  }
  Expr(expr=@syntax.MapVisitor::visit_Expr(self, expr), loc=source.loc)
}
