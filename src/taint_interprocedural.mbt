// Inter-procedural taint analysis: tracks data flow across function boundaries.
// Phase 1: Text-based function summary collection (which params flow to sinks)
// Phase 2: AST-based call-site checking (tainted args matched against summaries)

///|
pub(all) struct FuncTaintSummary {
  name : String
  file : String
  line : Int
  params : Array[String]
  param_sinks : Map[String, Array[TaintSink]]
  // P3: params whose taint flows into the return value
  ret_from : Array[String]
  // P3: field-write side effects — param r -> [(field, source-param)]
  // (approximation: field name only, no alias/handler precision)
  field_taint : Map[String, Array[(String, String)]]
  // M4-lite: conditional field sinks — (param, field) pairs where the
  // function reads `param.field` into a header sink; the CALLER confirms
  // via the bounded heap model (alloc-site field facts) before reporting
  param_field_sinks : Array[(String, String)]
}

///|
pub(all) struct InterProceduralContext {
  summaries : Map[String, FuncTaintSummary]
  // T4.2: cyclic SCCs that exhausted their convergence budget (|SCC|+2
  // sweeps) — disclosed in analysis-scope, never silently truncated
  mut not_converged : Int
}

///|
pub fn InterProceduralContext::new() -> InterProceduralContext {
  { summaries: Map([]), not_converged: 0, }
}

///|
priv struct IPFuncSig {
  name : String
  params : Array[String]
  line : Int
}

// ── Phase 1: Function summary collection ──

///|
pub fn collect_func_summaries(
  source : String,
  file : String,
  ctx : InterProceduralContext,
) -> Unit {
  let sigs = ip_extract_func_sigs(source)
  for sig in sigs {
    let body = ip_extract_func_body(source, sig.line)
    if body.length() > 0 {
      let summary = ip_build_summary(sig, file, body)
      if summary.param_sinks.length() > 0 {
        ctx.summaries[summary.name] = summary
      }
    }
  }
}

///|
fn ip_extract_func_sigs(source : String) -> Array[IPFuncSig] {
  let results : Array[IPFuncSig] = []
  let mut line_num = 0
  for line in source.split("\n") {
    line_num += 1
    let owned = line.to_owned()
    let trimmed = owned.trim()
    if trimmed.has_prefix("//") || trimmed.length() == 0 {
      continue
    }
    let trimmed_s = trimmed.to_owned()
    if !ip_has_fn_keyword(trimmed_s) || trimmed_s.has_prefix("extern") {
      continue
    }
    let name = ip_get_fn_name(trimmed_s)
    if name.length() == 0 || !trimmed_s.contains("(") {
      continue
    }
    let paren_content = ip_between_parens(trimmed_s)
    let params = ip_parse_params(paren_content)
    if params.length() > 0 {
      results.push({ name, params, line: line_num, })
    }
  }
  results
}

///|
fn ip_has_fn_keyword(line : String) -> Bool {
  line.has_prefix("fn ") ||
  line.has_prefix("pub fn ") ||
  line.has_prefix("priv fn ") ||
  line.has_prefix("pub(all) fn ")
}

///|
fn ip_get_fn_name(line : String) -> String {
  let pos = ip_indexof_str(line, "fn ", 0)
  if pos < 0 {
    return ""
  }
  let rest = line[pos + 3:].to_owned().trim().to_owned()
  ip_extract_ident(rest)
}

///|
fn ip_extract_ident(s : String) -> String {
  let buf = StringBuilder()
  for i = 0; i < s.length(); i = i + 1 {
    if ip_is_ident_ch(s[i]) {
      buf.write_string(s[i].to_int().unsafe_to_char().to_string())
    } else {
      break
    }
  }
  buf.to_string()
}

///|
fn ip_is_ident_ch(c : UInt16) -> Bool {
  (c >= char16('a') && c <= char16('z')) ||
  (c >= char16('A') && c <= char16('Z')) ||
  (c >= char16('0') && c <= char16('9')) ||
  c == char16('_')
}

///|
fn ip_between_parens(s : String) -> String {
  let open = char16('(')
  let close = char16(')')
  let mut start = -1
  let mut depth = 0
  for i = 0; i < s.length(); i = i + 1 {
    if s[i] == open {
      if depth == 0 {
        start = i
      }
      depth += 1
    } else if s[i] == close {
      depth -= 1
      if depth == 0 && start >= 0 {
        return s[start + 1:i].to_owned()
      }
    }
  }
  ""
}

///|
fn ip_parse_params(params_str : String) -> Array[String] {
  let names : Array[String] = []
  if params_str.length() == 0 {
    return names
  }
  for part in params_str.split(",") {
    let seg = part.to_owned().trim()
    if seg.length() == 0 || seg.has_prefix("self") {
      continue
    }
    let clean = if seg.has_prefix("~") {
      seg[1:].to_owned()
    } else {
      seg.to_owned()
    }
    let name = ip_extract_ident(clean)
    if name.length() > 0 && name != "self" {
      names.push(name)
    }
  }
  names
}

///|
fn ip_extract_func_body(source : String, start_line : Int) -> String {
  let lines : Array[String] = []
  for line in source.split("\n") {
    lines.push(line.to_owned())
  }
  let brace_open = char16('{')
  let brace_close = char16('}')
  let mut depth = 0
  let mut started = false
  let buf = StringBuilder()
  let from = if start_line - 1 >= 0 { start_line - 1 } else { 0 }
  for i = from; i < lines.length(); i = i + 1 {
    let line = lines[i]
    for j = 0; j < line.length(); j = j + 1 {
      if line[j] == brace_open {
        depth += 1
        if !started {
          started = true
        }
      } else if line[j] == brace_close {
        depth -= 1
        if started && depth == 0 {
          return buf.to_string()
        }
      }
    }
    if started {
      buf.write_string(line)
      buf.write_char('\n')
    }
  }
  buf.to_string()
}

///|
fn ip_build_summary(
  sig : IPFuncSig,
  file : String,
  body : String,
) -> FuncTaintSummary {
  let param_sinks : Map[String, Array[TaintSink]] = Map([])
  for param in sig.params {
    let all_names = ip_find_anamees(body, param)
    let sinks : Array[TaintSink] = []
    for name in all_names {
      let found = ip_find_sinks_for_var(body, name)
      for s in found {
        if !ip_has_sink(sinks, s) {
          sinks.push(s)
        }
      }
    }
    if sinks.length() > 0 {
      param_sinks[param] = sinks
    }
  }
  {
    name: sig.name,
    file,
    line: sig.line,
    params: sig.params,
    param_sinks,
    ret_from: [],
    field_taint: Map([]),
    param_field_sinks: [],
  }
}

///|
fn ip_find_anamees(body : String, param : String) -> Array[String] {
  let names : Array[String] = [param]
  let patterns = ["let ", "let mut "]
  for pat in patterns {
    let mut pos = 0
    while pos < body.length() {
      let idx = ip_indexof_str(body, pat, pos)
      if idx < 0 {
        break
      }
      let rest_start = idx + pat.length()
      if rest_start >= body.length() {
        break
      }
      let after = body[rest_start:].to_owned()
      let aname = ip_extract_ident(after)
      if aname.length() > 0 {
        let eq_pos = find_char_in_str(after, '=')
        if eq_pos > 0 && eq_pos + 1 < after.length() {
          let rhs = after[eq_pos + 1:].to_owned().trim().to_owned()
          if ip_starts_with_word(rhs, param) {
            names.push(aname)
          }
        }
      }
      pos = idx + 1
    }
  }
  names
}

///|
fn ip_starts_with_word(s : String, word : String) -> Bool {
  if !s.has_prefix(word) {
    return false
  }
  if word.length() >= s.length() {
    return true
  }
  !ip_is_ident_ch(s[word.length()])
}

///|
fn ip_find_sinks_for_var(body : String, var_name : String) -> Array[TaintSink] {
  let sinks : Array[TaintSink] = []
  if ip_var_in_call_args(body, var_name, "set_header") ||
    ip_var_in_call_args(body, var_name, "add_header") ||
    ip_var_in_call_args(body, var_name, "append_header") ||
    ip_var_in_call_args(body, var_name, "set_response_header") {
    sinks.push(HeaderValue)
  }
  if ip_var_in_call_args(body, var_name, "html") ||
    ip_var_in_call_args(body, var_name, "inner_html") ||
    ip_var_in_call_args(body, var_name, "set_inner_html") ||
    ip_var_in_call_args(body, var_name, "render_html") {
    sinks.push(HtmlOutput)
  }
  if ip_var_in_call_args(body, var_name, "redirect") ||
    ip_var_in_call_args(body, var_name, "redirect_to") {
    sinks.push(RedirectUrl)
  }
  if ip_var_in_call_args(body, var_name, "read_file") ||
    ip_var_in_call_args(body, var_name, "write_file") ||
    ip_var_in_call_args(body, var_name, "read_file_to_string") ||
    ip_var_in_call_args(body, var_name, "open") {
    sinks.push(FilePathConcat)
  }
  sinks
}

///|
fn ip_var_in_call_args(body : String, var_name : String, meth : String) -> Bool {
  let search = meth + "("
  let mut pos = 0
  while pos < body.length() {
    let idx = ip_indexof_str(body, search, pos)
    if idx < 0 {
      return false
    }
    let args_start = idx + search.length()
    let args_end = ip_find_close_paren(body, args_start)
    if args_end > args_start {
      let args_text = body[args_start:args_end].to_owned()
      if ip_has_word(args_text, var_name) {
        return true
      }
    }
    pos = idx + 1
  }
  false
}

///|
fn ip_has_sink(sinks : Array[TaintSink], s : TaintSink) -> Bool {
  let s_str = taint_sink_str(s)
  sinks.iter().any(fn(existing) { taint_sink_str(existing) == s_str })
}

// ── Phase 2: Cross-function taint checking ──

///|
priv struct CrossFuncVisitor {
  findings : Array[Finding]
  file : String
  source : String
  ctx : InterProceduralContext
  tainted_vars : Map[String, TaintSource]
}

///|
pub fn run_cross_func_taint(
  impls : @list.List[@syntax.Impl],
  file : String,
  source : String,
  findings : Array[Finding],
  ctx : InterProceduralContext,
  _imports : ImportContext,
) -> Unit {
  impls.each(fn(impl_) {
    let visitor : CrossFuncVisitor = {
      findings,
      file,
      source,
      ctx,
      tainted_vars: Map([]),
    }
    @syntax.IterVisitor::visit_Impl(visitor, impl_)
  })
}

///|
fn ip_sink_to_rule_id(sink : TaintSink) -> RuleId {
  let cwe = match sink {
    HtmlOutput => 79
    SqlQuery => 89
    FilePathConcat => 22
    HeaderValue => 113
    CookieValue => 614
    ShellCommand => 78
    ExternJsEval => 94
    RedirectUrl => 601
  }
  { cwe, variant: "taint-" + taint_sink_str(sink), }
}

///|
impl @syntax.IterVisitor for CrossFuncVisitor with fn visit_Expr_DotApply(
  env,
  self~,
  method_name~,
  args~,
  return_self~,
  loc~,
) {
  let mname = method_name.name
  match classify_source_method(mname) {
    Some(source) => {
      let receiver = expr_to_var_name(self)
      match receiver {
        Some(name) => {
          env.tainted_vars[name + "." + mname] = source
          env.tainted_vars[name] = source
        }
        None => ()
      }
    }
    None => ()
  }
  @syntax.IterVisitor::base(env).visit_Expr_DotApply(
    self~,
    method_name~,
    args~,
    return_self~,
    loc~,
  )
}

///|
impl @syntax.IterVisitor for CrossFuncVisitor with fn visit_Expr_Apply(
  env,
  func~,
  args~,
  loc~,
) {
  let callee_name = match func {
    Ident(id~, ..) =>
      match id.name {
        Ident(name~) => name
        Dot(id~, ..) => id
      }
    Method(method_name~, ..) => method_name.name
    _ => ""
  }
  if callee_name.length() > 0 {
    match env.ctx.summaries.get(callee_name) {
      Some(summary) => ip_check_call_site(env, summary, args, loc)
      None => ()
    }
  }
  @syntax.IterVisitor::base(env).visit_Expr_Apply(func~, args~, loc~)
}

///|
fn ip_check_call_site(
  env : CrossFuncVisitor,
  summary : FuncTaintSummary,
  args : @list.List[@syntax.Argument],
  loc : @basic.Location,
) -> Unit {
  let mut pos_idx = 0
  for arg in args {
    let taint = ip_get_arg_taint(env, arg)
    match taint {
      Some(taint_source) => {
        let param_name = match arg.kind {
          Labelled(label) => label.name
          _ =>
            if pos_idx < summary.params.length() {
              summary.params[pos_idx]
            } else {
              ""
            }
        }
        if param_name.length() > 0 {
          match summary.param_sinks.get(param_name) {
            Some(sinks) =>
              for sink in sinks {
                env.findings.push(
                  make_finding(
                    ip_sink_to_rule_id(sink),
                    Error,
                    Medium,
                    "Tainted data from " +
                    taint_source_str(taint_source) +
                    " flows through " +
                    summary.name +
                    "() to " +
                    taint_sink_str(sink) +
                    " sink without sanitization",
                    env.file,
                    env.source,
                    loc,
                  ),
                )
              }
            None => ()
          }
        }
      }
      None => ()
    }
    match arg.kind {
      Labelled(_)
      | LabelledPun(_)
      | LabelledOption(..)
      | LabelledOptionPun(..) => ()
      _ => pos_idx += 1
    }
  }
}

///|
fn ip_get_arg_taint(
  env : CrossFuncVisitor,
  arg : @syntax.Argument,
) -> TaintSource? {
  let arg_var = expr_to_var_name(arg.value)
  match arg_var {
    Some(var_name) =>
      match env.tainted_vars.get(var_name) {
        Some(s) => Some(s)
        None => None
      }
    None => expr_to_source(arg.value)
  }
}

///|
impl @syntax.IterVisitor for CrossFuncVisitor with fn visit_Expr_Let(
  env,
  pattern~,
  expr~,
  body~,
  loc~,
) {
  let var_name = pattern_to_var_name(pattern)
  match var_name {
    Some(name) => {
      let source = expr_to_source(expr)
      match source {
        Some(s) => env.tainted_vars[name] = s
        None => {
          let rhs_var = expr_to_var_name(expr)
          match rhs_var {
            Some(from) =>
              match env.tainted_vars.get(from) {
                Some(s) => env.tainted_vars[name] = s
                None => ()
              }
            None => ()
          }
        }
      }
    }
    None => ()
  }
  @syntax.IterVisitor::base(env).visit_Expr_Let(pattern~, expr~, body~, loc~)
}

///|
impl @syntax.IterVisitor for CrossFuncVisitor with fn visit_Expr_LetMut(
  env,
  binder~,
  ty~,
  expr~,
  body~,
  loc~,
) {
  let name = binder.name
  let source = expr_to_source(expr)
  match source {
    Some(s) => env.tainted_vars[name] = s
    None => {
      let rhs_var = expr_to_var_name(expr)
      match rhs_var {
        Some(from) =>
          match env.tainted_vars.get(from) {
            Some(s) => env.tainted_vars[name] = s
            None => ()
          }
        None => ()
      }
    }
  }
  @syntax.IterVisitor::base(env).visit_Expr_LetMut(
    binder~,
    ty~,
    expr~,
    body~,
    loc~,
  )
}

// ── String helpers ──

///|
fn ip_indexof_str(haystack : String, needle : String, from : Int) -> Int {
  let n_len = needle.length()
  if n_len == 0 || haystack.length() < n_len {
    return -1
  }
  let limit = haystack.length() - n_len
  for i = from; i <= limit; i = i + 1 {
    let mut ok = true
    for j = 0; j < n_len; j = j + 1 {
      if haystack[i + j] != needle[j] {
        ok = false
        break
      }
    }
    if ok {
      return i
    }
  }
  -1
}

///|
fn ip_find_close_paren(s : String, from : Int) -> Int {
  let open = char16('(')
  let close = char16(')')
  let mut depth = 1
  for i = from; i < s.length(); i = i + 1 {
    if s[i] == open {
      depth += 1
    } else if s[i] == close {
      depth -= 1
      if depth == 0 {
        return i
      }
    }
  }
  -1
}

///|
fn ip_has_word(text : String, word : String) -> Bool {
  let mut pos = 0
  while pos < text.length() {
    let idx = ip_indexof_str(text, word, pos)
    if idx < 0 {
      return false
    }
    let before_ok = idx == 0 || !ip_is_ident_ch(text[idx - 1])
    let after_idx = idx + word.length()
    let after_ok = after_idx >= text.length() ||
      !ip_is_ident_ch(text[after_idx])
    if before_ok && after_ok {
      return true
    }
    pos = idx + 1
  }
  false
}
