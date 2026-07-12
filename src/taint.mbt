// Taint analysis for tracking data flow from sources to sinks.
// Identifies user-controlled inputs (route params, query strings,
// request bodies) and tracks them through variable assignments
// and function calls to security-sensitive sinks.

///|
pub(all) enum TaintSource {
  RouteParam(String)
  QueryParam(String)
  RequestBody
  RequestHeader(String)
  WebSocketMessage
  FileUpload
  FormField(String)
}

///|
pub(all) enum TaintSink {
  HtmlOutput
  SqlQuery
  FilePathConcat
  HeaderValue
  CookieValue
  ShellCommand
  ExternJsEval
  RedirectUrl
}

///|
pub(all) struct TaintedVar {
  name : String
  source : TaintSource
  file : String
  line : Int
}

///|
pub(all) struct TaintFlow {
  source : TaintSource
  sink : TaintSink
  source_location : Location
  sink_location : Location
  path : Array[String]
}

///|
pub(all) struct Location {
  file : String
  line : Int
  column : Int
}

///|
pub(all) struct TaintState {
  tainted_vars : Map[String, TaintedVar]
  flows : Array[TaintFlow]
  current_file : String
}

///|
pub fn TaintState::new(file : String) -> TaintState {
  { tainted_vars: {}, flows: [], current_file: file }
}

///|
fn taint_source_str(src : TaintSource) -> String {
  match src {
    RouteParam(name) => "route_param:" + name
    QueryParam(name) => "query_param:" + name
    RequestBody => "request_body"
    RequestHeader(name) => "request_header:" + name
    WebSocketMessage => "websocket_message"
    FileUpload => "file_upload"
    FormField(name) => "form_field:" + name
  }
}

///|
fn taint_sink_str(sink : TaintSink) -> String {
  match sink {
    HtmlOutput => "html_output"
    SqlQuery => "sql_query"
    FilePathConcat => "file_path_concat"
    HeaderValue => "header_value"
    CookieValue => "cookie_value"
    ShellCommand => "shell_command"
    ExternJsEval => "extern_js_eval"
    RedirectUrl => "redirect_url"
  }
}

///|
pub fn TaintState::add_tainted_var(
  self : TaintState,
  name : String,
  source : TaintSource,
  line : Int,
) -> Unit {
  self.tainted_vars[name] = { name, source, file: self.current_file, line }
}

///|
pub fn TaintState::is_tainted(self : TaintState, name : String) -> Bool {
  self.tainted_vars.contains(name)
}

///|
pub fn TaintState::get_taint_source(
  self : TaintState,
  name : String,
) -> TaintSource? {
  match self.tainted_vars.get(name) {
    Some(tv) => Some(tv.source)
    None => None
  }
}

///|
pub fn TaintState::record_flow(
  self : TaintState,
  source : TaintSource,
  sink : TaintSink,
  source_line : Int,
  source_col : Int,
  sink_line : Int,
  sink_col : Int,
  path : Array[String],
) -> Unit {
  self.flows.push({
    source,
    sink,
    source_location: {
      file: self.current_file,
      line: source_line,
      column: source_col,
    },
    sink_location: {
      file: self.current_file,
      line: sink_line,
      column: sink_col,
    },
    path,
  })
}

///|
pub fn TaintState::propagate(
  self : TaintState,
  from_var : String,
  to_var : String,
  line : Int,
) -> Unit {
  match self.tainted_vars.get(from_var) {
    Some(tv) =>
      self.tainted_vars[to_var] = {
        name: to_var,
        source: tv.source,
        file: self.current_file,
        line,
      }
    None => ()
  }
}

///|
pub fn TaintState::clear_var(self : TaintState, name : String) -> Unit {
  self.tainted_vars.remove(name) |> ignore
}

///|
priv struct TaintVisitor {
  state : TaintState
}

///|
fn is_route_param_extraction(method_name : String) -> Bool {
  method_name == "param" ||
  method_name == "get_param" ||
  method_name == "route_param" ||
  method_name == "path_param"
}

///|
fn is_query_param_extraction(method_name : String) -> Bool {
  method_name == "query" ||
  method_name == "get_query" ||
  method_name == "query_param" ||
  method_name == "query_string"
}

///|
fn is_request_body_access(method_name : String) -> Bool {
  method_name == "body" ||
  method_name == "text" ||
  method_name == "json" ||
  method_name == "form" ||
  method_name == "read_body"
}

///|
fn is_header_access(method_name : String) -> Bool {
  method_name == "header" ||
  method_name == "get_header" ||
  method_name == "headers"
}

///|
fn is_html_sink_method(method_name : String) -> Bool {
  method_name == "html" ||
  method_name == "inner_html" ||
  method_name == "set_inner_html" ||
  method_name == "render_html"
}

///|
fn is_header_sink_method(method_name : String) -> Bool {
  method_name == "set_header" ||
  method_name == "add_header" ||
  method_name == "append_header"
}

///|
fn is_redirect_sink(method_name : String) -> Bool {
  method_name == "redirect" || method_name == "redirect_to"
}

///|
fn is_file_path_sink(method_name : String) -> Bool {
  method_name == "read_file" ||
  method_name == "read_file_to_string" ||
  method_name == "open" ||
  method_name == "write_file"
}

///|
fn classify_source_method(method_name : String) -> TaintSource? {
  if is_route_param_extraction(method_name) {
    Some(RouteParam(method_name))
  } else if is_query_param_extraction(method_name) {
    Some(QueryParam(method_name))
  } else if is_request_body_access(method_name) {
    Some(RequestBody)
  } else if is_header_access(method_name) {
    Some(RequestHeader(method_name))
  } else {
    None
  }
}

///|
fn classify_sink_method(method_name : String) -> TaintSink? {
  if is_html_sink_method(method_name) {
    Some(HtmlOutput)
  } else if is_header_sink_method(method_name) {
    Some(HeaderValue)
  } else if is_redirect_sink(method_name) {
    Some(RedirectUrl)
  } else if is_file_path_sink(method_name) {
    Some(FilePathConcat)
  } else {
    None
  }
}

///|
impl @syntax.IterVisitor for TaintVisitor with fn visit_Expr_DotApply(
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
      let var_name = expr_to_var_name(self)
      match var_name {
        Some(name) => {
          env.state.add_tainted_var(name + "." + mname, source, loc.start.lnum)
          env.state.add_tainted_var(name, source, loc.start.lnum)
        }
        None => ()
      }
    }
    None => ()
  }
  match classify_sink_method(mname) {
    Some(sink) =>
      for arg in args {
        match expr_to_var_name(arg.value) {
          Some(var_name) =>
            if env.state.is_tainted(var_name) {
              match env.state.get_taint_source(var_name) {
                Some(source) =>
                  env.state.record_flow(
                    source,
                    sink,
                    loc.start.lnum,
                    loc.start.column(),
                    loc.end.lnum,
                    loc.end.column(),
                    [var_name, mname],
                  )
                None => ()
              }
            }
          None => ()
        }
      }
    None => ()
  }
  env.base().visit_Expr_DotApply(self~, method_name~, args~, return_self~, loc~)
}

///|
impl @syntax.IterVisitor for TaintVisitor with fn visit_Expr_Let(
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
        Some(s) => env.state.add_tainted_var(name, s, loc.start.lnum)
        None => {
          let rhs_var = expr_to_var_name(expr)
          match rhs_var {
            Some(from) => env.state.propagate(from, name, loc.start.lnum)
            None => ()
          }
        }
      }
    }
    None => ()
  }
  env.base().visit_Expr_Let(pattern~, expr~, body~, loc~)
}

///|
impl @syntax.IterVisitor for TaintVisitor with fn visit_Expr_LetMut(
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
    Some(s) => env.state.add_tainted_var(name, s, loc.start.lnum)
    None => {
      let rhs_var = expr_to_var_name(expr)
      match rhs_var {
        Some(from) => env.state.propagate(from, name, loc.start.lnum)
        None => ()
      }
    }
  }
  env.base().visit_Expr_LetMut(binder~, ty~, expr~, body~, loc~)
}

///|
fn pattern_to_var_name(pat : @syntax.Pattern) -> String? {
  match pat {
    Var(binder) => Some(binder.name)
    _ => None
  }
}

///|
fn expr_to_source(expr : @syntax.Expr) -> TaintSource? {
  match expr {
    DotApply(method_name~, ..) => classify_source_method(method_name.name)
    Apply(func~, ..) =>
      match func {
        Ident(id~, ..) =>
          match id.name {
            Ident(name~) => classify_source_method(name)
            _ => None
          }
        _ => None
      }
    _ => None
  }
}

///|
fn expr_to_var_name(expr : @syntax.Expr) -> String? {
  match expr {
    Ident(id~, ..) =>
      match id.name {
        Ident(name~) => Some(name)
        _ => None
      }
    _ => None
  }
}

///|
pub fn run_taint_analysis(
  impls : @list.List[@syntax.Impl],
  file : String,
  _source : String,
  _imports : ImportContext,
) -> TaintState {
  let state = TaintState::new(file)
  let visitor : TaintVisitor = { state, }
  impls.each(fn(impl_) { @syntax.IterVisitor::visit_Impl(visitor, impl_) })
  state
}

///|
pub fn taint_flows_to_findings(
  flows : Array[TaintFlow],
  _severity : Severity,
) -> Array[Finding] {
  let findings : Array[Finding] = []
  for flow in flows {
    let cwe = match flow.sink {
      HtmlOutput => 79
      SqlQuery => 89
      FilePathConcat => 22
      HeaderValue => 113
      CookieValue => 614
      ShellCommand => 78
      ExternJsEval => 94
      RedirectUrl => 601
    }
    let variant = taint_sink_str(flow.sink)
    let message = "Tainted data from " +
      taint_source_str(flow.source) +
      " flows to " +
      taint_sink_str(flow.sink) +
      " without sanitization"
    let rid : RuleId = { cwe, variant }
    findings.push({
      rule_id: rid,
      severity: Error,
      confidence: Medium,
      message,
      file: flow.sink_location.file,
      line: flow.sink_location.line,
      column: flow.sink_location.column,
      end_line: flow.sink_location.line,
      end_column: flow.sink_location.column + 10,
      snippet: "",
      fingerprint: compute_fingerprint(rid, ""),
    })
  }
  findings
}

///|
pub fn format_taint_report(flows : Array[TaintFlow]) -> String {
  let buf = StringBuilder::new()
  buf.write_string("# Taint Analysis Report\n\n")
  if flows.length() == 0 {
    buf.write_string("No taint flows detected.\n")
    return buf.to_string()
  }
  buf.write_string("Found ")
  buf.write_string(flows.length().to_string())
  buf.write_string(" taint flow(s):\n\n")
  for i, flow in flows {
    buf.write_string("## Flow ")
    buf.write_string((i + 1).to_string())
    buf.write_string("\n\n")
    buf.write_string("- **Source**: ")
    buf.write_string(taint_source_str(flow.source))
    buf.write_string(" at ")
    buf.write_string(flow.source_location.file)
    buf.write_char(':')
    buf.write_string(flow.source_location.line.to_string())
    buf.write_char('\n')
    buf.write_string("- **Sink**: ")
    buf.write_string(taint_sink_str(flow.sink))
    buf.write_string(" at ")
    buf.write_string(flow.sink_location.file)
    buf.write_char(':')
    buf.write_string(flow.sink_location.line.to_string())
    buf.write_char('\n')
    if flow.path.length() > 0 {
      buf.write_string("- **Path**: ")
      for j, step in flow.path {
        if j > 0 {
          buf.write_string(" → ")
        }
        buf.write_string(step)
      }
      buf.write_char('\n')
    }
    buf.write_char('\n')
  }
  buf.to_string()
}
