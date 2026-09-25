// Experimental source lowering. API models require declaration identity and
// reviewed fingerprints. The independent IR owns all propagation and overwrite.

///|
priv struct Declaration {
  file : String
  function : @syntax.FunDecl
  body : @syntax.Expr
}

///|
priv struct Candidate {
  file : String
  method_label : @syntax.Label
  arguments : @list.List[@syntax.Argument]
}

///|
priv struct Collector {
  file : String
  candidates : Array[Candidate]
  query_sites : Array[(String, @basic.Location)]
  unsupported_registrations : Array[String]
}

///|
impl @syntax.IterVisitor for Collector with fn visit_Expr_DotApply(
  env,
  self~,
  method_name~,
  args~,
  return_self~,
  loc~,
) {
  env.query_sites.push((env.file, method_name.loc))
  if method_name.name == "get" && args.length() == 2 {
    env.candidates.push({
      file: env.file,
      method_label: method_name,
      arguments: args,
    })
  }
  @syntax.IterVisitor::visit_Expr_DotApply(
    @syntax.IterVisitor::base(env),
    self~,
    method_name~,
    args~,
    return_self~,
    loc~,
  )
}

///|
impl @syntax.IterVisitor for Collector with fn visit_Expr_Apply(
  env,
  func~,
  args~,
  loc~,
) {
  env.query_sites.push((env.file, func.loc()))
  if func is Method(method_name~, ..) && method_name.name == "get" {
    env.unsupported_registrations.push(
      "unsupported_static_registration_candidate: " +
      site(env.file, method_name.loc),
    )
  }
  @syntax.IterVisitor::visit_Expr_Apply(
    @syntax.IterVisitor::base(env),
    func~,
    args~,
    loc~,
  )
}

///|
impl @syntax.IterVisitor for Collector with fn visit_Expr_Field(
  env,
  record~,
  accessor~,
  loc~,
) {
  if accessor is Label(label) {
    env.query_sites.push((env.file, label.loc))
  }
  @syntax.IterVisitor::visit_Expr_Field(
    @syntax.IterVisitor::base(env),
    record~,
    accessor~,
    loc~,
  )
}

///|
priv struct Lowerer {
  root : String
  executable : String
  home : String?
  declarations : Map[String, Declaration]
  functions : Map[String, @ir.Function]
  bindings : Map[String, (String, String)]
  failed_bindings : Map[String, String]
  packages : Map[String, Bool]
  mut first_query : Bool
  mut queries : Int
  mut next : Int
}

///|
fn site(file : String, loc : @basic.Location) -> String {
  file + ":" + loc.start.lnum.to_string() + ":" + loc.start.column().to_string()
}

///|
fn fresh(ctx : Lowerer) -> Int {
  ctx.next += 1
  ctx.next
}

///|
async fn bind(
  ctx : Lowerer,
  file : String,
  loc : @basic.Location,
) -> (String, String) {
  let key = site(file, loc)
  if ctx.bindings.get(key) is Some(value) {
    return value
  }
  if ctx.failed_bindings.get(key) is Some(reason) {
    fail(reason)
  }
  ctx.queries += 1
  if ctx.queries > 256 {
    fail("binding_budget_exhausted")
  }
  let value = @project.definition(
    ctx.root,
    ctx.executable,
    ctx.home,
    file,
    loc.start.lnum,
    loc.start.column(),
    ctx.first_query,
  )
  ctx.first_query = false
  match value {
    [{ "path": String(path), "range": String(range), .. }] => {
      let result = (@project.absolute(path), range)
      ctx.bindings[key] = result
      result
    }
    _ => fail("binding_not_unique: " + key)
  }
}

///|
fn hash(path : String) -> String raise {
  @crypto.bytes_to_hex_string(@crypto.sha256(@fs.read_file_to_bytes(path)))
}

///|
fn model(ctx : Lowerer, binding : (String, String)) -> String {
  let (path, range) = binding
  let name = @path.Path(path).basename().to_owned()
  let candidates = model_declarations()
  for (file, expected_range, digest, kind) in candidates {
    if file == name && expected_range == range {
      if (hash(path) catch { _ => "" }) != digest {
        return "model_mismatch"
      }
      if kind == "lookup" || kind == "default" {
        if !path.contains("/lib/core/builtin/") {
          return ""
        }
      } else {
        let directory = @path.Path(path).dirname().0
        let valid = match ctx.packages.get(directory) {
          Some(valid) => valid
          None => {
            let valid = if kind == "markdown" {
              verify_cmark_package(directory)
            } else {
              verify_mocket_package(directory)
            }
            ctx.packages[directory] = valid
            valid
          }
        }
        if !valid {
          return "model_mismatch"
        }
      }
      return kind
    }
  }
  ""
}

///|
fn variable(expr : @syntax.Expr) -> String? {
  match expr {
    Ident(id={ name: Ident(name~), .. }, ..) => Some(name)
    _ => None
  }
}

///|
async fn lower_function(ctx : Lowerer, id : String) -> Unit {
  if ctx.functions.contains(id) {
    return
  }
  let decl = match ctx.declarations.get(id) {
    Some(decl) => decl
    None => fail("unmodeled_external_call: " + id)
  }
  if decl.function.is_async is Some(_) ||
    !decl.function.quantifiers.is_empty() ||
    decl.function.type_name is Some(_) {
    fail("unsupported_helper_semantics: " + id)
  }
  match decl.function.error_type {
    NoErrorType => ()
    _ => fail("unsupported_helper_error: " + id)
  }
  let env : Map[String, Int] = Map([])
  let params : Array[Int] = []
  for parameter in decl.function.decl_params.unwrap_or(@list.empty()) {
    match parameter {
      Positional(binder~, ..) => {
        let id = fresh(ctx)
        params.push(id)
        env[binder.name] = id
      }
      _ => fail("unsupported_helper_parameter")
    }
  }
  let operations : Array[@ir.Op] = []
  ctx.functions[id] = { id, parameters: params, operations, }
  let result = lower(ctx, decl.file, decl.body, env, operations)
  operations.push(Return(result))
}

///|
async fn call(
  ctx : Lowerer,
  file : String,
  loc : @basic.Location,
  callable : @basic.Location,
  arguments : Array[Int],
  operations : Array[@ir.Op],
) -> Int {
  let binding = bind(ctx, file, callable)
  let kind = model(ctx, binding)
  let dest = fresh(ctx)
  let where_ = site(file, loc)
  match (kind, arguments) {
    ("model_mismatch", _) => fail("model_mismatch: " + where_)
    ("query", [request]) => operations.push(Query(dest, request, where_))
    ("lookup", [container, key]) =>
      operations.push(Lookup(dest, container, key))
    ("default", [optional, fallback]) =>
      operations.push(Default(dest, optional, fallback))
    ("escape", [value]) => operations.push(EscapeHtmlText(dest, value))
    ("html", [value]) => operations.push(Response(dest, value, true, where_))
    ("text", [value]) => operations.push(Response(dest, value, false, where_))
    ("", _) => {
      let start = binding.1.split("-").to_array()[0].to_owned()
      let id = binding.0 + ":" + start
      lower_function(ctx, id)
      operations.push(Call(dest, id, arguments, where_))
    }
    _ => fail("unsupported_model_arguments: " + where_)
  }
  dest
}

///|
async fn lower(
  ctx : Lowerer,
  file : String,
  expr : @syntax.Expr,
  env : Map[String, Int],
  operations : Array[@ir.Op],
) -> Int {
  if ctx.next > 10000 {
    fail("lowering_budget_exhausted")
  }
  match expr {
    Constant(c=String(value), ..) => {
      let dest = fresh(ctx)
      operations.push(Literal(dest, value))
      dest
    }
    Ident(..) => {
      let name = variable(expr).unwrap_or("")
      let source = match env.get(name) {
        Some(source) => source
        None => fail("unknown_or_captured_value: " + name)
      }
      let dest = fresh(ctx)
      operations.push(Copy(dest, source))
      dest
    }
    Group(expr~, ..) | Constraint(expr~, ..) =>
      lower(ctx, file, expr, env, operations)
    Let(pattern~, expr~, body~, ..) => {
      let value = lower(ctx, file, expr, env, operations)
      let nested : Map[String, Int] = Map([])
      for name, id in env {
        nested[name] = id
      }
      match pattern {
        Var(binder) | Constraint(pat=Var(binder), ..) =>
          nested[binder.name] = value
        Any(..) => ()
        _ => fail("unsupported_local_pattern")
      }
      lower(ctx, file, body, nested, operations)
    }
    LetMut(binder~, expr~, body~, ..) => {
      let value = lower(ctx, file, expr, env, operations)
      let nested : Map[String, Int] = Map([])
      for name, id in env {
        nested[name] = id
      }
      nested[binder.name] = value
      lower(ctx, file, body, nested, operations)
    }
    Sequence(exprs~, last_expr~, ..) => {
      for expr in exprs {
        ignore(lower(ctx, file, expr, env, operations))
      }
      lower(ctx, file, last_expr, env, operations)
    }
    Assign(var_={ name: Ident(name~), .. }, expr~, augmented_by=None, ..) => {
      let value = lower(ctx, file, expr, env, operations)
      let slot = match env.get(name) {
        Some(slot) => slot
        None => fail("assignment_binding_missing")
      }
      operations.push(Copy(slot, value))
      value
    }
    Field(record~, accessor=Label(label), ..) => {
      let source = lower(ctx, file, record, env, operations)
      let target = bind(ctx, file, label.loc)
      if model(ctx, target) != "request" {
        fail("unsupported_field")
      }
      let dest = fresh(ctx)
      operations.push(Request(dest, source))
      dest
    }
    DotApply(self=receiver, method_name~, args~, return_self=false, loc~) => {
      let values = [lower(ctx, file, receiver, env, operations)]
      for arg in args {
        if !(arg.kind is Positional) {
          fail("unsupported_argument_kind")
        }
        values.push(lower(ctx, file, arg.value, env, operations))
      }
      call(ctx, file, loc, method_name.loc, values, operations)
    }
    Apply(func~, args~, loc~) => {
      let values : Array[Int] = []
      for arg in args {
        if !(arg.kind is Positional) {
          fail("unsupported_argument_kind")
        }
        values.push(lower(ctx, file, arg.value, env, operations))
      }
      call(ctx, file, loc, func.loc(), values, operations)
    }
    TryOperator(body=Apply(func~, args~, ..), kind=Exclamation, loc~, ..) => {
      let binding = bind(ctx, file, func.loc())
      if model(ctx, binding) != "markdown" {
        fail("unsupported_terminating_call")
      }
      let mut safe = true
      let mut input : Int? = None
      for arg in args {
        match arg.kind {
          Positional => {
            if input is Some(_) {
              fail("unsupported_markdown_arguments")
            }
            input = Some(lower(ctx, file, arg.value, env, operations))
          }
          Labelled(label) =>
            match (label.name, arg.value) {
              ("safe", Constant(c=Bool(value), ..)) => safe = value
              ("strict", Constant(c=Bool(true), ..))
              | ("backend_blocks", Constant(c=Bool(false), ..)) => ()
              _ => fail("unsupported_markdown_options")
            }
          _ => fail("unsupported_markdown_arguments")
        }
      }
      let input = match input {
        Some(value) => value
        None => fail("missing_markdown_input")
      }
      let dest = fresh(ctx)
      operations.push(RenderMarkdown(dest, input, safe, site(file, loc)))
      dest
    }
    Interp(elems~, ..) => {
      let parts : Array[Int] = []
      for elem in elems {
        match elem {
          Literal(repr~, ..) => {
            if repr.contains("\\") {
              fail("unsupported_escaped_interpolation_literal")
            }
            let dest = fresh(ctx)
            operations.push(Literal(dest, repr))
            parts.push(dest)
          }
          Expr(expr~, ..) => parts.push(lower(ctx, file, expr, env, operations))
          _ => fail("unsupported_interpolation")
        }
      }
      let dest = fresh(ctx)
      operations.push(Concat(dest, parts))
      dest
    }
    Return(return_value=Some(value), ..) => {
      let id = lower(ctx, file, value, env, operations)
      operations.push(Return(id))
      id
    }
    Loop(..) => fail("unsupported_legacy_loop: " + site(file, expr.loc()))
    TryOperator(kind=Question, ..) =>
      fail("unsupported_legacy_try_question: " + site(file, expr.loc()))
    _ => fail("unsupported_semantics: " + site(file, expr.loc()))
  }
}

///|
pub async fn analyze(
  root : String,
  executable : String,
  home : String?,
  files : Array[String],
) -> Json {
  let declarations : Map[String, Declaration] = Map([])
  let candidates : Array[Candidate] = []
  let query_sites : Array[(String, @basic.Location)] = []
  let errors : Array[String] = []
  for file in files {
    if file.has_suffix("_test.mbt") || file.has_suffix("_wbtest.mbt") {
      continue
    }
    let source = @fs.read_file_to_string(file) catch {
      _ => {
        errors.push("read_failed: " + file)
        continue
      }
    }
    let (items, reports) = @source_parser.parse_source(source, name=file)
    if !reports.is_empty() {
      errors.push("parser_rejected: " + file)
      continue
    }
    let visitor = Collector::{
      file,
      candidates,
      query_sites,
      unsupported_registrations: errors,
    }
    for item in items {
      match item {
        TopFuncDef(fun_decl~, decl_body=DeclBody(expr~), where_clause=None, ..) =>
          declarations[site(file, fun_decl.name.loc)] = {
            file,
            function: fun_decl,
            body: expr,
          }
        _ => ()
      }
      @syntax.IterVisitor::visit_Impl(visitor, item)
    }
  }
  let ctx = Lowerer::{
    root,
    executable,
    home,
    declarations,
    functions: Map([]),
    bindings: Map([]),
    packages: Map([]),
    failed_bindings: Map([]),
    first_query: true,
    queries: 0,
    next: 0,
  }
  // The first query prepares official metadata. Subsequent independent lookups
  // read the same frozen metadata, with at most four compiler clients in flight.
  if !candidates.is_empty() {
    let candidate = candidates[0]
    let first_binding = bind(ctx, candidate.file, candidate.method_label.loc) catch {
      _ => ("", "")
    }
    ctx.first_query = false
    let unique : Map[String, (String, @basic.Location)] = Map([])
    for (file, loc) in query_sites {
      unique[site(file, loc)] = (file, loc)
    }
    let sites = unique.values().to_array()
    if sites.length() > 256 {
      errors.push("binding_budget_exhausted")
    } else if model(ctx, first_binding) == "route" {
      let mut offset = 0
      while offset < sites.length() {
        let end = Int::min(offset + 4, sites.length())
        @async.with_task_group(group => {
          let tasks = sites[offset:end]
            .to_owned()
            .map(fn(pair) {
              group.spawn(() => {
                ignore(
                  bind(ctx, pair.0, pair.1) catch {
                    e => {
                      ctx.failed_bindings[site(pair.0, pair.1)] = e.to_string()
                      ("", "")
                    }
                  },
                )
              })
            })
          for task in tasks {
            task.wait()
          }
        })
        offset = end
      }
    }
  }
  let routes : Array[Json] = []
  for candidate in candidates {
    let id = site(candidate.file, candidate.method_label.loc)
    let binding = bind(ctx, candidate.file, candidate.method_label.loc) catch {
      e => {
        errors.push("binding_unavailable: " + id + ": " + e.to_string())
        continue
      }
    }
    if model(ctx, binding) != "route" {
      errors.push("unmodeled_registration_or_model_mismatch: " + id)
      continue
    }
    let arguments = candidate.arguments.to_array()
    let result : Json = try {
      guard arguments[0].value is Constant(c=String(route_path), ..) else {
        fail("dynamic_route_path")
      }
      guard arguments[1].value is Function(func~, ..) else {
        fail("unsupported_route_callback")
      }
      guard func.parameters.to_array() is [Positional(binder~, ..)] else {
        fail("unsupported_route_parameters")
      }
      let parameter = fresh(ctx)
      let operations : Array[@ir.Op] = []
      let env : Map[String, Int] = Map([(binder.name, parameter)])
      let returned = lower(ctx, candidate.file, func.body, env, operations)
      operations.push(Return(returned))
      ctx.functions[id] = { id, parameters: [parameter], operations, }
      let functions = ctx.functions.values().to_array()
      let result = @ir.analyze(functions, id)
      {
        "entry": Json::string(id),
        "result": result.to_json(),
        "route": Json::string(route_path),
      }
    } catch {
      e =>
        {
          "entry": Json::string(id),
          "status": Json::string("incomplete"),
          "reason": Json::string(e.to_string()),
        }
    }
    routes.push(result)
  }
  let bindings : Array[Json] = []
  let query_keys = ctx.bindings.keys().to_array()
  query_keys.sort_by(String::lexical_compare)
  for query in query_keys {
    let binding = ctx.bindings[query]
    bindings.push({
      "query": Json::string(query),
      "definition": Json::string(binding.0),
      "range": Json::string(binding.1),
    })
  }
  {
    "models": model_manifest(),
    "coverage_status": Json::string("restricted_experiment"),
    "schema": Json::string("moon-audit.experimental-security-ir.v1"),
    "production_ready": Json::boolean(false),
    "entry_scope": Json::string(
      "only two-positional-argument .get literal-route inline-callback declarations; registration invocation and unchanged responder middleware/content-type behavior are preconditions; other registration forms are not covered",
    ),
    "functions": ctx.functions.values().to_array().to_json(),
    "binding_queries": Json::number(ctx.queries.to_double()),
    "routes": Json::array(routes),
    "errors": Json::array(errors.map(Json::string)),
    "bindings": Json::array(bindings),
  }
}
