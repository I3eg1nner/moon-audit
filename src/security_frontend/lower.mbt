// Experimental source lowering. API models require declaration identity and
// reviewed fingerprints. The independent IR owns all propagation and overwrite.

///|
priv struct Declaration {
  file : String
  function : @syntax.FunDecl
  body : @syntax.Expr
  conditional : Bool
}

///|
priv struct Candidate {
  file : String
  method_label : @syntax.Label
  arguments : @list.List[@syntax.Argument]
  conditional : Bool
}

///|
priv struct Collector {
  file : String
  candidates : Array[Candidate]
  unsupported_registrations : Array[String]
  conditional : Bool
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
  if method_name.name == "get" && args.length() == 2 {
    env.candidates.push({
      file: env.file,
      method_label: method_name,
      arguments: args,
      conditional: env.conditional,
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
  if func is Method(method_name~, ..) && method_name.name == "get" {
    env.unsupported_registrations.push(
      (if env.conditional {
        "unsupported_conditional_compilation: "
      } else {
        "unsupported_static_registration_candidate: "
      }) +
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
// Structural lowering records only operations that it can fully represent.
// Official definitions are queried after the whole body has passed this phase.
priv enum PendingOp {
  Ready(@ir.Op)
  PendingCall(Int, @basic.Location, @basic.Location, Array[Int])
  PendingField(Int, Int, @basic.Location)
  PendingMarkdown(Int, Int, Bool, @basic.Location, @basic.Location)
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
  if ctx.queries >= 256 {
    ctx.failed_bindings[key] = "binding_budget_exhausted"
    fail("binding_budget_exhausted")
  }
  ctx.queries += 1
  let value = @project.definition(
    ctx.root,
    ctx.executable,
    ctx.home,
    file,
    loc.start.lnum,
    loc.start.column(),
    ctx.first_query,
  ) catch {
    e => {
      let reason = e.to_string()
      ctx.failed_bindings[key] = reason
      fail(reason)
    }
  }
  ctx.first_query = false
  match value {
    [{ "path": String(path), "range": String(range), .. }] => {
      let result = (@project.absolute(path), range)
      ctx.bindings[key] = result
      result
    }
    _ => {
      let reason = "binding_not_unique: " + key
      ctx.failed_bindings[key] = reason
      fail(reason)
    }
  }
}

///|
// Only reached callback/helper bodies enter this bounded prefetch. The route
// binding has already prepared official metadata before any parallel lookup.
async fn prefetch_bindings(
  ctx : Lowerer,
  file : String,
  pending : Array[PendingOp],
) -> Unit {
  let locations : Map[String, @basic.Location] = Map([])
  for operation in pending {
    let location = match operation {
      Ready(_) => continue
      PendingCall(_, _, callable, _) => callable
      PendingField(_, _, location) => location
      PendingMarkdown(_, _, _, _, callable) => callable
    }
    locations[site(file, location)] = location
  }
  let keys = locations.keys().to_array()
  keys.sort_by(String::lexical_compare)
  let sites : Array[@basic.Location] = []
  for key in keys {
    if !ctx.bindings.contains(key) && !ctx.failed_bindings.contains(key) {
      sites.push(locations[key])
    }
  }
  let mut offset = 0
  while offset < sites.length() {
    let end = Int::min(offset + 4, sites.length())
    @async.with_task_group(group => {
      let tasks = sites[offset:end]
        .to_owned()
        .map(fn(loc) {
          group.spawn(() => ignore(bind(ctx, file, loc) catch { _ => ("", "") }))
        })
      for task in tasks {
        task.wait()
      }
    })
    offset = end
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
      if kind == "lookup" || kind == "default" || kind == "string_concat" {
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
  if decl.conditional {
    fail("unsupported_conditional_compilation: " + id)
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
  let pending : Array[PendingOp] = []
  let result = lower(ctx, decl.file, decl.body, env, pending)
  pending.push(Ready(Return(result)))
  let operations : Array[@ir.Op] = []
  ctx.functions[id] = { id, parameters: params, operations, }
  resolve_operations(ctx, decl.file, pending, operations)
}

///|
async fn call(
  ctx : Lowerer,
  file : String,
  loc : @basic.Location,
  callable : @basic.Location,
  arguments : Array[Int],
  dest : Int,
  operations : Array[@ir.Op],
) -> Unit {
  let binding = bind(ctx, file, callable)
  let kind = model(ctx, binding)
  let where_ = site(file, loc)
  match (kind, arguments) {
    ("model_mismatch", _) => fail("model_mismatch: " + where_)
    ("query", [request]) => operations.push(Query(dest, request, where_))
    ("lookup", [container, key]) =>
      operations.push(Lookup(dest, container, key))
    ("default", [optional, fallback]) =>
      operations.push(Default(dest, optional, fallback))
    ("string_concat", [lhs, rhs]) => operations.push(Concat(dest, [lhs, rhs]))
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
}

///|
async fn resolve_operations(
  ctx : Lowerer,
  file : String,
  pending : Array[PendingOp],
  operations : Array[@ir.Op],
) -> Unit {
  prefetch_bindings(ctx, file, pending)
  for operation in pending {
    match operation {
      Ready(operation) => operations.push(operation)
      PendingCall(dest, location, callable, arguments) =>
        call(ctx, file, location, callable, arguments, dest, operations)
      PendingField(dest, source, location) => {
        let binding = bind(ctx, file, location)
        if model(ctx, binding) != "request" {
          fail("unsupported_field")
        }
        operations.push(Request(dest, source))
      }
      PendingMarkdown(dest, input, safe, location, callable) => {
        let binding = bind(ctx, file, callable)
        if model(ctx, binding) != "markdown" {
          fail("unsupported_terminating_call")
        }
        operations.push(RenderMarkdown(dest, input, safe, site(file, location)))
      }
    }
  }
}

///|
fn plan_call(
  ctx : Lowerer,
  loc : @basic.Location,
  callable : @basic.Location,
  arguments : Array[Int],
  operations : Array[PendingOp],
) -> Int {
  let dest = fresh(ctx)
  operations.push(PendingCall(dest, loc, callable, arguments))
  dest
}

///|
fn lower(
  ctx : Lowerer,
  file : String,
  expr : @syntax.Expr,
  env : Map[String, Int],
  operations : Array[PendingOp],
) -> Int raise {
  if ctx.next > 10000 {
    fail("lowering_budget_exhausted")
  }
  match expr {
    Constant(c=String(value), ..) => {
      let dest = fresh(ctx)
      let value = match literal_value(value) {
        Some(value) => value
        None => fail("unsupported_literal_escape: " + site(file, expr.loc()))
      }
      operations.push(Ready(Literal(dest, value)))
      dest
    }
    Ident(..) => {
      let name = variable(expr).unwrap_or("")
      let source = match env.get(name) {
        Some(source) => source
        None => fail("unknown_or_captured_value: " + name)
      }
      let dest = fresh(ctx)
      operations.push(Ready(Copy(dest, source)))
      dest
    }
    Infix(op~, lhs~, rhs~, loc~) => {
      let lhs = lower(ctx, file, lhs, env, operations)
      let rhs = lower(ctx, file, rhs, env, operations)
      plan_call(ctx, loc, op.loc, [lhs, rhs], operations)
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
      operations.push(Ready(Copy(slot, value)))
      value
    }
    Field(record~, accessor=Label(label), ..) => {
      let source = lower(ctx, file, record, env, operations)
      let dest = fresh(ctx)
      operations.push(PendingField(dest, source, label.loc))
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
      plan_call(ctx, loc, method_name.loc, values, operations)
    }
    Apply(func~, args~, loc~) => {
      let values : Array[Int] = []
      for arg in args {
        if !(arg.kind is Positional) {
          fail("unsupported_argument_kind")
        }
        values.push(lower(ctx, file, arg.value, env, operations))
      }
      plan_call(ctx, loc, func.loc(), values, operations)
    }
    TryOperator(body=Apply(func~, args~, ..), kind=Exclamation, loc~, ..) => {
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
      operations.push(PendingMarkdown(dest, input, safe, loc, func.loc()))
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
            operations.push(Ready(Literal(dest, repr)))
            parts.push(dest)
          }
          Expr(expr~, ..) => parts.push(lower(ctx, file, expr, env, operations))
          _ => fail("unsupported_interpolation")
        }
      }
      let dest = fresh(ctx)
      operations.push(Ready(Concat(dest, parts)))
      dest
    }
    Return(return_value=Some(value), ..) => {
      let id = lower(ctx, file, value, env, operations)
      operations.push(Ready(Return(id)))
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
  units : Array[@project.CompilationUnit],
) -> Json {
  let declarations : Map[String, Declaration] = Map([])
  let candidates : Array[Candidate] = []
  let errors : Array[String] = []
  let production_units : Map[String, @project.CompilationUnit] = Map([])
  let source_units : Map[String, @project.CompilationUnit] = Map([])
  let invalid_sources : Map[String, Bool] = Map([])
  let invalid_units : Map[String, Bool] = Map([])
  let function_files : Map[String, String] = Map([])
  for unit in units {
    if !(unit.role is Production) {
      continue
    }
    if unit.module_root != root ||
      unit.target != "native" ||
      (unit.package_root != root && !unit.package_root.has_prefix(root + "/")) {
      errors.push("unsupported_compilation_unit: " + unit.id)
      invalid_units[unit.id] = true
    }
    match production_units.get(unit.id) {
      Some(previous) =>
        if previous != unit {
          errors.push("compilation_unit_identity_conflict: " + unit.id)
          invalid_units[unit.id] = true
        }
      None => production_units[unit.id] = unit
    }
    for input in unit.inputs {
      if !(input.mode is Source) {
        continue
      }
      let file = input.path
      if !file.has_prefix(unit.package_root + "/") ||
        !file.has_prefix(root + "/") ||
        @project.absolute(file) != file {
        errors.push("invalid_compilation_source: " + file)
        invalid_sources[file] = true
      }
      match source_units.get(file) {
        Some(previous) =>
          if previous.id != unit.id || previous != unit {
            errors.push("compilation_source_identity_conflict: " + file)
            invalid_sources[file] = true
          }
        None => source_units[file] = unit
      }
    }
  }
  let files = source_units.keys().to_array()
  files.sort_by(String::lexical_compare)
  for file in files {
    if invalid_sources.contains(file) ||
      invalid_units.contains(source_units[file].id) {
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
    for item in items {
      if item is TopTest(..) {
        continue
      }
      let conditional = match item {
        TopFuncDef(fun_decl~, ..) =>
          fun_decl.attrs.iter().any(fn(attr) { attr.name() == Some("cfg") })
        TopLetDef(attrs~, ..) | TopImpl(attrs~, ..) | TopView(attrs~, ..) =>
          attrs.iter().any(fn(attr) { attr.name() == Some("cfg") })
        _ => false
      }
      let visitor = Collector::{
        file,
        candidates,
        unsupported_registrations: errors,
        conditional,
      }
      match item {
        TopFuncDef(fun_decl~, decl_body=DeclBody(expr~), where_clause=None, ..) => {
          let id = site(file, fun_decl.name.loc)
          function_files[id] = file
          declarations[id] = {
            file,
            function: fun_decl,
            body: expr,
            conditional,
          }
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
  let routes : Array[Json] = []
  for candidate in candidates {
    let id = site(candidate.file, candidate.method_label.loc)
    function_files[id] = candidate.file
    if candidate.conditional {
      routes.push({
        "entry": Json::string(id),
        "status": Json::string("incomplete"),
        "reason": Json::string("unsupported_conditional_compilation: " + id),
      })
      continue
    }
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
    // Lowering may install recursive placeholders and transitive helpers. If
    // this callback fails, none of those partial IR functions may be reused.
    let previous_functions : Map[String, Bool] = Map([])
    for function_id in ctx.functions.keys() {
      previous_functions[function_id] = true
    }
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
      let pending : Array[PendingOp] = []
      let env : Map[String, Int] = Map([(binder.name, parameter)])
      let returned = lower(ctx, candidate.file, func.body, env, pending)
      pending.push(Ready(Return(returned)))
      let operations : Array[@ir.Op] = []
      resolve_operations(ctx, candidate.file, pending, operations)
      ctx.functions[id] = { id, parameters: [parameter], operations, }
      let functions = ctx.functions.values().to_array()
      let result = @ir.analyze(functions, id)
      {
        "entry": Json::string(id),
        "result": result.to_json(),
        "route": Json::string(route_path),
      }
    } catch {
      e => {
        for function_id in ctx.functions.keys().to_array() {
          if !previous_functions.contains(function_id) {
            ctx.functions.remove(function_id)
          }
        }
        {
          "entry": Json::string(id),
          "status": Json::string("incomplete"),
          "reason": Json::string(e.to_string()),
        }
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
  let unit_ids = production_units.keys().to_array()
  unit_ids.sort_by(String::lexical_compare)
  let source_metadata : Array[Json] = []
  for file in files {
    let unit = source_units[file]
    if !invalid_sources.contains(file) && !invalid_units.contains(unit.id) {
      source_metadata.push({
        "source": Json::string(file),
        "unit": Json::string(unit.id),
      })
    }
  }
  let function_metadata : Array[Json] = []
  let function_ids = ctx.functions.keys().to_array()
  function_ids.sort_by(String::lexical_compare)
  for id in function_ids {
    let file = function_files[id]
    function_metadata.push({
      "function": Json::string(id),
      "source": Json::string(file),
      "unit": Json::string(source_units[file].id),
    })
  }
  {
    "compilation_units": Json::array(
      unit_ids.map(fn(id) { production_units[id].to_json() }),
    ),
    "source_units": Json::array(source_metadata),
    "function_units": Json::array(function_metadata),
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
