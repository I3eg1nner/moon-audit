// Independent ordered value IR. No parser, pattern-scanner state or name matching.

///|
pub(all) enum Op {
  Literal(Int, String)
  Copy(Int, Int)
  Request(Int, Int)
  Query(Int, Int, String)
  Lookup(Int, Int, Int)
  Default(Int, Int, Int)
  EscapeHtmlText(Int, Int)
  RenderMarkdown(Int, Int, Bool, String)
  Concat(Int, Array[Int])
  Response(Int, Int, Bool, String)
  Call(Int, String, Array[Int], String)
  Return(Int)
} derive(ToJson)

///|
pub(all) struct Function {
  id : String
  parameters : Array[Int]
  operations : Array[Op]
} derive(ToJson)

///|
pub(all) struct Segment {
  literal : String?
  origin : String?
  encoded_html_text : Bool
  safe_html_fragment : Bool
  trace : Array[String]
} derive(ToJson)

///|
priv enum Value {
  Text(Array[Segment])
  Event
  RequestHandle
  QueryHandle(String)
  Optional(Array[Segment])
  Responder(Array[Segment], Bool, String)
}

///|
pub(all) struct Result {
  status : String
  reason : String
  source_paths : Array[Array[String]]
  steps : Int
} derive(ToJson)

///|
priv suberror FlowError {
  Incomplete(String)
}

///|
priv struct Budget {
  mut steps : Int
  limit : Int
}

///|
fn spend(budget : Budget, amount : Int) -> Unit raise FlowError {
  if amount > budget.limit - budget.steps {
    raise Incomplete("incomplete_budget")
  }
  budget.steps += amount
}

///|
fn get(values : Map[Int, Value], id : Int) -> Value raise FlowError {
  match values.get(id) {
    Some(value) => value
    None => raise Incomplete("undefined_value")
  }
}

///|
fn text(value : Value) -> Array[Segment] raise FlowError {
  match value {
    Text(segments) => segments
    _ => raise Incomplete("unproven_builtin_string")
  }
}

///|
fn execute(
  functions : Map[String, Function],
  id : String,
  args : Array[Value],
  budget : Budget,
  depth : Int,
) -> Value raise FlowError {
  if depth > 64 {
    raise Incomplete("incomplete_budget")
  }
  let function = match functions.get(id) {
    Some(function) => function
    None => raise Incomplete("unbound_function")
  }
  if args.length() != function.parameters.length() {
    raise Incomplete("argument_binding_mismatch")
  }
  let values : Map[Int, Value] = Map([])
  for index in 0..<args.length() {
    values[function.parameters[index]] = args[index]
  }
  for operation in function.operations {
    spend(budget, 1)
    match operation {
      Literal(dest, value) =>
        values[dest] = Text([
          {
            literal: Some(value),
            origin: None,
            encoded_html_text: false,
            safe_html_fragment: false,
            trace: [],
          },
        ])
      Copy(dest, source) => values[dest] = get(values, source)
      Request(dest, source) =>
        match get(values, source) {
          Event => values[dest] = RequestHandle
          _ => raise Incomplete("unproven_event_handle")
        }
      Query(dest, source, site) =>
        match get(values, source) {
          RequestHandle => values[dest] = QueryHandle(site)
          _ => raise Incomplete("unproven_request_handle")
        }
      Lookup(dest, source, key) => {
        ignore(text(get(values, key)))
        match get(values, source) {
          QueryHandle(site) =>
            values[dest] = Optional([
              {
                literal: None,
                origin: Some(site),
                encoded_html_text: false,
                safe_html_fragment: false,
                trace: [site],
              },
            ])
          _ => raise Incomplete("unmodeled_container")
        }
      }
      Default(dest, source, fallback) => {
        let alternate = text(get(values, fallback))
        if alternate.any(fn(segment) {
            segment.origin is Some(_) ||
            segment.literal.unwrap_or("").contains("<")
          }) {
          raise Incomplete("unsupported_optional_default")
        }
        match get(values, source) {
          Optional(segments) => {
            spend(budget, segments.length() + alternate.length())
            values[dest] = Text(segments + alternate)
          }
          _ => raise Incomplete("unmodeled_optional_value")
        }
      }
      EscapeHtmlText(dest, source) => {
        let segments = text(get(values, source))
        spend(budget, segments.length())
        values[dest] = Text(
          segments.map(fn(segment) { { ..segment, encoded_html_text: true, } }),
        )
      }
      RenderMarkdown(dest, source, safe, site) => {
        let segments = text(get(values, source))
        for segment in segments {
          spend(budget, segment.trace.length() + 2)
        }
        // Markdown is a transformation, never a transparent encoding transfer.
        // Literal markup is unknown after rendering; safe output is a fragment.
        values[dest] = Text(
          segments.map(fn(segment) {
            {
              ..segment,
              literal: if safe {
                Some("")
              } else {
                Some("<unknown-markdown>")
              },
              encoded_html_text: false,
              safe_html_fragment: safe,
              trace: segment.trace + [site],
            }
          }),
        )
      }
      Concat(dest, sources) => {
        let segments : Array[Segment] = []
        for source in sources {
          let incoming = text(get(values, source))
          spend(budget, incoming.length())
          for segment in incoming {
            segments.push(segment)
          }
        }
        values[dest] = Text(segments)
      }
      Response(dest, source, html, site) =>
        values[dest] = Responder(text(get(values, source)), html, site)
      Call(dest, callee, actuals, site) => {
        let actual_values : Array[Value] = []
        for actual in actuals {
          actual_values.push(get(values, actual))
        }
        let value = execute(functions, callee, actual_values, budget, depth + 1)
        values[dest] = match value {
          Text(segments) => {
            for segment in segments {
              spend(budget, segment.trace.length() + 2)
            }
            Text(
              segments.map(fn(segment) {
                { ..segment, trace: segment.trace + [site], }
              }),
            )
          }
          _ => value
        }
      }
      Return(source) => return get(values, source)
    }
  }
  raise Incomplete("missing_return")
}

///|
// Only plain HTML text and plain element wrappers are proven contexts in v1.
// Unknown markup never turns an encoded value into a safe conclusion.
fn plain_html_context(segments : Array[Segment]) -> Bool {
  for segment in segments {
    if segment.literal is Some(value) {
      let mut remaining = value
      for tag in ["<p>", "</p>", "<div>", "</div>", "<span>", "</span>"] {
        remaining = remaining.replace_all(old=tag, new="")
      }
      if remaining.contains("<") {
        return false
      }
    }
  }
  true
}

///|
pub fn analyze(
  functions : Array[Function],
  entry : String,
  limit? : Int = 10000,
) -> Result {
  let table : Map[String, Function] = Map([])
  for function in functions {
    if table.contains(function.id) {
      return {
        status: "incomplete",
        reason: "duplicate_function_identity",
        source_paths: [],
        steps: 0,
      }
    }
    table[function.id] = function
  }
  let budget = { steps: 0, limit, }
  let result = execute(table, entry, [Event], budget, 0) catch {
    Incomplete(reason) =>
      return {
        status: "incomplete",
        reason,
        source_paths: [],
        steps: budget.steps,
      }
  }
  let paths : Array[Array[String]] = []
  match result {
    Responder(segments, html, sink) => {
      if !html {
        return {
          status: "complete",
          reason: "",
          source_paths: paths,
          steps: budget.steps,
        }
      }
      let plain = plain_html_context(segments)
      for segment in segments {
        if segment.origin is Some(_) &&
          (!(segment.encoded_html_text || segment.safe_html_fragment) || !plain) {
          spend(budget, segment.trace.length() + 2) catch {
            Incomplete(reason) =>
              return {
                status: "incomplete",
                reason,
                source_paths: paths,
                steps: budget.steps,
              }
          }
          paths.push(segment.trace + [sink, entry + ":route_response"])
        }
      }
      {
        status: if plain {
          "complete"
        } else {
          "incomplete"
        },
        reason: if plain {
          ""
        } else {
          "unsupported_html_context"
        },
        source_paths: paths,
        steps: budget.steps,
      }
    }
    _ =>
      {
        status: "incomplete",
        reason: "route_return_not_responder",
        source_paths: [],
        steps: budget.steps,
      }
  }
}

///|
pub extend Op with ToJson::{to_json}

///|
pub extend Function with ToJson::{to_json}

///|
pub extend Segment with ToJson::{to_json}

///|
pub extend Result with ToJson::{to_json}
