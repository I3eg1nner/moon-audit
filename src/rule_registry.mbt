// One registry owns dispatch, defaults, import gates and report capabilities.

///|
priv struct RuleEntry {
  info : RuleInfo
  requirement : String
  api : String
  forms : String
  limitation : String
  default_enabled : Bool
  run : (@list.List[@syntax.Impl], String, String, Array[Finding], Severity) -> Unit
}

///|
fn rule_registry() -> Array[RuleEntry] {
  [
    {
      info: cwe116_info(),
      requirement: "none",
      api: "String::replace",
      forms: "receiver.replace; String::replace",
      limitation: "Dot receiver type is unresolved; User type named String or Dummy.replace can be safe and still match; No proof that output reaches HTML or input is untrusted",
      default_enabled: true,
      run: run_cwe116,
    },
    {
      info: cwe079_cmark_info(),
      requirement: "cmark_import",
      api: "cmark render/from_doc/renderer/xhtml_renderer",
      forms: "unqualified function; package-qualified function",
      limitation: "Import substring does not establish declaration identity; A local render function can match; Disabling safe mode does not establish untrusted HTML reaching a browser",
      default_enabled: true,
      run: run_cwe079_cmark,
    },
    {
      info: cwe079_inner_html_info(),
      requirement: "rabbita_import",
      api: "rabbita inner_html",
      forms: "receiver.inner_html",
      limitation: "Receiver declaration unresolved; Variables holding safe constants still match; Uppercase variable name is not a safety proof; No DOM insertion reachability",
      default_enabled: false,
      run: run_cwe079_inner_html,
    },
    {
      info: cwe079_template_info(),
      requirement: "mocket_or_crescent_import",
      api: "mocket/crescent template APIs",
      forms: "unqualified html; package-qualified html; receiver.html",
      limitation: "No response-return proof; No source provenance; No encoding semantics; No declaration binding",
      default_enabled: false,
      run: run_cwe079_template,
    },
    {
      info: cwe094_info(),
      requirement: "none",
      api: "JavaScript extern",
      forms: "embedded FFI string; embedded FFI multiline string",
      limitation: "Comment containing eval(input) triggers; No JavaScript parser; Whitespace and aliases can evade matching; No user-control evidence",
      default_enabled: false,
      run: run_cwe094,
    },
    {
      info: cwe113_info(),
      requirement: "none",
      api: "HTTP header-like APIs",
      forms: "receiver method only",
      limitation: "No validated current-library matched sink; Safe values in locals trigger; No knowledge of library rejection/normalization; Does not match current crescent header API",
      default_enabled: false,
      run: run_cwe113,
    },
    {
      info: cwe942_info(),
      requirement: "mocket_or_crescent_import",
      api: "CORS-like configuration",
      forms: "unqualified function; package-qualified function",
      limitation: "Original credential theft claim is false for wildcard+credentials alone; Dynamic trusted origin can match; No browser behavioral or reflected-origin proof; No declaration binding",
      default_enabled: false,
      run: run_cwe942,
    },
    {
      info: cwe614_info(),
      requirement: "mocket_or_crescent_import",
      api: "cookie-like API",
      forms: "receiver.set_cookie",
      limitation: "False attributes are treated as present/safe; Cookie role and deployment are unknown; No serialization inspection; Same-name harmless APIs trigger",
      default_enabled: false,
      run: run_cwe614,
    },
    {
      info: cwe770_info(),
      requirement: "crescent_import",
      api: "crescent serve",
      forms: "receiver method only",
      limitation: "Current API nested options cause false positive; File text does not bind routes to server; No default or reverse-proxy configuration knowledge",
      default_enabled: false,
      run: run_cwe770,
    },
    {
      info: cwe346_info(),
      requirement: "mocket_or_crescent_import",
      api: "websocket-like API",
      forms: "receiver method; unqualified function; package-qualified function",
      limitation: "No real current-library API validation; Prior middleware validation invisible; Label presence is not validation proof",
      default_enabled: false,
      run: run_cwe346,
    },
    {
      info: cwe022_info(),
      requirement: "none",
      api: "file/path-like API",
      forms: "infix +",
      limitation: "Variable names do not prove user control; No filesystem sink or normalization semantics; Path joining alone is not path traversal",
      default_enabled: false,
      run: run_cwe022,
    },
    {
      info: cwe676_info(),
      requirement: "non_stdlib_module",
      api: "unsafe-like API",
      forms: "receiver method; unqualified function; qualified function; type method",
      limitation: "Arbitrary guard suppresses without proving precondition; Function name does not establish unsafe semantics; Many genuine unsafe APIs are excluded",
      default_enabled: false,
      run: run_cwe676,
    },
    {
      info: cwe248_info(),
      requirement: "non_stdlib_module",
      api: "panic/abort-like API",
      forms: "unqualified function only",
      limitation: "No reachability analysis; String contents and function names are not safety proofs; Platform file exclusion hides compiled target behavior; Local binding unresolved",
      default_enabled: false,
      run: run_cwe248,
    },
    {
      info: cwe704_info(),
      requirement: "non_stdlib_module",
      api: "cast-like API",
      forms: "receiver.cast; receiver.reinterpret_cast",
      limitation: "No receiver or declaration identity; File-wide extern substring suppresses unrelated calls; Custom safe conversions match",
      default_enabled: false,
      run: run_cwe704,
    },
  ]
}

///|
fn rule_requirement(id : String) -> String {
  for entry in rule_registry() {
    if rule_id_str(entry.info.id) == id {
      return entry.requirement
    }
  }
  "unknown_rule"
}

///|
pub fn rule_capabilities() -> Json {
  let values : Array[Json] = []
  for entry in rule_registry() {
    values.push({
      "id": Json::string(rule_id_str(entry.info.id)),
      "evidence": Json::string("syntax_hint"),
      "requirement": Json::string(entry.requirement),
      "default_enabled": Json::boolean(entry.default_enabled),
      "disposition": Json::string(
        if entry.default_enabled {
          "review_hint"
        } else {
          "opt_in_unverified"
        },
      ),
      "api_scope": Json::string(entry.api),
      "call_forms": Json::string(entry.forms),
      "limitations": Json::string(entry.limitation),
      "binding": Json::string("unverified; names and imports are hints"),
      "backend_policy": Json::string(
        "selected by project compiler when verification requested; otherwise not verified",
      ),
      "version_policy": Json::string(
        "parser 0.4.0; no arbitrary library version claim",
      ),
      "validation": Json::string("experiments/rule_audit/README.md"),
      "model_fingerprint": Json::null(),
    })
  }
  Json::array(values)
}
