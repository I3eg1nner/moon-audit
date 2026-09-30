// Source: moonbitlang/async src/websocket/client.mbt
// Verdict: needs_review (audit_hint — abort on invalid protocol from network)
// Protocol string comes from network peer; invalid value crashes the process

pub fn connect(protocol : String) -> Unit {
  if protocol != "ws" && protocol != "wss" {
    abort("invalid protocol " + protocol)
  }
}
