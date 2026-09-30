// Source: mizchi/llm src/openai/openai.mbt
// Verdict: likely_false_positive (LLM confirmed)
// HTTPS API URL construction, not filesystem path

pub fn api_url(account_id : String) -> String {
  "https://api.cloudflare.com/client/v4/accounts/" + account_id + "/ai"
}
