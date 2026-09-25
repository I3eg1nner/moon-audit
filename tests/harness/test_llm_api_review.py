#!/usr/bin/env python3
"""Local HTTP integration tests; never invoke an external model."""
import contextlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import unittest
from unittest.mock import patch

import test_llm_review as fixtures
sys.path.insert(0, str(fixtures.REPO / 'scripts'))
import llm_api_review as api

SCRIPT = Path(os.environ.get('LLM_API_SCRIPT', str(fixtures.REPO / 'scripts/llm_api_review.py'))).resolve()


@contextlib.contextmanager
def server(responder):
    calls = []
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            calls.append((self.path, self.headers.get('Authorization'), body))
            code, headers, value = responder(body, len(calls))
            self.send_response(code)
            for k, v in headers.items():
                self.send_header(k, v)
            self.end_headers()
            try:
                self.wfile.write(value if isinstance(value, bytes) else json.dumps(value).encode())
            except BrokenPipeError:
                pass
    httpd = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{httpd.server_port}/v1', calls
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join()


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.LlmReviewContractTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.prepare()
        self.bundle = self.fixture.load_bundle()
        self.secret = 'local-test-key-never-output'
        self.env = self.fixture.root / '.env'
        self.env.write_text('API_KEY="' + self.secret + '"\nModel="local-fixture"\n')

    def valid(self):
        return {'schema': api.contract.SCHEMA_RESPONSE, 'bundle_id': self.bundle['bundle_id'],
                'reviews': self.fixture.default_reviews(self.bundle)}

    def envelope(self, content=None, **choice):
        return {'choices': [{'finish_reason': 'stop', 'message': {'role': 'assistant', 'content': json.dumps(content or self.valid())}, **choice}],
                'usage': {'prompt_tokens': 42, 'completion_tokens': 21, 'total_tokens': 63, 'secret': self.secret}}

    def invoke(self, url, *extra, expect=0):
        env = {k: v for k, v in os.environ.items() if k not in ('OPENAI_API_KEY', 'OPENAI_BASE_URL', 'OPENAI_MODEL', 'API_KEY', 'Base_URL', 'Model')}
        result = subprocess.run([sys.executable, str(SCRIPT), '--bundle', str(self.fixture.bundle_dir), '--output', str(self.fixture.result),
                                 '--env-file', str(self.env), '--base-url', url, *extra], capture_output=True, text=True, env=env, timeout=15)
        self.assertEqual(result.returncode, expect, result.stdout + result.stderr)
        self.assertNotIn(self.secret, result.stdout + result.stderr)
        return result

    def test_actual_http_contract_and_env_aliases(self):
        with server(lambda *_: (200, {}, self.envelope())) as (url, calls):
            self.invoke(url, '--json-mode', '--token-parameter', 'max_completion_tokens', '--max-output-tokens', '800')
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], '/v1/chat/completions')
        self.assertEqual(calls[0][1], 'Bearer ' + self.secret)
        payload = calls[0][2]
        self.assertEqual(payload['model'], 'local-fixture')
        self.assertEqual(payload['max_completion_tokens'], 800)
        self.assertEqual(payload['response_format'], {'type': 'json_object'})
        result = json.loads(self.fixture.result.read_text())
        self.assertTrue(result['static_incomplete'])  # syntax-only input stays unverified
        self.assertEqual(result['reviews'][0]['static_evidence'], 'syntax_hint')
        self.assertEqual(result['origin'], 'llm_unverified')
        self.assertNotIn(self.secret, self.fixture.result.read_text())
        self.assertEqual(result['provider']['usage']['total_tokens'], 63)

    def test_retry_429_then_success(self):
        with server(lambda _, n: (429, {}, b'busy') if n == 1 else (200, {}, self.envelope())) as (url, calls):
            self.invoke(url, '--retries', '1')
        self.assertEqual(len(calls), 2)

    def test_retry_exhaustion_keeps_existing_output(self):
        self.fixture.result.write_text('previous')
        with server(lambda *_: (503, {}, self.secret.encode())) as (url, calls):
            self.invoke(url, '--retries', '1', expect=2)
        self.assertEqual(len(calls), 2)
        self.assertEqual(self.fixture.result.read_text(), 'previous')

    def test_401_no_retry_or_secret_log(self):
        with server(lambda *_: (401, {}, self.secret.encode())) as (url, calls):
            self.invoke(url, '--retries', '2', expect=2)
        self.assertEqual(len(calls), 1)

    def test_redirect_does_not_forward_credentials(self):
        with server(lambda *_: (200, {}, self.envelope())) as (target, target_calls):
            with server(lambda *_: (307, {'Location': target + '/chat/completions'}, b'')) as (url, calls):
                self.invoke(url, expect=2)
        self.assertEqual(len(calls), 1)
        self.assertEqual(target_calls, [])

    def test_invalid_citation_does_not_replace_output(self):
        self.fixture.result.write_text('previous')
        response = self.valid()
        response['reviews'][0]['evidence'][0]['quote'] = 'fabricated'
        with server(lambda *_: (200, {}, self.envelope(response))) as (url, calls):
            self.invoke(url, expect=2)
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.fixture.result.read_text(), 'previous')

    def test_truncation_tool_calls_refusal_and_non_json_rejected(self):
        envelopes = [self.envelope(finish_reason='length'),
                     self.envelope(message={'content': '{}', 'tool_calls': [{}]}),
                     self.envelope(message={'content': '{}', 'refusal': 'no'}),
                     self.envelope(message={'content': '```json\n{}\n```'}),
                     {'choices': []}]
        for envelope in envelopes:
            with self.subTest(envelope=envelope):
                with server(lambda *_: (200, {}, envelope)) as (url, _):
                    self.invoke(url, expect=2)
        self.assertFalse(self.fixture.result.exists())

    def test_source_change_before_request_makes_no_call(self):
        self.fixture.source.write_text('changed')
        with server(lambda *_: (200, {}, self.envelope())) as (url, calls):
            self.invoke(url, expect=2)
        self.assertEqual(calls, [])

    def test_source_change_during_request_rejected(self):
        def respond(*_):
            self.fixture.source.write_text('changed')
            return 200, {}, self.envelope()
        with server(respond) as (url, _):
            self.invoke(url, expect=2)
        self.assertFalse(self.fixture.result.exists())

    def test_zero_findings_needs_no_config_or_network(self):
        self.fixture.prepare(findings=[])
        self.env.unlink()
        with server(lambda *_: (500, {}, b'no')) as (url, calls):
            self.invoke(url)
        self.assertEqual(calls, [])
        self.assertEqual(json.loads(self.fixture.result.read_text())['provider']['attempts'], 0)

    def test_output_config_collision_makes_no_call(self):
        self.fixture.result = self.env
        with server(lambda *_: (200, {}, self.envelope())) as (url, calls):
            self.invoke(url, expect=2)
        self.assertEqual(calls, [])
        self.assertIn(self.secret, self.env.read_text())

    def test_dotenv_never_executes_and_environment_precedence(self):
        self.env.write_text('export API_KEY="$(touch /tmp/should-never-be-created)" # text\nModel=test # note\n')
        config = api.dotenv(self.env)
        self.assertEqual(config['API_KEY'], '$(touch /tmp/should-never-be-created)')
        self.assertEqual(config['Model'], 'test')
        with patch.dict(os.environ, {'API_KEY': 'environment'}, clear=True):
            self.assertEqual(api.choose(None, ('OPENAI_API_KEY', 'API_KEY'), config), 'environment')

    def test_endpoint_constraints(self):
        for url in ('file:///tmp/key', 'http://remote.test/v1', 'https://u:p@host/v1', 'https://host/v1?token=x', 'https://host/v1#fragment'):
            with self.subTest(url=url), self.assertRaises(api.contract.ReviewError):
                api.endpoint(url)
        self.assertEqual(api.endpoint('https://host/v1/chat/completions'), 'https://host/v1/chat/completions')


if __name__ == '__main__':
    unittest.main()
