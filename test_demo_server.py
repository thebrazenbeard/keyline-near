"""Public HTTP behavior: local-only synthetic agent-wallet policy demonstration."""
import http.client
import json
import threading
import unittest
from http.server import ThreadingHTTPServer

from demo_server import Handler, evaluate_scenario


class DemoPolicyTests(unittest.TestCase):
    def test_prompt_injection_receiver_route_is_blocked(self):
        result = evaluate_scenario("injected_receiver")
        self.assertEqual(result["action"], "BLOCK")
        self.assertIn("RECEIVER_OUTSIDE_POLICY", result["findings"])
        self.assertFalse(result["signing_attempted"])
        self.assertFalse(result["trade_authorized"])

    def test_full_access_key_is_not_agent_safe(self):
        result = evaluate_scenario("full_access")
        self.assertEqual(result["action"], "BLOCK")
        self.assertIn("FULL_ACCESS_AGENT_KEY", result["findings"])

    def test_valid_scoped_key_is_review_only_not_spend_cap(self):
        result = evaluate_scenario("scoped_read")
        self.assertEqual(result["decision"], "POLICY_MATCH_UNVERIFIED")
        self.assertEqual(result["action"], "REVIEW_ONLY")
        self.assertFalse(result["trade_authorized"])
        self.assertEqual(result["asset_spend_limit_verified"], False)
        self.assertIs(result["contract_effects_verified"], False)
        self.assertIs(result["key_owner_verified"], False)

    def test_invalid_unknown_scenario_is_rejected(self):
        with self.assertRaises(ValueError):
            evaluate_scenario("nonexistent")


class DemoHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def request(self, method, path, body=b"", headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=2)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read(12000)
        finally:
            connection.close()

    def test_local_landing_page_explains_key_limit(self):
        status, headers, body = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(b"gas allowance", body.lower())
        self.assertIn(b"no wallet", body.lower())
        self.assertIn("no-store", headers.get("Cache-Control", ""))

    def test_review_label_is_not_green_clearance(self):
        status, _, page = self.request("GET", "/")
        self.assertEqual(status, 200)
        for name in ("scoped_read", "full_access", "wildcard_methods",
                     "injected_receiver", "unlimited_gas"):
            self.assertIn(('data-scenario="' + name + '"').encode(), page)
        self.assertIn(b"result.action === 'BLOCK' ? 'bad' : 'caution'", page)
        self.assertNotIn(b"https://", page)
        self.assertIn(b"not an asset spending limit", page)

    def test_endpoint_returns_block_for_attack(self):
        body = json.dumps({"scenario": "injected_receiver"}).encode("utf-8")
        status, _, content = self.request("POST", "/api/audit", body,
                        {"Content-Type": "application/json"})
        self.assertEqual(status, 200)
        result = json.loads(content)
        self.assertEqual(result["action"], "BLOCK")
        self.assertEqual(result["network_calls"], 0)

    def test_cross_site_origin_is_rejected(self):
        body = b'{"scenario":"scoped_read"}'
        status, _, _ = self.request("POST", "/api/audit", body,
                {"Content-Type": "application/json", "Origin": "https://evil.example"})
        self.assertEqual(status, 403)

    def test_invalid_scenario_and_oversized_body_rejected(self):
        status, _, _ = self.request("POST", "/api/audit", b'{"scenario":"bogus"}',
                                     {"Content-Type": "application/json"})
        self.assertEqual(status, 400)
        status, _, _ = self.request("POST", "/api/audit", b"x" * 2048,
                                     {"Content-Type": "application/json"})
        self.assertEqual(status, 413)

    def test_no_other_routes_or_mutating_methods(self):
        status, _, _ = self.request("GET", "/admin")
        self.assertEqual(status, 404)
        status, _, _ = self.request("PUT", "/api/audit")
        self.assertNotEqual(status, 200)



class DemoStartupTests(unittest.TestCase):
    def test_os_selected_port_reports_bound_loopback_url(self):
        from contextlib import redirect_stdout
        from io import StringIO
        from unittest.mock import patch
        from demo_server import Handler, main
        out = StringIO()
        with patch("demo_server.ThreadingHTTPServer") as create:
            server = create.return_value.__enter__.return_value
            server.server_port = 54321
            server.serve_forever.side_effect = KeyboardInterrupt
            with redirect_stdout(out):
                code = main(["--port", "0"])
        self.assertEqual(code, 0)
        create.assert_called_once_with(("127.0.0.1", 0), Handler)
        self.assertIn("http://127.0.0.1:54321/", out.getvalue())
        self.assertNotIn("http://127.0.0.1:0/", out.getvalue())

class BoundedOversizeResponseTests(unittest.TestCase):
    """Check 413 rejection before reply, without nondeterministic sockets."""
    def test_modest_oversize_consumed_before_413_with_short_timeout(self):
        from demo_server import MAX_BODY_BYTES
        class Input:
            calls = []
            def read(self, count):
                self.calls.append(count)
                return b"x" * count
        class Connection:
            timeouts = []
            def settimeout(self, sec):
                self.timeouts.append(sec)
        class Stub:
            path = "/api/audit"
            headers = {"Content-Type":"application/json",
                       "Content-Length":str(MAX_BODY_BYTES * 2)}
            rfile = Input()
            connection = Connection()
            close_connection = False
            response_status = None
            def _allowed_origin(self): return True
            def _reply(self, status, body): self.response_status = status
        stub = Stub()
        Handler.do_POST(stub)
        self.assertEqual(stub.response_status, 413)
        self.assertEqual(stub.rfile.calls, [MAX_BODY_BYTES * 2])
        self.assertTrue(stub.close_connection)
        self.assertEqual(len(stub.connection.timeouts), 1)
        self.assertLessEqual(stub.connection.timeouts[0], 1)

    def test_absurd_declared_body_never_drained_unbounded(self):
        class Input:
            calls = []
            def read(self, count): self.calls.append(count); return b"x" * count
        class Connection:
            def settimeout(self, sec): raise AssertionError("no huge-body read")
        class Stub:
            path = "/api/audit"
            headers = {"Content-Type":"application/json",
                       "Content-Length":"100000000"}
            rfile = Input()
            connection = Connection()
            close_connection = False
            response_status = None
            def _allowed_origin(self): return True
            def _reply(self, status, body): self.response_status = status
        stub = Stub()
        Handler.do_POST(stub)
        self.assertEqual(stub.response_status, 413)
        self.assertEqual(stub.rfile.calls, [])
        self.assertTrue(stub.close_connection)


if __name__ == "__main__":
    unittest.main()