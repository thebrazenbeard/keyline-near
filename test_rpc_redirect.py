"""Hostile localhost 302 probe: fixed NEAR RPC calls must not redirect."""
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

import audit


class RedirectIsolationTests(unittest.TestCase):
    def test_default_rpc_reader_must_reject_any_redirect(self):
        sink_hits = []

        class LocalFakeRPC(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_POST(self):
                self.send_response(302)
                self.send_header("Location", "/untrusted/sink")
                self.end_headers()

            def do_GET(self):
                sink_hits.append(self.path)
                data = json.dumps({
                    "jsonrpc": "2.0", "id": audit.REQUEST_ID,
                    "result": {"block_height": 123, "block_hash": "fake",
                               "permission": "FullAccess"}
                }).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        server = ThreadingHTTPServer(("127.0.0.1", 0), LocalFakeRPC)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            local_endpoint = "http://127.0.0.1:%d/selected" % server.server_port
            with patch.object(audit, "ENDPOINT", local_endpoint):
                with self.assertRaisesRegex(RuntimeError, "RPC_UNAVAILABLE"):
                    audit.fetch_testnet_key("sample.testnet", "ed25519:" + "3"*44)
            self.assertEqual(sink_hits, [], "RPC reader followed an untrusted redirect")
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
