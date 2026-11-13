"""Interactive localhost-only NEAR agent-key review demo.

Nothing here signs, transacts, creates accounts, connects to a wallet,
or enables outgoing blockchain requests. Scenarios are fixed fictional inputs.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path

from audit import assess_rpc

ROOT = Path(__file__).resolve().parent
FIXTURE = ROOT / "sample_access_key.json"
PAGE = ROOT / "demo.html"
DEFAULT_RECEIVER = "safe.contract.testnet"
DEFAULT_METHODS = ("read_profile",)
MAX_BODY_BYTES = 1024
MAX_REJECT_DRAIN_BYTES = 4096
POLICY_GAS_LIMIT = 10**24
SCENARIOS = (
    "scoped_read",
    "full_access",
    "wildcard_methods",
    "injected_receiver",
    "unlimited_gas",
)


def evaluate_scenario(name: str) -> dict:
    """Return read-only synthetic policy findings, NEVER execution authority."""
    if type(name) is not str or name not in SCENARIOS:
        raise ValueError("unsupported synthetic scenario")
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    fixture = deepcopy(payload)
    permission = fixture["result"]["permission"]
    if name == "full_access":
        fixture["result"]["permission"] = "FullAccess"
    elif name == "wildcard_methods":
        permission["FunctionCall"]["method_names"] = []
    elif name == "injected_receiver":
        permission["FunctionCall"]["receiver_id"] = "pay.attacker.testnet"
    elif name == "unlimited_gas":
        permission["FunctionCall"]["allowance"] = None

    report = assess_rpc(
        fixture,
        receiver=DEFAULT_RECEIVER,
        allowed_methods=DEFAULT_METHODS,
        max_gas_allowance_yocto=POLICY_GAS_LIMIT,
        provenance="FICTIONAL_LOCAL_SCENARIO_NOT_CHAIN_EVIDENCE",
    )
    clean = report["decision"] == "POLICY_MATCH_UNVERIFIED"
    action = "REVIEW_ONLY" if clean else "BLOCK"
    return {
        "scenario": name,
        "decision": report["decision"],
        "action": action,
        "findings": report.get("findings", []),
        "reason": (
            "Key scope matches the declared policy, but contract effects and "
            "asset spending are not verified. Human review still required."
            if clean else
            "Key permissions exceed the declared policy; the mock agent gate "
            "refuses to proceed."
        ),
        "network_calls": 0,
        "trade_authorized": False,
        "signing_attempted": False,
        "private_key_inspected": False,
        "asset_spend_limit_verified": False,
        "contract_effects_verified": False,
        "key_owner_verified": False,
        "rpc_cryptographic_proof_verified": False,
        "data_provenance": "FICTIONAL_LOCAL_SCENARIO_NOT_CHAIN_EVIDENCE",
        "allowance_kind": "GAS_ONLY_NOT_ASSET_SPEND_LIMIT",
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "AgentKeyAuditDemo/0.1"

    def log_message(self, *_args):
        return

    def _allowed_origin(self):
        port = self.server.server_address[1]
        host = self.headers.get("Host", "")
        valid = {f"127.0.0.1:{port}", f"localhost:{port}"}
        origin = self.headers.get("Origin")
        return host in valid and (
            not origin or origin in {f"http://{item}" for item in valid}
        )

    def _reply(self, status: int, body: bytes = b"", content_type: str = "text/plain; charset=utf-8"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'unsafe-inline'; "
            "style-src 'unsafe-inline'; connect-src 'self'; "
            "img-src 'self' data:; form-action 'none'; frame-ancestors 'none'",
        )
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        if not self._allowed_origin():
            self._reply(403, b"forbidden")
            return
        if self.path != "/":
            self._reply(404, b"not found")
            return
        page = PAGE.read_bytes()
        self._reply(200, page, "text/html; charset=utf-8")

    def do_POST(self):
        if not self._allowed_origin():
            self._reply(403, b"forbidden")
            return
        if self.path != "/api/audit":
            self._reply(404, b"not found")
            return
        if self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
            self._reply(415, b"application/json required")
            return
        length = self.headers.get("Content-Length", "")
        if not length.isascii() or not length.isdecimal():
            self._reply(400, b"valid content length required")
            return
        n = int(length)
        if n > MAX_BODY_BYTES:
            # Windows may reset a connection when queued request bytes remain
            # unread as a server closes it after returning HTTP 413. Discard
            # only modest bounded payloads under a short timeout, then close.
            # Never drain an attacker-declared arbitrary body length.
            self.close_connection = True
            if n <= MAX_REJECT_DRAIN_BYTES:
                try:
                    self.connection.settimeout(0.5)
                    self.rfile.read(n)
                except OSError:
                    pass
            self._reply(413, b"input too large")
            return
        try:
            obj = json.loads(self.rfile.read(n))
            if type(obj) is not dict or set(obj) != {"scenario"}:
                raise ValueError("invalid scenario payload")
            report = evaluate_scenario(obj["scenario"])
        except (ValueError, UnicodeError, TypeError, json.JSONDecodeError):
            self._reply(400, b"invalid scenario")
            return
        self._reply(200, json.dumps(report, sort_keys=True).encode("utf-8"),
                    "application/json; charset=utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Local fictional NEAR agent-wallet demo")
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args(argv)
    if args.port != 0 and not 1024 <= args.port <= 65535:
        parser.error("port must be 0 (automatic) or 1024..65535")
    with ThreadingHTTPServer(("127.0.0.1", args.port), Handler) as server:
        print(f"NEAR agent-key audit (fictional/local): http://127.0.0.1:{server.server_port}/", flush=True)
        print("No wallet, keys, trade signing, or network access.", flush=True)
        try:
            server.serve_forever(poll_interval=0.2)
        except KeyboardInterrupt:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())