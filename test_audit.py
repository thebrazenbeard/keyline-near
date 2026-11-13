"""Externally observable read-only key-permission decisions, no real signing."""
import io
import json
import unittest
from audit import assess_permission, assess_rpc, fetch_testnet_key, main

ACCOUNT = "demo.testnet"
RECEIVER = "safe.contract.testnet"
KEY = "ed25519:" + "3" * 44  # fabricated public identifier, not a usable key


def grant(allowance="10000000000000000000000", receiver=RECEIVER, methods=None):
    return {"FunctionCall": {"receiver_id": receiver,
                              "method_names": ["read_profile"] if methods is None else methods,
                              "allowance": allowance}}


def envelope(permission=None):
    return {"jsonrpc": "2.0", "id": "near-key-audit-v0", "result": {
        "block_height": 123, "block_hash": "HashFromSyntheticFixtureNotARealBlock",
        "nonce": 44, "permission": grant() if permission is None else permission}}


class PermissionAudit(unittest.TestCase):
    def inspect(self, permission=None, **kwargs):
        return assess_permission(grant() if permission is None else permission,
                                 receiver=RECEIVER, allowed_methods=("read_profile",),
                                 max_gas_allowance_yocto=10**23, **kwargs)

    def test_exact_scoped_key_is_only_permission_compatible(self):
        r = self.inspect()
        self.assertEqual(r["decision"], "POLICY_MATCH_UNVERIFIED")
        self.assertEqual(r["findings"], [])
        self.assertFalse(r["trade_authorized"])
        self.assertFalse(r["private_key_inspected"])
        self.assertEqual(r["allowance_kind"], "GAS_ONLY_NOT_ASSET_SPEND_LIMIT")

    def test_full_access_selected_agent_key_requires_review(self):
        for permission in ("FullAccess", "GasKeyFullAccess"):
            with self.subTest(permission=permission):
                r = self.inspect(permission)
                self.assertEqual(r["decision"], "REVIEW_REQUIRED")
                self.assertIn("FULL_ACCESS_AGENT_KEY", r["findings"])

    def test_unbounded_allowance_and_wildcard_methods_are_flagged(self):
        r = self.inspect(grant(None, methods=[]))
        self.assertEqual(r["decision"], "REVIEW_REQUIRED")
        self.assertIn("UNLIMITED_GAS_ALLOWANCE", r["findings"])
        self.assertIn("ALL_RECEIVER_METHODS_ALLOWED", r["findings"])

    def test_unapproved_receiver_and_method_are_flagged(self):
        r = self.inspect(grant(receiver="unknown.testnet", methods=["transfer"] ))
        self.assertIn("RECEIVER_OUTSIDE_POLICY", r["findings"])
        self.assertIn("METHOD_OUTSIDE_POLICY", r["findings"])

    def test_allowance_is_gas_not_token_spend_and_cap_is_enforced(self):
        r = self.inspect(grant("1000000000000000000000000"))
        self.assertIn("GAS_ALLOWANCE_EXCEEDS_POLICY", r["findings"])
        self.assertFalse(r["trade_authorized"])

    def test_malformed_permission_fails_closed(self):
        for permission in ({"FunctionCall": {"receiver_id": RECEIVER,
                              "method_names": "read_profile", "allowance": "100"}},
                           {"FunctionCall": {"receiver_id": RECEIVER,
                              "method_names": ["read_profile"], "allowance": -1}},
                           {"FutureKeyPermission": {}}, {"FunctionCall": {}}):
            with self.subTest(permission=permission):
                r = self.inspect(permission)
                self.assertEqual(r["decision"], "UNVERIFIED_MALFORMED_PERMISSION")
                self.assertFalse(r["trade_authorized"])

    def test_bad_policy_does_not_create_approval(self):
        for bad in (True, 10.3, "10000", -1):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    assess_permission(grant(), receiver=RECEIVER,
                         allowed_methods=("read_profile",), max_gas_allowance_yocto=bad)

    def test_rpc_error_or_missing_chain_metadata_is_unverified(self):
        for data in ({"jsonrpc":"2.0","id":"near-key-audit-v0","error":{"message":"key missing"}},
                     {"jsonrpc":"2.0","id":"near-key-audit-v0","result":{"permission": grant()}},
                     {"jsonrpc":"2.0","id":"other","result":{"block_height":123,"block_hash":"h","permission":grant()}}):
            with self.subTest(data=data):
                r = assess_rpc(data, receiver=RECEIVER, allowed_methods=("read_profile",),
                               max_gas_allowance_yocto=10**23)
                self.assertEqual(r["decision"], "UNVERIFIED_RPC_RESPONSE")

    def test_rpc_valid_envelope_preserves_block_evidence_and_provenance(self):
        r = assess_rpc(envelope(), receiver=RECEIVER, allowed_methods=("read_profile",),
                       max_gas_allowance_yocto=10**23, provenance="SYNTHETIC_FIXTURE")
        self.assertEqual(r["decision"], "POLICY_MATCH_UNVERIFIED")
        self.assertEqual(r["block_height"], 123)
        self.assertEqual(r["data_provenance"], "SYNTHETIC_FIXTURE")
        self.assertFalse(r["rpc_cryptographic_proof_verified"])

    def test_explicit_single_readonly_testnet_rpc_request(self):
        calls = []
        class Response:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *_): return None
            def read(self, n=-1): return json.dumps(envelope()).encode()
        def opener(req, timeout):
            calls.append((req, timeout))
            return Response()
        data = fetch_testnet_key(ACCOUNT, KEY, opener=opener)
        self.assertEqual(len(calls), 1)
        req, timeout = calls[0]
        self.assertEqual(req.full_url, "https://test.rpc.fastnear.com")
        self.assertLessEqual(timeout, 10)
        obj = json.loads(req.data)
        self.assertEqual(obj["method"], "query")
        self.assertEqual(obj["params"]["request_type"], "view_access_key")
        self.assertEqual(obj["params"]["account_id"], ACCOUNT)
        self.assertEqual(obj["params"]["public_key"], KEY)
        self.assertEqual(obj["params"]["finality"], "final")
        self.assertNotIn("private_key", json.dumps(obj))
        self.assertEqual(data["result"]["block_height"], 123)

    def test_non_testnet_or_bad_public_key_cannot_reach_network(self):
        calls=[]
        def opener(*args,**kwargs): calls.append((args,kwargs)); raise AssertionError("network accessed")
        for acct,key in (("wallet.near",KEY),("BAD.testnet",KEY),
                         ("example.testnet","secret-key"),("example.testnet", "ed25519:tiny")):
            with self.subTest(acct=acct,key=key), self.assertRaises(ValueError):
                fetch_testnet_key(acct,key,opener=opener)
        self.assertEqual(calls,[])

    def test_network_failure_is_reported_without_exposing_url_or_identifiers(self):
        def opener(*args, **kwargs): raise OSError("connection failure and secret://internal")
        with self.assertRaisesRegex(RuntimeError, "RPC_UNAVAILABLE") as ctx:
            fetch_testnet_key(ACCOUNT,KEY,opener=opener)
        self.assertNotIn("secret", str(ctx.exception))

    def test_oversized_response_rejected(self):
        class Oversize:
            status=200
            def __enter__(self): return self
            def __exit__(self,*args): return False
            def read(self,n=-1): return b"x" * 262145
        with self.assertRaisesRegex(RuntimeError,"RPC_UNAVAILABLE"):
            fetch_testnet_key(ACCOUNT,KEY,opener=lambda *a,**kw:Oversize())


if __name__ == "__main__":
    unittest.main()

class CliContract(unittest.TestCase):
    def test_fixture_cli_is_json_and_never_claims_trade_rights(self):
        from contextlib import redirect_stdout
        from pathlib import Path
        from unittest.mock import patch
        out = io.StringIO()
        fixture = str(Path(__file__).with_name("sample_access_key.json"))
        with patch("audit.fetch_testnet_key", side_effect=AssertionError("network used")):
            with redirect_stdout(out):
                exit_code = main(["--fixture", fixture, "--receiver", RECEIVER,
                                  "--method", "read_profile", "--max-gas-yocto",
                                  str(10**23)])
        report = json.loads(out.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(report["decision"], "POLICY_MATCH_UNVERIFIED")
        self.assertFalse(report["trade_authorized"])
        self.assertEqual(report["data_provenance"], "USER_SUPPLIED_FIXTURE_NOT_LIVE")

    def test_bad_fixture_fails_closed(self):
        from contextlib import redirect_stdout
        out = io.StringIO()
        with redirect_stdout(out):
            exit_code = main(["--fixture", "/path/not/on/disk.json", "--receiver", RECEIVER,
                              "--method", "read_profile", "--max-gas-yocto", "1"])
        self.assertEqual(exit_code, 2)
        self.assertEqual(json.loads(out.getvalue())["decision"], "UNVERIFIED_RPC_RESPONSE")

class BoundedOfflineInput(unittest.TestCase):
    def test_oversized_valid_json_fixture_fails_closed(self):
        from contextlib import redirect_stdout
        from pathlib import Path
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as d:
            filename = Path(d) / "oversized.json"
            data = envelope()
            data["irrelevant_padding"] = "X" * 270000
            filename.write_text(json.dumps(data), encoding="utf-8")
            out = io.StringIO()
            with redirect_stdout(out):
                code = main(["--fixture", str(filename), "--receiver", RECEIVER,
                             "--method", "read_profile", "--max-gas-yocto", str(10**23)])
        self.assertEqual(code, 2, "large untrusted fixture cannot be silently accepted")
        self.assertEqual(json.loads(out.getvalue())["decision"], "UNVERIFIED_RPC_RESPONSE")
