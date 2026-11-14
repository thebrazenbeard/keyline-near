"""Read-only NEAR agent access-key scope review; no wallet or signing methods.

An RPC response is not a cryptographic proof of chain state. In particular,
FunctionCall allowance limits *gas fees*, not value controlled by contracts.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from urllib import error, request

ENDPOINT = "https://test.rpc.fastnear.com"
REQUEST_ID = "near-key-audit-v0"
MAX_RPC_BYTES = 262144
# NEAR account identifiers allow separators only between alphanumerics.
# Source: nearcore/docs/DataStructures/Account.md (length 2..64).
ACCOUNT_RE = re.compile(r"[a-z0-9]+(?:[-_][a-z0-9]+)*(?:\.[a-z0-9]+(?:[-_][a-z0-9]+)*)*\Z")


def _valid_account_id(value):
    return type(value) is str and 2 <= len(value) <= 64 and ACCOUNT_RE.fullmatch(value) is not None

METHOD_RE = re.compile(r"[A-Za-z0-9_]{1,64}\Z")
PUBKEY_RE = re.compile(r"(?:ed25519|secp256k1):[1-9A-HJ-NP-Za-km-z]{32,90}\Z")


def _unknown():
    return {"decision": "UNVERIFIED_MALFORMED_PERMISSION",
            "findings": ["UNKNOWN_OR_MALFORMED_KEY_PERMISSION"],
            "trade_authorized": False, "private_key_inspected": False,
            "allowance_kind": "GAS_ONLY_NOT_ASSET_SPEND_LIMIT"}


def _validate_review_policy(receiver, allowed_methods, max_gas_allowance_yocto):
    """Reject invalid reviewer policy before even optional public RPC reads."""
    if not _valid_account_id(receiver):
        raise ValueError("invalid expected receiver")
    if (not isinstance(allowed_methods, tuple) or not allowed_methods or
            any(type(m) is not str or not METHOD_RE.fullmatch(m) for m in allowed_methods)):
        raise ValueError("allowed methods must be a nonempty tuple of method names")
    if type(max_gas_allowance_yocto) is not int or max_gas_allowance_yocto < 0:
        raise ValueError("invalid gas cap")

def assess_permission(permission, *, receiver, allowed_methods, max_gas_allowance_yocto):
    """Compare *one selected agent key* against declared reviewer policy.

    POLICY_MATCH_UNVERIFIED is a permission-shape observation, never approval
    of a contract's own asset transfers, delegated identity, or settlement.
    """
    _validate_review_policy(receiver, allowed_methods, max_gas_allowance_yocto)
    if permission in ("FullAccess", "GasKeyFullAccess"):
        return {"decision": "REVIEW_REQUIRED", "findings": ["FULL_ACCESS_AGENT_KEY"],
                "trade_authorized": False, "private_key_inspected": False,
                "allowance_kind": "GAS_ONLY_NOT_ASSET_SPEND_LIMIT"}
    if type(permission) is not dict or set(permission) != {"FunctionCall"}:
        return _unknown()  # GasKeyFunctionCall needs independent balance validation.
    grant = permission["FunctionCall"]
    if type(grant) is not dict or set(grant) != {"receiver_id", "method_names", "allowance"}:
        return _unknown()
    observed_receiver = grant["receiver_id"]
    methods = grant["method_names"]
    raw_allowance = grant["allowance"]
    if (not _valid_account_id(observed_receiver) or
            type(methods) is not list or any(type(m) is not str or not METHOD_RE.fullmatch(m) for m in methods)):
        return _unknown()
    if raw_allowance is not None and (type(raw_allowance) is not str or
            not raw_allowance.isascii() or not raw_allowance.isdecimal() or
            len(raw_allowance) > 60):
        return _unknown()
    findings = []
    if observed_receiver != receiver:
        findings.append("RECEIVER_OUTSIDE_POLICY")
    if not methods:
        findings.append("ALL_RECEIVER_METHODS_ALLOWED")
    elif any(m not in allowed_methods for m in methods):
        findings.append("METHOD_OUTSIDE_POLICY")
    if raw_allowance is None:
        findings.append("UNLIMITED_GAS_ALLOWANCE")
    elif int(raw_allowance) > max_gas_allowance_yocto:
        findings.append("GAS_ALLOWANCE_EXCEEDS_POLICY")
    return {"decision": "REVIEW_REQUIRED" if findings else "POLICY_MATCH_UNVERIFIED",
            "findings": findings, "trade_authorized": False,
            "private_key_inspected": False,
            "allowance_kind": "GAS_ONLY_NOT_ASSET_SPEND_LIMIT"}


def _unique_object_pairs(pairs):
    """Reject ambiguous untrusted JSON keys instead of silently taking the last."""
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("duplicate JSON object key")
        obj[key] = value
    return obj


def assess_rpc(payload, *, receiver, allowed_methods, max_gas_allowance_yocto,
               provenance="UNATTESTED_RPC_RESULT"):
    """Check NEAR view_access_key JSON-RPC envelope then permission shape."""
    failure = {"decision": "UNVERIFIED_RPC_RESPONSE", "findings": ["RPC_RESPONSE_UNVERIFIED"],
               "trade_authorized": False, "rpc_cryptographic_proof_verified": False,
               "data_provenance": provenance}
    if (type(payload) is not dict or payload.get("jsonrpc") != "2.0" or
            payload.get("id") != REQUEST_ID or "error" in payload):
        return failure
    body = payload.get("result")
    if (type(body) is not dict or type(body.get("block_height")) is not int or
            body["block_height"] < 0 or type(body.get("block_hash")) is not str or
            not body["block_hash"] or "permission" not in body):
        return failure
    report = assess_permission(body["permission"], receiver=receiver,
                    allowed_methods=allowed_methods,
                    max_gas_allowance_yocto=max_gas_allowance_yocto)
    return {**report, "block_height": body["block_height"],
            "block_hash": body["block_hash"], "data_provenance": provenance,
            "rpc_cryptographic_proof_verified": False,
            "trade_authorized": False}


class _DenyRedirect(request.HTTPRedirectHandler):
    """A pinned read-only RPC endpoint must not silently change destinations."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch_testnet_key(account, public_key, *, opener=None):
    """One bounded, opt-in, public-key-specific testnet RPC read, no credentials."""
    if not _valid_account_id(account) or not account.endswith(".testnet"):
        raise ValueError("testnet account required")
    if type(public_key) is not str or not PUBKEY_RE.fullmatch(public_key):
        raise ValueError("valid NEAR public key required")
    req = request.Request(ENDPOINT, method="POST", data=json.dumps({
        "jsonrpc": "2.0", "id": REQUEST_ID, "method": "query",
        "params": {"request_type": "view_access_key", "finality": "final",
                   "account_id": account, "public_key": public_key}},
        separators=(",", ":")).encode("utf-8"),
        headers={"Content-Type": "application/json", "Accept": "application/json"})
    # No ambient proxy and no HTTP redirects: a provider response cannot
    # silently redirect selected public-key queries to an unapproved host.
    direct_open = (opener if opener is not None else request.build_opener(
        request.ProxyHandler({}), _DenyRedirect()).open)
    try:
        with direct_open(req, timeout=7) as resp:
            if getattr(resp, "status", None) != 200:
                raise RuntimeError("RPC_UNAVAILABLE")
            raw = resp.read(MAX_RPC_BYTES + 1)
        if len(raw) > MAX_RPC_BYTES:
            raise RuntimeError("RPC_UNAVAILABLE")
        payload = json.loads(raw, object_pairs_hook=_unique_object_pairs)
        if type(payload) is not dict:
            raise RuntimeError("RPC_UNAVAILABLE")
        return payload
    except (OSError, ValueError, UnicodeError, RuntimeError) as exc:
        if isinstance(exc, error.HTTPError):
            exc.close()
        raise RuntimeError("RPC_UNAVAILABLE") from None


def main(argv=None):
    parser = argparse.ArgumentParser(description="Read-only NEAR agent-key scope review")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--fixture", help="Local JSON-RPC response fixture (synthetic)")
    group.add_argument("--live-testnet", action="store_true", help="Opt-in, exactly one public testnet RPC query")
    parser.add_argument("--account", help="NEAR testnet account; required for live")
    parser.add_argument("--public-key", help="Selected agent public key; required for live")
    parser.add_argument("--receiver", required=True, help="Only permitted function-call receiver")
    parser.add_argument("--method", required=True, action="append", help="Permitted method (repeat for more)")
    parser.add_argument("--max-gas-yocto", type=int, required=True, help="Maximum permitted gas allowance in yoctoNEAR")
    args = parser.parse_args(argv)
    # Validate declared intent before the opt-in live request. Invalid
    # reviewer input must never trigger RPC or an unhandled exception.
    try:
        _validate_review_policy(args.receiver, tuple(args.method), args.max_gas_yocto)
    except ValueError:
        print(json.dumps({"decision": "INVALID_REVIEW_POLICY",
                          "trade_authorized": False,
                          "signing_attempted": False,
                          "rpc_cryptographic_proof_verified": False},
                         sort_keys=True))
        return 2
    if args.live_testnet:
        if not args.account or not args.public_key:
            parser.error("live requires --account and --public-key")
        try:
            data = fetch_testnet_key(args.account, args.public_key)
        except RuntimeError:
            print(json.dumps({"decision": "UNVERIFIED_RPC_RESPONSE", "trade_authorized": False,
                              "data_provenance": "NETWORK_UNAVAILABLE"}, sort_keys=True))
            return 2
        provenance = "PUBLIC_TESTNET_RPC_UNATTESTED"
    else:
        try:
            with open(args.fixture, "rb") as f:
                raw = f.read(MAX_RPC_BYTES + 1)
            if len(raw) > MAX_RPC_BYTES:
                raise ValueError("oversized fixture")
            data = json.loads(raw, object_pairs_hook=_unique_object_pairs)
        except (OSError, ValueError):
            print(json.dumps({"decision":"UNVERIFIED_RPC_RESPONSE","trade_authorized":False,
                              "data_provenance":"MALFORMED_FIXTURE"}, sort_keys=True))
            return 2
        provenance = "USER_SUPPLIED_FIXTURE_NOT_LIVE"
    report = assess_rpc(data, receiver=args.receiver, allowed_methods=tuple(args.method),
                        max_gas_allowance_yocto=args.max_gas_yocto, provenance=provenance)
    print(json.dumps(report, sort_keys=True))
    return 0 if report["decision"] == "POLICY_MATCH_UNVERIFIED" else 2


if __name__ == "__main__":
    sys.exit(main())
