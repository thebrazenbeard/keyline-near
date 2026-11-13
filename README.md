# KEYLINE — NEAR agent access-key security review

A working, read-only Python prototype for reviewing **one selected NEAR access key** against a declared receiver, function-method, and gas-allowance policy. Built for the November 2026 NEAR Hackathon AI Security & Defense track. This version demonstrates safeguards; it does **not** authorize transactions, prove contract safety, or connect to a wallet.

## Reproduce in five minutes (Python 3.10+, no dependencies)

Clone this public repository. From the project directory, run:

```sh
python -B -m unittest discover -s . -p 'test*.py' -q
python -B demo_server.py --port 0
```

**Expected:** the tests pass, and the second command prints a loopback URL such as `http://127.0.0.1:54321/`. Open that exact URL **on the same computer**. Click the five scenario cards and observe:

| Scenario | Expected outcome | Why |
| --- | --- | --- |
| Scoped function-call key | `REVIEW_ONLY` | Receiver/method/gas shape matches; contract effects still unknown |
| Simulated receiver injection | `BLOCK` | The receiver is not allowlisted |
| FullAccess key | `BLOCK` | The selected key is unrestricted |
| Wildcard methods | `BLOCK` | An empty method list enables all methods at the receiver |
| Unlimited gas | `BLOCK` | No bounded gas allowance exists |

Every JSON response reports `trade_authorized=false`, `signing_attempted=false`, and `contract_effects_verified=false`. All browser scenarios use **fictional local data** and make no external requests.

[View real browser screenshots and reproducible demo evidence](docs/DEMO_EVIDENCE.md) — the blocked receiver-injection case and scoped-key review were captured from this public source, not drawn as mockups.

## Run the offline CLI

```sh
python -B audit.py --fixture sample_access_key.json --receiver safe.contract.testnet --method read_profile --max-gas-yocto 100000000000000000000000
```

**Expected:** `POLICY_MATCH_UNVERIFIED`, `USER_SUPPLIED_FIXTURE_NOT_LIVE`, `trade_authorized:false` and exit code 0. A syntactically matching permission is **not approval to spend assets**.

For an explicitly chosen public testnet account and public key, a separate optional `--live-testnet` mode fetches **one** `view_access_key` query using a pinned provider endpoint, no redirects or ambient proxies. It neither proves RPC authenticity nor identifies who owns the key. The browser demo itself never invokes this network mode.

## What NEAR contributes

NEAR distinguishes `FullAccess` keys from `FunctionCall` access keys with a particular receiver, allowed method names, and an allowance. KEYLINE interprets this NEAR-native public permission structure and refuses to misstate a **gas** allowance as an **asset-spending** limit. It makes the difference between a narrow-looking key and a genuinely verified permission boundary explicit.

## Threat model and limits

- **No wallet, private key, signing endpoint, transfer, market feed, exchange, or deployed contract.** The local browser runs on `127.0.0.1` with an OS-selected port.
- A contract allowed by a FunctionCall key may itself transfer assets. A good-looking receiver/method match is not a verified contract effect.
- Provider JSON-RPC responses are **unattested**; no independent block proof or key ownership is checked.
- Only one *selected* key is reviewed. An account may have other keys, and a public key is not necessarily an AI agent's key.
- The five browser examples are fictional: they demonstrate policy behavior, not a real prompt-injection experiment or an audited wallet.
- The prototype uses only the Python standard library. Source code is published under the [MIT License](LICENSE); this does not certify wallet safety.

## Hackathon release requirements

This repository has been approved for **public code release under MIT**, but **has not been submitted to the NEAR Hackathon**. A human must separately publish an actual demo post on X meeting the organizer's requirements, choose their mainnet NEAR payout account, supply contact and team details, and approve the exact final application before **November 14, 2026, 23:59 UTC**. Check https://nearhackathon.com/HACKATHON.md for current rules. No prize or earnings are implied by this repository.
## Demo video

A [24-second silent KEYLINE walkthrough](demo/KEYLINE_hackathon_demo.mp4) shows real localhost browser outcomes for the five fictional access-key scenarios. The video is assembled from actual browser captures, not a recording of live funds, a wallet, or a real agent. The scoped case is review-only; unsafe receiver switching, FullAccess, wildcard grants, and unbounded gas are blocked.

The project has **not** been submitted to the NEAR Hackathon by publishing this video here. The event also requires a public demo post on X, published by the human, plus a completed and explicitly confirmed final entry.
