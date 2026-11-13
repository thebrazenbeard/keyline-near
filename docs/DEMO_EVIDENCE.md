# KEYLINE — independently captured browser demonstration

These screenshots are **real local browser results**, not generated illustrations, accounts, mainnet wallet activity, or evidence that a transaction was attempted. The five demonstration inputs are intentionally fictional.

Source under test: [public KEYLINE main at `0db2f7fde2821e519c45ddf8b33ab9b41ed88e40`](https://github.com/thebrazenbeard/keyline-near/tree/0db2f7fde2821e519c45ddf8b33ab9b41ed88e40). Captured on November 13, 2026 using an isolated Windows Lappy working directory, a fresh read-only public-clone checkout, the source's actual localhost-only `demo_server.py`, and headless Microsoft Edge. The browser ran JavaScript clicks on the original five scenario cards and read their actual HTTP responses. No production wallet, private key, exchange API, app account, customer information, or external posting was accessed.

## Two actual policy outcomes

**1. Simulated receiver injection — BLOCK.** A fake request to change the receiver to `pay.attacker.testnet` is outside the declared policy.

![Actual KEYLINE local UI showing BLOCK for simulated receiver injection](keyline_blocked_demo.png)

**2. Narrow FunctionCall grant — REVIEW, not approval.** Receiver, method name, and gas allowance match the stated policy, but contract effects and asset spend limits remain unverified.

![Actual KEYLINE local UI showing REVIEW for a scoped function-call grant](keyline_review_demo.png)

## Reproduction checks

From a new public clone of the exact source commit, with Python 3.10+ and no third-party packages needed for the app or tests:

```sh
python -B -m unittest discover -s . -p 'test*.py' -q
python -B demo_server.py --port 0
```

On the machine running the demo, open the printed `http://127.0.0.1:<ephemeral-port>/` URL and click each case. The browser demo itself never contacts a NEAR RPC, signs, or sends a transaction. The CLI's opt-in testnet observation is a separate path.

An independent Lappy run of the **exact public commit** recorded:

| Check | Observed |
| --- | --- |
| Python normal unit tests | **30/30 PASS**, exit 0 |
| Python optimized `-O` unit tests | **30/30 PASS**, exit 0 |
| Live localhost landing page | **HTTP 200**, containing KEYLINE |
| Scoped function-call key | **REVIEW_ONLY**, local HTTP 200 |
| Simulated injected receiver | **BLOCK**, local HTTP 200 |
| FullAccess key | **BLOCK**, local HTTP 200 |
| Wildcard method list | **BLOCK**, local HTTP 200 |
| Missing gas allowance | **BLOCK**, local HTTP 200 |
| Deliberately cross-origin POST | **HTTP 403** |
| Network calls and signing in all scenario responses | **0** and **false** |

All scenario replies additionally had `trade_authorized=false`. Edge screenshots were captured **after** actual JavaScript clicks and policy responses, using Chrome DevTools Protocol on a temporary isolated browser profile; screenshot file content was checked as valid PNG and verified byte-for-byte against the GitHub image blobs.

Screenshot checksums (SHA-256):
- `keyline_blocked_demo.png`: `5c0fab9a9d2dc07c67a89cbd19f463198a9c203e502e3ce8f20898e90509a0f4`
- `keyline_review_demo.png`: `d2c822d4d1ca5c35635a67bb7f2bdf1153bcdd0f95674ae251723fca9b35ed22`

**Evidence ceiling:** this is a reproducible *fictional permission-policy* demo, **not** a wallet audit, cryptographically validated NEAR key ownership, a spend limit, an authenticated RPC proof, verified contract effects, or economic revenue.

**Contest status at capture:** repository publicly released under MIT; no X demo post, contest form, mainnet NEAR payout account, prize or payout is asserted by this evidence. Official closing deadline is 14 November 2026 at 23:59 UTC; check [organizer rules](https://nearhackathon.com/HACKATHON.md).