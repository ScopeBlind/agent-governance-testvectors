# Vector 1 — Fail-closed enforcement

## What this proves

The APS gateway is fail-closed at the receipt-signing boundary. A request
that **passes policy evaluation** but **fails to produce a signed receipt**
must not reach `executeToolCall()`. The gateway returns a structured
`PolicyEvaluationError`, no side effects occur, and the failure is
recorded in the audit log as an unsigned entry.

This answers desiorac's question on OWASP#802: "what does the gateway do
when the cryptographic primitive itself fails?" It does not silently
allow execution. It does not retry until success. It does not write a
fake receipt.

## Files

| File | Role |
|------|------|
| `input.json` | Tool-call request that **passes policy** (`http.get` permitted by the agent's delegation). |
| `fault-injection.json` | The injected fault: receipt-signer reports `signing_key_unavailable` even though the policy engine returned `allow`. |
| `expected-output.json` | The structured `PolicyEvaluationError` the gateway returns to the caller. `decision: "fail_closed"`, `receipt: null`, `tool_invoked: false`. |
| `audit-log.json` | The unsigned audit entry recording the failure. The note explains why this entry must not be re-signed after the fact. |

## Why no signed artifact

The vector's whole point is the **absence** of a signed receipt. If a
signed receipt existed, the failure would be invisible: the executor would
have proceeded, side effects would have occurred, and the only record
would be an audit gap. The gateway's contract is exactly the inverse — no
signed receipt means no execution, and the audit trail captures the
unsigned failure as evidence that the request was attempted.

## How to run

There is nothing to verify cryptographically (the point of the vector).
A consumer reading these files should check:

1. `expected-output.json` has `tool_invoked: false` and `receipt: null`.
2. `audit-log.json` has `signed: false` and `enforcement_outcome: "fail_closed"`.
3. The fault was injected at signing-time, not at policy-eval time
   (`fault-injection.json` shows `component: "receipt-signer"`).

These three together demonstrate the fail-closed property at the level
above the policy engine.
