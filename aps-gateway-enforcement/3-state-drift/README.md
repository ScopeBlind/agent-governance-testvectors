# Vector 3 — State-drift detection

## What this proves

A signed receipt is necessary but not sufficient. The gateway's executor
re-checks state immediately before each side-effecting call, and aborts
fail-closed when the state hash bound into the receipt no longer matches
the live state. Receipt freshness is enforced at execution time, not at
sign time.

In this vector a delegation is **active** when the receipt is signed and
**revoked** three seconds later, before `executeToolCall()` runs. The
gateway detects the drift via a `state_hash_at_signing` field in the
receipt payload, compares it against the live state hash, and aborts
with `state_hash_mismatch`. The receipt's signature is still valid — the
abort is not because the receipt was tampered with; it is because the
world the receipt describes no longer exists.

This answers desiorac's question on OWASP#802: "what stops a stale
receipt from authorising an action whose preconditions have changed?"

## Files

| File | Role |
|------|------|
| `input.json` | The tool-call request, with both `timestamp_signed_at` and `timestamp_executed_at` to make the time gap explicit. |
| `state-at-signing.json` | Delegation `dlg-vec3-research-bot-003` in `status: "active"` at signing time. The SHA-256 of its canonical form is what the receipt commits to. |
| `state-at-execution.json` | Same delegation, `status: "revoked"`, `revocation_reason: "operator_initiated"`. SHA-256 is different. |
| `receipt.json` | The decision receipt signed at the active state. The payload includes `state_hash_at_signing`. The receipt's Ed25519 signature is valid. |
| `expected-output.json` | The structured `StateHashMismatch` abort response: signature valid, but execution aborted because `state_hash_at_signing != live_state_hash`. Includes both hashes and a state diff so the operator can see what drifted. |

## How to verify

The receipt's signature still verifies under any verifier (it was a
correctly-signed receipt at the moment of signing):

```sh
node ../_scripts/verify-with-aps-sdk.mjs receipt.json
# valid: true
npx @veritasacta/verify receipt.json --key 4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29
# VALID
```

The state-drift check is a separate operation: compare the receipt's
`payload.state_hash_at_signing` against the SHA-256 of the canonical form
of `state-at-execution.json`. They differ. Therefore the gateway must
abort. `expected-output.json` shows the abort response shape.

```sh
# Demonstrate the drift:
EXPECTED="$(jq -r '.payload.state_hash_at_signing' receipt.json)"
ACTUAL_RAW="$(python3 -c 'import json,sys,hashlib; \
  o=json.load(open("state-at-execution.json")); \
  def s(x): return {k:s(x[k]) for k in sorted(x)} if isinstance(x,dict) else \
                  [s(i) for i in x] if isinstance(x,list) else x; \
  print("sha256:"+hashlib.sha256(json.dumps(s(o),separators=(",",":")).encode()).hexdigest())')"
test "$EXPECTED" != "$ACTUAL_RAW" && echo "drift detected → abort fail-closed"
```

## Why a `state_hash_at_signing` field

A bare signature over decision metadata leaves the gateway with no way to
detect drift later: the executor would have to reconstruct the entire
signing-time policy context from external sources (slow, error-prone,
network-dependent). Committing a single 32-byte digest of the
authority-bearing state into the signed payload makes drift detection a
local hash comparison. It is also the cheapest possible primitive to make
revocation actually enforced rather than merely advertised.

## What this is NOT proving

It does not prove that revocation propagates instantly across distributed
gateway instances; that is a separate problem (gossip protocol, CRDT,
revocation registry timing). It proves only that **once a single gateway
instance sees the revocation**, the very next `executeToolCall()` on that
instance will refuse to execute regardless of how recently the receipt
was signed.
