# APS gateway enforcement test vectors

Four vectors demonstrating the enforcement primitives the APS gateway
exposes above the policy-evaluation layer. Contributed in response to
[OWASP/www-project-ai-security-and-privacy-guide#802](https://github.com/OWASP/www-project-ai-security-and-privacy-guide/issues/802),
answering @desiorac's three open questions on what an "enforcement
primitive" looks like in practice.

## The four vectors

| # | Vector | What it proves |
|---|--------|----------------|
| 1 | [`1-fail-closed/`](./1-fail-closed/) | Policy passes; receipt-signing fails. `executeToolCall()` is never reached. Returns structured `PolicyEvaluationError`. No side effects. Audit log records the failure unsigned. |
| 2 | [`2-external-verification/`](./2-external-verification/) | The receipt format is portable. Verification needs only `openssl`, `jq`, and Python's stdlib — no APS code, no `@veritasacta/*` packages. |
| 3 | [`3-state-drift/`](./3-state-drift/) | A delegation revoked between sign-time and execute-time triggers a `StateHashMismatch` abort. The receipt's signature is still valid; the world it described changed. |
| 4 | [`4-portability/`](./4-portability/) | One decision, three independent verifier ecosystems: APS SDK, `@veritasacta/verify`, and an in-toto/DSSE consumer. All three return `VALID`. |

## How to run each vector

```sh
# Vector 1: read three files; no crypto check (the point is the absence of a receipt)
cat 1-fail-closed/expected-output.json

# Vector 2: openssl-only verification of the v2 envelope
./2-external-verification/verify-external.sh

# Vector 3: re-verify the receipt's signature, then compare state hashes
node _scripts/verify-with-aps-sdk.mjs 3-state-drift/receipt.json
diff <(jq -r .payload.state_hash_at_signing 3-state-drift/receipt.json) \
     <(python3 -c '...')   # see 3-state-drift/README.md for the full snippet

# Vector 4: three verifiers
./4-portability/verify-aps.sh
./4-portability/verify-veritasacta.sh
./4-portability/verify-intoto.sh
```

## Cryptographic setup

| Field | Value |
|-------|-------|
| Algorithm | Ed25519 (RFC 8032) |
| Seed | `0000000000000000000000000000000000000000000000000000000000000001` (matches `fixtures/keys/README.md`) |
| Public key (hex) | `4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29` |
| `kid` (JWK thumbprint, RFC 7638) | `3iR-H6Xx_3rpt7eNMUVNazSZkUclb_cekBJZZL4mlUs` |
| Issuer | `aps:gateway:test` |
| Receipt shape | v2 envelope per the repo's [`expected/receipt-schema.json`](../expected/receipt-schema.json) |

## Re-generating the artifacts

```sh
node _scripts/generate.mjs
```

Output is byte-deterministic given the fixed seed. Self-verification runs
at the end of generation; the script exits non-zero if any artifact fails
to round-trip under the APS SDK's own primitives.

## What this is not

These vectors target the **enforcement** boundary above the policy
engine: receipt signing, executor pre-flight, state-drift detection,
cross-ecosystem verifier portability. They do **not** test:

- Cedar policy evaluation correctness (that's covered by the
  `fixtures/policy/` + `fixtures/inputs/` suite at the repo root).
- Distributed revocation propagation timing (out of scope; per-instance
  enforcement only).
- Sybil resistance or identity issuance (separate concern; the gateway
  here treats the agent identity as input).

## Files

```
aps-gateway-enforcement/
├── README.md                           This file.
├── 1-fail-closed/
│   ├── README.md
│   ├── input.json
│   ├── fault-injection.json
│   ├── expected-output.json
│   └── audit-log.json
├── 2-external-verification/
│   ├── README.md
│   ├── input.json
│   ├── receipt.json                    v2 envelope, signed.
│   ├── jwks.json
│   ├── canonical.txt                   Bytes that were signed.
│   ├── expected-output.json
│   └── verify-external.sh              openssl + jq + python3 only.
├── 3-state-drift/
│   ├── README.md
│   ├── input.json
│   ├── state-at-signing.json           Delegation active.
│   ├── state-at-execution.json         Delegation revoked.
│   ├── receipt.json                    Signed at signing-time state.
│   └── expected-output.json            StateHashMismatch abort.
├── 4-portability/
│   ├── README.md
│   ├── input.json
│   ├── receipt.json                    v2 envelope.
│   ├── in-toto-statement.json          Statement with receipt as predicate.
│   ├── intoto-envelope.json            DSSE envelope around the Statement.
│   ├── jwks.json
│   ├── expected-output.json            All three verifiers VALID.
│   ├── verify-aps.sh
│   ├── verify-veritasacta.sh
│   └── verify-intoto.sh
├── _keys/
│   ├── jwks.json                       Shared JWKS for all vectors.
│   └── public-key.json                 Pubkey + derivation note.
└── _scripts/
    ├── lib.mjs                         Shared crypto + canonicalize + DSSE PAE.
    ├── generate.mjs                    Deterministic artifact generator.
    └── verify-with-aps-sdk.mjs         APS-SDK verifier (Node).
```

## Status of each vector

| Vector | APS SDK | @veritasacta/verify | openssl | DSSE |
|--------|:-------:|:-------------------:|:-------:|:----:|
| 1 (fail-closed) | n/a — no signed artifact | n/a | n/a | n/a |
| 2 (external)    | VALID | VALID | VALID | n/a |
| 3 (state-drift) | VALID (signature) → ABORT (state) | VALID (signature) | n/a | n/a |
| 4 (portability) | VALID | VALID | n/a | VALID |

Verified locally against `@veritasacta/verify@0.3.0`, Node 18+, OpenSSL 3,
Python 3 + `cryptography`.
