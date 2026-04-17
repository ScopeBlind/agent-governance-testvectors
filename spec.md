# Conformance Specification

This document describes what an implementation must do to claim conformance
with `draft-farley-acta-signed-receipts` as tested by this repo.

## What a conformant implementation does

Given a Cedar policy `P` and a list of tool-call inputs `[I_1, I_2, ...]`
plus a deterministic keypair `K`, an implementation must:

1. Evaluate each `I_i` against `P` using the Cedar semantics defined in
   the [Cedar language reference](https://docs.cedarpolicy.com/).
2. For each evaluation, produce a receipt `R_i` with the fields listed in
   [`expected/receipt-schema.json`](./expected/receipt-schema.json).
3. Each receipt's `parent_receipt_hash` (except the first) must be the
   SHA-256 of the JCS-canonical form of `R_{i-1}`.
4. Sign each receipt with Ed25519 over the JCS-canonical payload.
5. Write the receipt chain to disk as a directory of per-receipt JSON
   files, ordered by `sequence`.

## What conformance is NOT

Conformance does not require:

- **Byte-identical JSON serialization at the file level.** The file can
  have any whitespace and key ordering; only the JCS-canonical form (the
  signed bytes) must be byte-identical.
- **Identical `receipt_id` values.** The `receipt_id` can be chosen by the
  implementation; only the signature and chain integrity matter.
- **Identical timestamps.** Each implementation picks its own wall clock
  time for `timestamp`. The chain still verifies because timestamps are
  signed, and cross-implementation verification only checks signatures +
  chain links, not timestamp equality.

## The three checks

Every conformant implementation must pass these three checks:

| # | Check | Where |
|---|-------|-------|
| 1 | Each produced receipt matches one of the two schema shapes (v1 flat or v2 envelope) | `expected/receipt-schema.json` |
| 2 | Each receipt's Ed25519 signature verifies against the public key | Signature validation with `fixtures/keys/public.hex` |
| 3 | The chain of `parent_receipt_hash` (v1) or `prev_hash` (v2) values forms a valid ordered chain from genesis to the final receipt | Walk the chain |

`@veritasacta/verify` performs checks 2 and 3 automatically and accepts
both receipt shapes. Check 1 is a shape-level test run by
`conformance/verify.sh`.

## Two conformant receipt shapes

The format has accumulated two interoperable shapes. A conformant receipt
is one OR the other; `@veritasacta/verify` accepts both, and the
test-vector schema uses `oneOf` to allow either.

### v1 flat (used by protect-mcp, protect-mcp-adk)

```json
{
  "receipt_id": "rcpt-a8f3c9d2",
  "receipt_version": "1.0",
  "tool_name": "Bash",
  "decision": "allow",
  "policy_id": "autoresearch-safe",
  "timestamp": "2026-04-17T12:34:56Z",
  "parent_receipt_hash": "sha256:...",
  "public_key": "4437ca56...",
  "signature": "4cde814b..."
}
```

### v2 structured envelope (used by sb-runtime, APS)

```json
{
  "payload": {
    "type": "scopeblind.receipt.v1",
    "decision": "allow",
    "action": { "kind": "exec", "target": "/usr/bin/git" },
    "policy_id": "autoresearch-safe",
    "sequence": 1,
    "prev_hash": "sha256:...",
    "timestamp": "2026-04-17T12:34:56Z"
  },
  "signature": "...",
  "pubkey": "..."
}
```

The two shapes express the same facts with different field layouts. The
JCS-canonical bytes signed over differ between shapes; the signature still
verifies because the signer and verifier agree on which bytes to sign
within each shape. A v1 verifier does not verify v2 receipts and vice
versa without the polyglot logic that `@veritasacta/verify` implements.

A future v0.3 spec revision of this repo may converge the two shapes.
Until then, conformance means producing at least one shape correctly and
having the reference verifier accept the output.

## Cedar evaluation semantics

The policy in `fixtures/policy/autoresearch-safe.cedar` uses standard Cedar
semantics:

- `permit` rules union: any matching `permit` grants access unless
  contradicted
- `forbid` rules are authoritative: any matching `forbid` denies access
  regardless of `permit` rules
- An input that matches no `permit` rule is denied by default

Implementations must use a Cedar engine for evaluation, either the
reference Rust implementation
([`cedar-policy`](https://github.com/cedar-policy/cedar))
or the WASM bindings
([`cedar-for-agents`](https://github.com/cedar-policy/cedar-for-agents)).

## Key material

The keypair in `fixtures/keys/` is **deterministic and for testing only**.
Every run of every implementation uses the same keypair. Production
deployments must generate their own keypairs; see
[key-management notes in the IETF draft](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/).

## Versioning

This spec is tied to `draft-farley-acta-signed-receipts-01`. When the
draft revises to `-02`, this repo will tag a v0.x release that exercises
the old format, and the `main` branch will move to the new format. Old
tags remain runnable for backwards-compatibility testing.

## Open questions

- **How to handle non-deterministic fields.** `receipt_id` is
  implementation-chosen. Currently the schema allows any string matching
  `^rcpt-[a-f0-9]+$`; conformance does not require a specific value. Should
  it? (Open for discussion on issues.)
- **How to handle optional fields.** `trust_tier` is optional; receipts
  that do not set it still conform. This may need tightening if
  cross-implementation consumers rely on the field.
- **Cross-implementation chain interleaving.** Can a chain contain receipts
  produced by different implementations? In principle yes, because the
  signature and chain verification are per-receipt. In practice this is
  not tested in v0.1. Target for v0.2.
