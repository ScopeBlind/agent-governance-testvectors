# agent-governance-testvectors

Shared test vectors for conformance between implementations of
[`draft-farley-acta-signed-receipts`](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/).

Four independent implementations emit the receipt format today. This repo
lets any of them prove interop against the others: the same input JSON
plus the same Cedar policy plus the same test keypair must produce a
receipt chain that any conformant verifier accepts.

## Why this exists

If there are four implementations of a wire format, "it works" is provable
only by cross-verification. A receipt minted by the Rust implementation
(`sb-runtime`) should verify against the TypeScript verifier
(`@veritasacta/verify`), against the Python implementation
(`protect-mcp-adk`), and against any future implementation. This repo is
where that property gets tested instead of assumed.

Also a place for a fifth, sixth, or seventh implementation to prove
conformance before their author calls it shipped.

## What is in here

```
fixtures/
├── keys/                        Deterministic test keypair (seed-based)
├── policy/                      Cedar policy used by all vectors
└── inputs/                      JSON inputs: tool calls to evaluate
expected/
├── receipt-schema.json          JSON Schema for receipt structure
└── chain.jsonl                  Canonical expected chain (the reference output)
conformance/
├── run.sh                       Exercise an implementation against fixtures
└── verify.sh                    Cross-implementation verification
implementations/
├── protect-mcp/                 TypeScript driver
├── protect-mcp-adk/             Python driver (stub; PR welcome)
├── sb-runtime/                  Rust driver (stub; PR welcome)
└── aps-governance-hook/         Python driver (stub; PR welcome)
.github/workflows/
└── conformance.yml              CI running all implementations against fixtures
```

## Status

- **v0.1** (this release): fixtures, expected schema, TypeScript driver,
  bash runner, GitHub Actions CI stub. Drivers for the other three
  implementations are placeholders inviting their authors to open PRs.
- **v0.2 target**: all four drivers plus a proper cross-verification
  matrix (every implementation's output verified by every verifier).

## Running locally

```bash
# Run all drivers whose dependencies are installed
./conformance/run.sh

# Verify a directory of receipts against the schema and the reference chain
./conformance/verify.sh receipts/
```

Each driver produces a `receipts/<implementation>/` directory. The
`verify.sh` script runs three checks:

1. Every receipt matches `expected/receipt-schema.json`
2. Every receipt's Ed25519 signature verifies against the test keypair
3. The chain of `parent_receipt_hash` values matches the canonical chain
   in `expected/chain.jsonl`

Exit 0 = all checks pass. Exit 1 = at least one check failed.

## Adding a new implementation

1. Fork this repo
2. Create `implementations/<your-name>/` with an executable `run.sh` that
   reads from `fixtures/inputs/` and writes receipts to
   `receipts/<your-name>/`
3. Open a PR. CI will run `./conformance/verify.sh receipts/<your-name>/`
   and accept the PR only if all three checks pass.

The fixtures and expected output are stable. If your implementation
produces output that does not match, either your implementation or the
expected output has a bug. Most of the time it is the former; when it is
the latter, open an issue explaining what diverged.

## Standards

- **Ed25519** (RFC 8032) for signatures
- **JCS canonicalization** (RFC 8785) before signing
- **Cedar** (AWS) for policy evaluation
- **IETF draft** [`draft-farley-acta-signed-receipts`](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/) for the wire format
- **In-toto predicate** (proposed at [in-toto/attestation#549](https://github.com/in-toto/attestation/pull/549)) for attestation framing

## Reference verifier

The tests use [`@veritasacta/verify`](https://www.npmjs.com/package/@veritasacta/verify)
as the reference verifier. This is independent of any single producer; its
source is public and its behavior is documented. Additional verifiers
welcome as PRs.

## License

Apache-2.0. Same as the `sb-runtime` and `@veritasacta/verify` codebases.

## Acknowledgements

Started in response to [google/adk-python#5164](https://github.com/google/adk-python/issues/5164)
where @aeoess offered to contribute a worked example demonstrating interop
between the APS governance hook and `protect-mcp-adk`. This repo is the
shared ground for that example and every similar cross-implementation
demonstration.
