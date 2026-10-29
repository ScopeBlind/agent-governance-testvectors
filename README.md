# agent-governance-testvectors

**Interop:** CI replays the receipt-signature corpus of [agent-evidence-vectors](https://github.com/probityai/agent-evidence-vectors) v0.24.0 against the pinned verifier, 25 of 25: [latest run](https://github.com/ScopeBlind/agent-governance-testvectors/actions/workflows/conformance.yml).

Shared test vectors for conformance between implementations of
[`draft-farley-acta-signed-receipts`](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/).

Several implementations emit the receipt format today. Four pass every
check here in CI: protect-mcp (TypeScript, maintained by the draft's author)
and three independent Python implementations, nobulex, the APS governance hook
and cryptovalid-opencore. Two more by the draft's author do not yet:
protect-mcp-adk has no driver, and sb-runtime still emits an older envelope.
[Status](#status) has the details. The same input JSON plus the same Cedar
policy plus the same test keypair must produce a receipt chain that a
conformant verifier accepts. The fixed seed pins the key, not the bytes:
timestamps differ across implementations, and no check compares signature
bytes between them.

`verifier-vectors/` tests the other side: fixed receipts and key sets, and the
outcome a verifier must reach, for cases such as a key used outside its
validity window, where every signature is valid and the verdict still has to
be a rejection.

## Start here

- [Run the existing suite](#running-locally).
- [Inspect results, exact revisions and limitations](docs/project-evidence.md).
- [Add an implementation](#adding-a-new-implementation) or report a reproducible disagreement.
- [Read the check history](docs/check-history.md), including fixes contributed by other maintainers.

## Why this exists

If there are several implementations of a wire format, "it works" is
provable only by checking each one's output the same way. A receipt chain
minted by nobulex, the APS governance hook or cryptovalid-opencore has to
pass the same checks as one minted by protect-mcp. This repo is where that
property gets tested instead of assumed.

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
├── protect-mcp/                 TypeScript driver (the reference implementation)
├── nobulex/                     Python driver
├── aps-governance-hook/         Python driver
├── cryptovalid-opencore/        Python driver
├── protect-mcp-adk/             Python driver (placeholder, not written yet)
└── sb-runtime/                  Rust driver (skips: see Status)
verifier-vectors/
├── key-window/                  Key validity windows (-03 Section 9.2)
├── revocation/                  A key revoked before issued_at (the gap: no revision defines revocation)
├── timeliness/                  One issued_at, alone and against an external chain commitment (Section 9.7)
├── signing-input/               A signature member in the object canonicalized, null included (Section 6.6)
├── chain-link/                  A previousReceiptHash alone, after a supplied predecessor, in a sequence (-03 Section 6.7; -04 editor's copy Section 6.7.1)
├── finos-mi24-decision-record/  FINOS MI-24 decision records as Acta receipt payloads, against the A-DoA schema v1.1.0; its own runner
└── run.mjs                      Runs these, argentum-core's farley vectors, and the embedded-key check
.github/workflows/
└── conformance.yml              CI running all implementations against fixtures
```

## Status

As of the [22 October 2026 run](https://github.com/ScopeBlind/agent-governance-testvectors/actions/runs/39722478336)
at commit `8043c5516defcd18492e534305f8fdbb72a7a09f` (Node 20 and Node 22):

| Implementation | Language | Maintained by | Result |
|---|---|---|---|
| protect-mcp | TypeScript | the draft's author | Conformant |
| nobulex | Python | independent ([#12](https://github.com/ScopeBlind/agent-governance-testvectors/pull/12)) | Conformant |
| APS governance hook | Python | independent ([#1](https://github.com/ScopeBlind/agent-governance-testvectors/pull/1)) | Conformant |
| cryptovalid-opencore | Python | independent ([#25](https://github.com/ScopeBlind/agent-governance-testvectors/pull/25)) | Conformant |
| GDI | Python | independent | Driver in review ([#7](https://github.com/ScopeBlind/agent-governance-testvectors/pull/7)) |
| protect-mcp-adk | Python | the draft's author | Skipped: no driver yet |
| sb-runtime | Rust | the draft's author | Skipped: emits the v0.1 envelope, which carries its own public key, so it is not conformant until it moves to the Acta envelope |

"Conformant" means all three checks pass: the schema, every signature under
the supplied key, and the chain against `expected/chain.jsonl`. One verifier
runs those checks for every implementation (see
[Reference verifier](#reference-verifier)); a matrix in which each
implementation's own verifier checks every other implementation's output is
still to do.

Elsewhere, public work implements or checks the format without a driver
here yet. Each description is the project's own:

- [asqav](https://github.com/jagmarques/asqav-sdk) (Python and TypeScript):
  its Internet-Draft
  [draft-marques-asqav-compliance-receipts](https://datatracker.ietf.org/doc/draft-marques-asqav-compliance-receipts/)
  is a compliance profile of draft-farley-acta-signed-receipts, signed with
  ML-DSA.
- [EMILIA](https://github.com/emiliaprotocol/emilia-protocol/tree/main/examples/acta-ep-join)
  (TypeScript): an example that checks `protectmcp:decision` receipts under a
  pinned issuer key and composes them with EMILIA's own receipts.
- [receipt-verify](https://github.com/LembaGang/receipt-verify) (TypeScript):
  a verifier whose CI checks published Acta receipts.
- Independent test sets: TRACE's Acta fixtures and verifier
  ([agentrust-io/trace-spec](https://github.com/agentrust-io/trace-spec/tree/main/examples/action-receipts/acta)),
  the agent-evidence-vectors corpus credited above, and argentum-core's
  `farley-receipt-signature` vectors, which `verifier-vectors/run.mjs` runs.

A driver for any of them is welcome: see
[Adding a new implementation](#adding-a-new-implementation).

## What the checks found about themselves

External contributors found and helped fix cases where the suite reported success
without checking the promised property. The [full history](docs/check-history.md)
records all fourteen findings, their fixes and contributor credit. It remains part
of the project record; current status and historical results are kept separate.

## Evidence predicate conformance

[`evidence-predicate/`](evidence-predicate/) is a separate semantic suite for the
OPTIONAL `evidence` field of -03 Section 4: eight signed `decision_receipt`s that
verify under the published verifier and settle, entry by entry, whether a basis
is independent corroboration or the signer's own word (Section 4.3), plus six
entries rejected on structure. Dependency-free; runs in CI beside the receipt
checks.

## Composition conformance

For APS, A2A, Hermes, and ACTA interop, this repo follows one rule: compose by content-hash reference, not by re-signing another system's receipt. See [docs/composition-conformance.md](docs/composition-conformance.md).

## Running locally

The nobulex and APS drivers need `pip install pynacl cedarpy agent-passport-system`;
without the required dependencies they report a skip (exit 77) rather than a failure.
The cryptovalid-opencore driver creates its own virtual environment and installs
its pinned package and dependencies, requiring network access on the first run.

```bash
# Run all drivers whose dependencies are installed
./conformance/run.sh

# Verify a directory of receipts against the schema and the reference chain
./conformance/verify.sh receipts/protect-mcp/
```

Each driver produces a `receipts/<implementation>/` directory. The
`verify.sh` script runs three checks:

1. Every receipt matches one of the two shapes in `expected/receipt-schema.json` (a JSON Schema validator, draft-07). The v1 flat and v2 envelope shapes stay in the schema's definitions for the record but are not accepted: the published verifier does not read them, measured on real sb-runtime output on 2026-09-13 (#21).
   Only the Acta 2.1 envelope is the shape the draft specifies; the others are
   recorded because real implementations emit them.
2. Every receipt's Ed25519 signature verifies against the test keypair, one
   verifier invocation per receipt.
3. Each receipt's `tool_name`, `decision` and policy identity (`policy_id` for
   the flat shapes, `policy_digest` for the envelope; a receipt carrying both has
   both checked) match the canonical chain in `expected/chain.jsonl`, and every
   `previousReceiptHash` reproduces as
   `"sha256:" + hex(SHA-256(JCS(previous receipt)))` per section 6.7 of
   draft-farley-acta-signed-receipts-03. A receipt that identifies no policy
   fails; a decision that does not say what it rested on is not evidence.

For `verify.sh`: exit 0 = all checks pass; exit 1 = at least one check failed;
exit 2 = usage error or a required command is missing. The aggregate runner
reports skipped drivers separately and fails if no implementation was verified.

The `policy_digest` in `expected/chain.jsonl` is not a hash of the policy file.
It is the section 6.8 construction, `acta-policy-digest-v1`: a manifest
`{construction, engine: "cedar", files: [{name: "autoresearch-safe.cedar", sha256}]}`
with each file hashed over its exact bytes, sorted by name, canonicalised with JCS,
then SHA-256, prefixed `sha256:`. `harness/policy-digest.py` recomputes it from the
fixture; the value in `chain.jsonl` must equal that output after any change to the policy.


## Adding a new implementation

1. Fork this repo
2. Create `implementations/<your-name>/` with an executable `run.sh` that
   reads from `fixtures/inputs/` and writes receipts to
   `receipts/<your-name>/`
3. Open a PR. CI runs `./conformance/verify.sh receipts/<your-name>/`.
   All three checks must pass; maintainers also review the implementation and
   its stated coverage before merging.

A disagreement may identify a producer defect, a verifier defect, an incorrect
fixture or an underspecified rule. Include the exact revisions, receipt and
expected outcome so it can be investigated. Do not change expected results merely
to make an implementation pass.

## Standards

- **Ed25519** (RFC 8032) for signatures
- **JCS canonicalization** (RFC 8785) before signing
- **Cedar** (AWS) for policy evaluation
- **IETF draft** [`draft-farley-acta-signed-receipts`](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/) for the wire format
- **In-toto predicate** (proposed at [in-toto/attestation#549](https://github.com/in-toto/attestation/pull/549)) for attestation framing

## Reference verifier

The tests use [`@veritasacta/verify`](https://www.npmjs.com/package/@veritasacta/verify)
as the reference verifier. Its source is public and its behavior is
documented, but it is maintained by the draft's author, who also maintains
protect-mcp, so a verifier from someone else is the most useful addition.
One exists: the TRACE specification ships an independently written Acta
receipt verifier
([agentrust-io/trace-spec#469](https://github.com/agentrust-io/trace-spec/pull/469)),
not yet run here. Independent test data also checks the reference verifier:
`verifier-vectors/` replays the
[agent-evidence-vectors](https://github.com/probityai/agent-evidence-vectors)
receipt-signature corpus against it. Additional verifiers welcome as PRs.

## License

Apache-2.0. Same as the `sb-runtime` and `@veritasacta/verify` codebases.

## Acknowledgements

Started in response to [google/adk-python#5164](https://github.com/google/adk-python/issues/5164)
where @aeoess offered to contribute a worked example demonstrating interop
between the APS governance hook and `protect-mcp-adk`. This repo is the
shared ground for that example and every similar cross-implementation
demonstration.

Most of what makes the suite trustworthy came from outside contributors:

- @arian-gogani: the nobulex driver, the audit in #13 that made the checks
  gate, and the embedded-key negative vectors;
- @aeoess: the APS vectors and driver;
- @robertolocatelli81-dev: the cryptovalid-opencore driver;
- @astrogilda: the revocation and timeliness vectors, the
  agent-evidence-vectors replay and the pinned signing key;
- @mj3b: the GDI driver, in review.
