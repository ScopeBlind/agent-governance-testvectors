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
- **v0.3** (September 2026): the checks made to gate (see the next
  section), four receipt shapes recognised, the chain link pinned to
  section 6.7 of draft-farley-acta-signed-receipts-03, and a check 3 that
  compares each receipt's outcome to the expected chain. The reference driver
  now signs the decision protect-mcp actually makes (`sign --cedar`, 0.13.0)
  and passes all three checks on Node 22; on Node 20 it needs protect-mcp
  0.13.1 (see findings 9 and 10 below). CI runs on both.

## What the checks found about themselves

Between August and September 2026 this suite was found to report green on
receipt sets that did not conform. Every finding below was measured from a
clean clone, reproduced by the maintainer, and is fixed in the tree you are
reading. They are kept here because a conformance suite whose checks did not
check is the same failure the receipts exist to prevent, one level up.

1. `run.sh` printed `NON-CONFORMANT` and exited 0, so CI was green on a
   failing suite.
2. The reference driver produced zero receipts against the published CLI.
3. Check 2 never passed a key, so a missing key was reported as a tampered
   signature.
4. Checks 1 and 2 accepted disjoint sets. Both shapes the schema defined were
   unknown to the verifier, and the shape the verifier accepted failed the
   schema, including this repository's own reference receipts.
5. Check 3 computed an expected chain hash and then discarded it. Any
   non-empty link passed.
6. `expected_decision` was read by no code. A driver could ignore the policy,
   sign four receipts with arbitrary decisions, and be reported conformant.
   The reference driver was doing exactly that.
7. Check 2 handed the verifier a glob. It verified only the last file, so a
   driver could forge three of four signatures and still see `PASS`.
8. The fixture policy was not valid Cedar. Its Bash clauses used `in`, which
   is Cedar's entity-hierarchy operator, on a string (`"git" in ["git"]`);
   cedar-wasm reports a type error and, fail-closed, denies. A subset
   evaluator that treats `in` as list membership accepted it and matched the
   expected decisions, so the invalid policy was never noticed. The clauses
   now use `.contains()`, and `spec.md` records the rule.
9. The reference driver signed receipts whose denies were not decisions. On
   Node 20 the published protect-mcp could not load its Cedar engine (the
   package root's ESM entry imports a `.wasm` module, which Node 20 rejects),
   every evaluation was a fail-closed deny with reason
   `cedar_wasm_not_available`, and `sign` recorded each one as `cedar_deny`.
   Check 3 caught the wrong outcomes; the log could not say why. The driver
   now prints the evaluator's verdict per input and refuses to sign when the
   engine or policy failed to load, and protect-mcp 0.13.1 loads the engine
   through the package's `/nodejs` entry and records the evaluator's reason.
10. A driver's exit 77 ("cannot run on this runner") was counted as a
    failure, so every run was red whether or not anything failed. Skips are
    now reported as skips; the run fails only on a failure, or when nothing
    was verified at all.

Findings 1 to 7 were reported, with position-by-position measurements, by
[@arian-gogani](https://github.com/arian-gogani) in
[#13](https://github.com/ScopeBlind/agent-governance-testvectors/issues/13),
who also sent the fix for 7 ([#15](https://github.com/ScopeBlind/agent-governance-testvectors/pull/15))
and the second implementation ([#12](https://github.com/ScopeBlind/agent-governance-testvectors/pull/12)).
The schema half of finding 4 was independently reported through the draft's
errata review.

What changed: `run.sh` returns its verdict; check 2 loops over every receipt
with the fixture key; check 1 recognises the four shapes actually in use and
says which one the draft specifies; check 3 reads `expected/chain.jsonl`,
compares each receipt's outcome to it, cross-checks it against the fixtures'
`expected_decision`, and pins the chain link to section 6.7 of
draft-farley-acta-signed-receipts-03, naming which convention a
non-conformant producer actually used instead of failing with "mismatch";
the fixture policy is valid Cedar; the reference driver signs real decisions
and refuses to sign an engine outage; CI runs every driver on Node 20 and 22
and reports skips as skips.

The rule this leaves behind: a check that cannot fail manufactures confidence
rather than withholding it. Each check here was rewritten so that a planted
failure is caught, and the planted failures are recorded in the pull requests
that closed each finding.

## Composition conformance

For APS, A2A, Hermes, and ACTA interop, this repo follows one rule: compose by content-hash reference, not by re-signing another system's receipt. See [docs/composition-conformance.md](docs/composition-conformance.md).

## Running locally

```bash
# Run all drivers whose dependencies are installed
./conformance/run.sh

# Verify a directory of receipts against the schema and the reference chain
./conformance/verify.sh receipts/
```

Each driver produces a `receipts/<implementation>/` directory. The
`verify.sh` script runs three checks:

1. Every receipt matches one of the four shapes in `expected/receipt-schema.json`.
   Only the Acta 2.1 envelope is the shape the draft specifies; the others are
   recorded because real implementations emit them.
2. Every receipt's Ed25519 signature verifies against the test keypair, one
   verifier invocation per receipt.
3. Each receipt's `tool_name`, `decision` and policy identity (`policy_id` for
   the flat shapes, `policy_digest` for the envelope) match the canonical chain
   in `expected/chain.jsonl`, and every `previousReceiptHash` reproduces as
   `"sha256:" + hex(SHA-256(JCS(previous receipt)))` per section 6.7 of
   draft-farley-acta-signed-receipts-03. A receipt that identifies no policy
   fails; a decision that does not say what it rested on is not evidence.

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
