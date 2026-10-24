# GDI driver

**Governed Decision Intelligence** conformance driver contributed by
[@mj3b](https://github.com/mj3b) in [PR #7](https://github.com/ScopeBlind/agent-governance-testvectors/pull/7).

- **License:** Apache-2.0
- **Spec:** https://github.com/mj3b/governed-decision-intelligence
- **Contact:** @mj3b
- **Format:** the `decision_receipt` compatibility shape accepted by this suite;
  not the Acta 2.1 envelope specified in the published Internet-Draft.

## What this driver checks

The driver evaluates the exact bytes of `fixtures/policy/autoresearch-safe.cedar`
using the Rust Cedar engine through `cedarpy`. It embeds a demonstration Governed
Decision Record (GDR) in `payload.gdr`. The `payload.result_hash` field is
`"sha256:"` + hex(SHA-256(JCS(GDR))), binding:

- `confidence_score`: numeric score against institutional thresholds (here a fixed fixture value)
- `gate_classification`: `routine | elevated_review | mandatory_escalation | blocked | deferred`
- `reasoning_reconstruction`: plain-language explanation of the decision
- `evidence_sources`: completeness classification per input source
- `accountability_chain`: named roles and responsibilities

In this driver, confidence scores and role names are fixture values, not measured
confidence, corroborating evidence, or evidence of a real person's approval. No
threshold is applied and no tool executes. A valid signature authenticates the
recorded bytes under the supplied test key; it does not establish the truth or
quality of the reasoning.

The chain and policy digest follow the published
[draft-farley-acta-signed-receipts-03](https://datatracker.ietf.org/doc/html/draft-farley-acta-signed-receipts-03)
Sections 2.2, 6.7 and 6.8:

- `payload.previousReceiptHash` is absent on the genesis receipt.
- Each later value is `"sha256:"` plus the lowercase hex SHA-256 of the JCS form
  of the **whole previous receipt as signed**, signature included.
- `policy_digest` is the `acta-policy-digest-v1` manifest digest over the exact
  policy bytes evaluated.

The signature covers JCS of the receipt without its `signature` member, the
Section 6.6 rule for a receipt whose signature is a hex string, as in the suite's
`decision_receipt` shape. Canonicalization uses the `rfc8785` package.

Cedar errors fail the driver. Every fixture is evaluated and signed before
replacing the prior output, so a bad later fixture does not leave a partial new
chain. `expected_decision` is never used to derive a decision.

The bilateral pattern (one receipt sealed over the pre-execution GDR as intent,
a second over the post-execution result, chained by `previousReceiptHash`) is
not implemented yet; this driver emits one receipt per fixture.

## Run from the repository root

Use Python 3.10+ and Node/npm for the shared verifier:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r implementations/gdi/requirements.txt
bash implementations/gdi/run.sh
bash conformance/verify.sh receipts/gdi
python -m unittest discover -s implementations/gdi -p 'test_*.py' -v
```

Receipts go to `receipts/gdi/`. The suite verifies **every file separately**:
the verifier takes one receipt per invocation, so do not pass it a glob. The
shared suite verifies with the fixture public key from `fixtures/keys/README.md`,
supplied separately from the receipt; `key.hex` records the same key for manual
checks. All signing key material in this driver is public test material and
must never be used for production.

The regression tests include malformed chain conventions, mutation of signed
GDR fields, policy replacement, Cedar evaluation errors, nested inputs, JCS
number/key-order behavior, and preservation of previous output on failed runs.
