# Evidence Predicate Conformance Vectors

This directory defines dependency-free reference vectors for the `evidence`
predicate proposed in `draft-farley-acta-signed-receipts-03`.

The predicate distinguishes an assertion present inside a receipt from an
independent corroborating assertion. A named `authority` or matching `kid` is
never enough. The relying party must verify `source.sig` under an
out-of-band-pinned source key and determine that the key belongs to a control
domain distinct from the receipt signer.

## Run

```bash
./evidence-predicate/run.sh
```

The suite regenerates no artifacts in check mode. It fails if a committed
fixture is stale or if any expected verification result changes.

## Vector Set

| Vector | Result | What it proves |
| --- | --- | --- |
| `01-independent-corroboration` | independent | A custodian source key is pinned, distinct, and signs the reconstructed claim. |
| `02-independent-without-as-of` | independent | `as_of` is omitted from the signed claim when it is absent from the evidence entry. It is never encoded as `null`. |
| `03-forged-trusted-kid` | not independent | Copying a trusted source `kid` does not work when the source signature does not verify under that key. |
| `04-self-corroboration` | not independent | A receipt signer cannot use its own pinned key to manufacture independent corroboration. |

`invalid/null-as-of-entry.json` is a structural negative fixture. It confirms
that `as_of` may be absent but may not be encoded as `null`.

## Artifact Shape

Each vector contains:

- `receipt.json`: a signed, compact test receipt;
- `source-claim.json`: the exact reconstructed claim signed by `source.sig`;
- `expected.json`: expected receipt, source, and independence verdicts.

`schema/evidence-entry.schema.json` supplies the corresponding JSON Schema.

`trust-policy.json` is deliberately outside every receipt. It represents the
relying party's out-of-band trust policy and records both public keys and
control domains. This distinction is load-bearing: public-key inequality by
itself does not prove independent control.

The included script only implements the subset of JCS exercised by these
fixtures: ASCII member names, finite integers, and strings. It is adequate to
make the fixtures reproducible, but production implementations MUST use a
complete RFC 8785 implementation.

## Scope

These are semantic conformance vectors for the evidence predicate. They do
not replace a full receipt-format compatibility suite or provide a production
key directory. The deterministic test keys are public and MUST NOT be reused.
