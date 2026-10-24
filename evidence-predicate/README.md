# Evidence predicate vectors

Reference vectors for the OPTIONAL `evidence` field of an Access Decision
Receipt, as published in
[draft-farley-acta-signed-receipts-03](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/03/)
Section 4, with the trust model of Section 4.3 and the failure mode of
Section 9.9. The predicate records what a decision rested on and whose
attestation that is. These vectors settle one question a relying party has to
answer for every entry: is this independent corroboration, or the receipt
signer's own word dressed up as someone else's?

Every receipt here is a `decision_receipt` that verifies under the published
verifier with the signer's key supplied out of band (`run.sh` checks this when
`npx` is available). The verifier ignores the predicate, as Section 4.2 allows;
judging it is the relying party's job, and `scripts/verify.mjs` does that job
with no dependencies beyond Node.

## Run

```bash
./evidence-predicate/run.sh
```

Regenerates nothing: `generate.mjs --check` fails on a stale artifact, then
`verify.mjs` judges each vector and each structural negative.

## The vectors

| Vector | Verdict | What it settles |
| --- | --- | --- |
| `01-independent-corroboration` | independent | An allow whose `data_rights` basis is attested by a custodian key the relying party pinned out of band, distinct from the signer. `alg` given explicitly. |
| `02-deny-on-failed-freshness` | independent | A deny on a failed `freshness` check attested by an independent administrator. No `as_of`, so the signed claim omits it. |
| `03-forged-trusted-kid` | not independent | The custodian's `kid` is named; the receipt signer made the signature. Section 9.9's named-key forgery. |
| `04-self-corroboration` | not independent | The signer signs the claim with its own pinned key. Everything verifies; it is still the signer's word. |
| `05-relabelled-signer-key` | not independent | The signer's key bytes pinned under a fresh `kid` and a different domain label. Section 4.3: the key bytes decide, not the label. |
| `06-extension-dimension` | independent | A vendor dimension in the `x-<vendor>:<name>` form, attested like any other. |
| `07-runtime-self-attested` | not independent | `authority: runtime:<component>`, no `kid`, no `sig`. The label is advisory; the absent signature is what counts. |
| `08-mixed-entries` | one of two | An attested `data_rights` beside a runtime-asserted `provenance`. Section 9.9: the two must be visibly distinguished. |

`invalid/` holds entries that are rejected before any signature is looked at,
each with the reason on file: `as_of: null`, the pre-publication `state`
vocabulary (`verified`), the hyphenated extension form, an un-namespaced
vendor dimension, an inline key inside `source`, and a `sig` with no `kid`.

## What each vector contains

- `receipt.json`: a signed `decision_receipt` whose payload carries `evidence`.
- `source-claims.json`: per entry, the exact claim `{ dimension, ref, state, as_of? }` that `source.sig` signs, or `null` for an unsigned entry.
- `expected.json`: per entry, the four conditions of Section 4.3 as booleans, the verdict, and a reason code; plus the list of dimensions that count as independent.

`trust-policy.json` is the relying party's out-of-band trust policy and is
deliberately outside every receipt. It records public keys and control
domains. Both matter: key inequality is necessary, and the control-domain
determination is the relying party's own. Its last entry is a trap, the
signer's key under a new name; vector 05 walks into it.

Reason codes: `source_signature_absent`, `source_key_not_pinned`,
`source_signature_invalid`, `source_key_not_independent`,
`independent_source_signature_verified`, `receipt_signature_invalid`.

## Scope

The JCS in `lib.mjs` covers only the value set these fixtures use (strings,
booleans, finite integers, arrays, objects with ASCII member names).
Production implementations MUST use a complete RFC 8785 implementation. The
test keys are derived from published seeds and MUST NOT be reused.

The predicate was proposed by Seydou Diaby (UseTruth) in VeritasActa/Acta#3.
