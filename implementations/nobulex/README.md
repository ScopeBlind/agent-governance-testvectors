# nobulex

Conformance driver for the agent-governance-testvectors suite.

## Running

```bash
pip install pynacl          # or: pip install cryptography
./implementations/nobulex/run.sh
```

Writes one receipt per fixture to `receipts/nobulex/`.

## Shape

`decision_receipt`, the shape this repository's own `aps-gateway-enforcement/`
reference receipts carry and the shape `@veritasacta/verify` reports as
`v2 (draft-farley-acta-signed-receipts-03)`.

The receipt carries no inline public key. `draft-farley-acta-signed-receipts`
says a verifier must not accept a key transported inside the envelope unless it
is independently anchored, so `kid` names the key and resolving it is the
verifier's job. `kid` is the RFC 7638 JWK thumbprint of the public half of the
shared conformance seed in `fixtures/keys/README.md`, which is why it matches
the `kid` on the `aps-gateway-enforcement` receipts.

Signature is Ed25519 (RFC 8032) over the RFC 8785 canonical bytes of the whole
envelope with `signature` removed, hex encoded.

## Two properties this driver holds itself to

**It never reads `expected_decision`.** Decisions come from parsing and
evaluating `fixtures/policy/autoresearch-safe.cedar`. `cedar_lite.py` is a
small evaluator for the subset of Cedar that policy uses, not a Cedar
implementation, and it says so at the top of the file. A driver that reads the
fixture's expected answer is copying the answer key, and until #14 the suite
would have reported it conformant. That is finding 6 in #13.

**Its parent-hash canonical form is byte-identical to the checker's.** If a
driver computed a different canonical form, every parent hash would mismatch
and the failure would look like tampering rather than like disagreement about
bytes.

## Files

| File | Contents |
|---|---|
| `run.sh` | entry point, matches the other drivers' contract |
| `emit.py` | evaluates each fixture, signs, writes `receipts/nobulex/` |
| `cedar_lite.py` | the policy evaluator, so decisions are derived and not copied |
