# Negative conformance vector: embedded key rejection

A conformant implementation of `draft-farley-acta-signed-receipts` **MUST** reject receipts whose verification key was transported inside the signed payload, unless that key is independently anchored via an external trust mechanism.

This directory contains fixtures that test this rejection.

## Rationale

A tampering party controls both the payload and any fields within it. If the verifier accepts `payload.public_key` (or `payload.verification_key` or equivalent) as authoritative, it allows an attacker to:

1. Tamper with the payload to their desired content.
2. Generate a new keypair.
3. Re-sign the tampered payload with the new key.
4. Replace `payload.public_key` with the new public key.

The resulting receipt verifies cleanly under any verifier that trusts embedded keys, even though the signer is the attacker rather than the original issuer. This breaks the issuer-blind property the spec is designed to provide.

Published in coordination with:

- [`@veritasacta/verify` 0.4.0](https://github.com/VeritasActa/verify) — rejects embedded keys by default; deprecated `--allow-embedded-key` flag for one release cycle backward compatibility.
- [draft-farley-acta-signed-receipts-02](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/) Security Considerations — adds the normative MUST NOT.
- GetBindu PR #459 discussion where @desiorac surfaced the gap.

## Fixtures

| Fixture | What it tests | Expected verifier outcome |
|---|---|---|
| `001-passport-embedded-key.json` | Passport envelope with `payload.public_key` field | Exit 2 (undecidable), error `embedded_key_rejected` |
| `002-v1-flat-embedded-key.json` | v1 flat artifact with top-level `public_key` field | Exit 2 (undecidable), error `embedded_key_rejected` |
| `003-v2-embedded-verification-key.json` | v2 structured with `payload.verification_key` | Exit 2 (undecidable), error `embedded_key_rejected` |
| `004-passport-embedded-jwk.json` | Passport envelope with `payload.verification_jwk` | Exit 2 (undecidable), error `embedded_key_rejected` |

All four fixtures contain a real Ed25519 signature that would verify cleanly if the verifier accepted the embedded key. The rejection is a policy check, not a signature-validity check. That is the point: a signature that verifies under an attacker-chosen key is worse than no signature at all, because it provides false assurance.

## Expected output

For each fixture, `@veritasacta/verify <fixture>.json` (no `--key`, no `--jwks`, no `--trust-anchor`) MUST exit with status 2 and emit an error identifying the embedded-key pattern as the reason for rejection.

With `--allow-embedded-key` (deprecated escape hatch in 0.4.x, removed in 0.5.0): the signature verification proceeds against the embedded key. This is for migration purposes only and MUST NOT be used in production verifiers.

With an externally-sourced `--key`, `--jwks`, or `--trust-anchor` providing the correct public key: signature verification proceeds normally and the receipt verifies valid. The point is not to block the receipts themselves, only to block the trust path that relies on an attacker-controllable field.

## Running

```bash
# From testvectors repo root
npx @veritasacta/verify@^0.4.0 negative/embedded-key-rejection/001-passport-embedded-key.json
# Expected: exit 2, error "embedded_key_rejected"

# Verify the escape hatch path (deprecated)
npx @veritasacta/verify@^0.4.0 negative/embedded-key-rejection/001-passport-embedded-key.json --allow-embedded-key
# Expected: signature verifies (but this verification is NOT trustworthy; the fixture
# is signed with a key the attacker could have generated)
```
