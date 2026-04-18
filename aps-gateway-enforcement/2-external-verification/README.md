# Vector 2 — External verification

## What this proves

An APS gateway receipt is verifiable by anyone with the public key, using
nothing but standard tooling (`openssl`, `jq`, Python's stdlib). No
APS-specific code, no `@veritasacta/*` packages, no SDK. The receipt is a
self-contained piece of evidence; the only trust anchor is the Ed25519
public key.

This answers desiorac's question on OWASP#802: "is the receipt format
genuinely portable, or does it require the gateway's own software to
validate?"

## Files

| File | Role |
|------|------|
| `input.json` | The tool-call request the gateway evaluated. |
| `receipt.json` | v2 envelope decision receipt, signed by the gateway. |
| `jwks.json` | JWKS containing the signing key as a JWK (RFC 7517) with `kid` matching the receipt's `kid`. |
| `canonical.txt` | The exact UTF-8 byte string that was signed (the canonical form of the receipt with `signature` removed). Provided so a verifier can prove the round-trip without reimplementing canonicalization. |
| `expected-output.json` | What a successful verification produces. |
| `verify-external.sh` | The verification recipe. Uses only `openssl pkeyutl -verify -rawin`, `jq`, and Python's stdlib. No APS code. |

## How to run

```sh
./verify-external.sh
# VALID — openssl confirmed Ed25519 signature over canonical bytes
```

Exit 0 = valid, exit 1 = invalid, exit 2 = a required system tool is missing.

## What the script actually does

1. Pulls the public key (`x` field, base64url) and `kid` from `jwks.json`.
2. Confirms the receipt's `kid` matches.
3. Decodes the base64url pubkey to 32 raw bytes, prepends the standard
   Ed25519 SPKI prefix (`302a300506032b6570032100`), writes a DER, and
   asks `openssl pkey` to convert it to PEM.
4. Reproduces the canonical message bytes from `receipt.json` using
   `python3 -c json.dumps(sort_keys=True, separators=(',', ':'))` over
   the receipt with the `signature` field removed.
5. Decodes the hex signature to 64 raw bytes (`xxd -r -p`).
6. Calls `openssl pkeyutl -verify -inkey pub.pem -pubin -rawin -in
   message.bin -sigfile sig.bin`. Ed25519 in OpenSSL is single-shot
   PureEdDSA per RFC 8032; `-rawin` makes it operate on the message
   directly (no pre-hashing).

The canonicalization recipe — sort all object keys at every nesting
level, no whitespace — is byte-identical to what the APS SDK produces
when no field is `null` (the receipts in this directory are constructed
with no nullable fields so the two canonicalizers agree).

## What this is NOT proving

This does not prove that the policy decision was correct, that the
delegation existed, or that the agent had authority to make the request.
It proves only that the receipt as a string of bytes was signed by the
holder of a specific Ed25519 private key. Higher-level claims layer on
top of this primitive.
