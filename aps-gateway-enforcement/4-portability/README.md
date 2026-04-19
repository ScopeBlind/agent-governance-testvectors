# Vector 4 — Receipt portability

## What this proves

A single APS gateway decision is verifiable by **three independent
verifier ecosystems** with no APS-specific code in the verification path
of two of them. The same Ed25519 signing key produces a v2 envelope
receipt (verified by APS SDK and `@veritasacta/verify`) and a DSSE
envelope wrapping an in-toto Statement (verified by any DSSE consumer).

This is the cross-verifier proof. APS is not a closed format; receipts
are independently auditable by anyone with the public key, using
infrastructure that is already deployed at the supply-chain layer
(in-toto/SLSA, DSSE).

This answers desiorac's question on OWASP#802: "if APS were to disappear
tomorrow, would these receipts still be verifiable?"

## Files

| File | Role |
|------|------|
| `input.json` | The original tool-call request. |
| `receipt.json` | v2 envelope decision receipt, signed. Verified by APS SDK and `@veritasacta/verify`. |
| `in-toto-statement.json` | An in-toto Statement (`https://in-toto.io/Statement/v1`) whose `predicate` is the v2 receipt and whose `predicateType` is `https://aeoess.com/aps/decision-receipt/v2`. |
| `intoto-envelope.json` | DSSE envelope wrapping the in-toto Statement, signed with the same Ed25519 key. Verified by any DSSE consumer. |
| `jwks.json` | JWKS containing the signing key. |
| `expected-output.json` | The three expected verifier outcomes, all `VALID`. |
| `verify-aps.sh` | Verifier 1 — APS SDK's own canonicalize() + verify(). |
| `verify-veritasacta.sh` | Verifier 2 — `npx @veritasacta/verify@0.3.0`. Independent npm-published Ed25519 verifier. |
| `verify-intoto.sh` | Verifier 3 — DSSE PAE + Ed25519 with the Python `cryptography` lib. ~30 lines, no APS code. |

## How to run

```sh
./verify-aps.sh           # verifier 1 of 3 — APS SDK
./verify-veritasacta.sh   # verifier 2 of 3 — @veritasacta/verify
./verify-intoto.sh        # verifier 3 of 3 — DSSE / in-toto
```

Each script exits 0 and prints `valid: true`. All three accepting the
same logical decision proves the receipt is portable across at least one
proprietary verifier (APS), one independent verifier (`@veritasacta`),
and one supply-chain-standard verifier (DSSE).

## Two artifacts, one decision

The v2 envelope and the DSSE envelope are not the same byte sequence —
they have different signatures because each verifier ecosystem has its
own canonicalization and pre-authentication recipe. They are the same
**logical decision** because:

1. The DSSE envelope's payload is an in-toto Statement.
2. The Statement's `predicate` is byte-identical to `receipt.json`.
3. The Statement's `predicateType` declares the predicate as a v2
   APS decision receipt.
4. Both signatures were produced by the same Ed25519 private key
   (matching the JWK in `jwks.json`).

A consumer who trusts the DSSE envelope can extract the embedded receipt
and re-verify it under APS or `@veritasacta` and reach the same answer.

## Required tooling

- **verify-aps.sh**: Node 18+. The APS SDK at `/Users/tima/agent-passport-system` (or set `APS_SDK_PATH`).
- **verify-veritasacta.sh**: Node 18+ with network access for `npx --yes @veritasacta/verify@0.3.0` (cached after first run).
- **verify-intoto.sh**: Python 3.8+ with `cryptography` (`pip install cryptography`).

The JWKS-only path means no proprietary key infrastructure is required;
any of these verifiers can swap in a different transport for the public
key (TUF, Sigstore Rekor, JWKS over HTTPS, hard-coded in code) without
affecting the signature math.
