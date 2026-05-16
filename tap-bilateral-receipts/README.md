# TAP bilateral receipt fixture

Specimen payloads for Visa Trusted Agent Protocol issue #16. The fixture keeps authentication and evidence separate:

- TAP request authentication remains represented by the RFC 9421 `signature-input` in `tap-request.json`.
- Transaction evidence is represented by two detached JWS-style receipts over JCS-canonical payloads.
- The agent signs the pre-execution authorization receipt.
- The merchant or TAP-aware proxy signs the post-execution outcome receipt.

Files:

- `tap-request.json` - simulated TAP request context and RFC 9421 signature metadata.
- `authorization-receipt.json` - agent-signed pre-execution authorization receipt.
- `outcome-receipt.json` - merchant-signed post-execution outcome receipt.
- `keys.json` - deterministic Ed25519 public keys used by the fixture.
- `verify.py` - verifies both signatures and cross-links.

Run:

```bash
python3 verify.py
```

Expected result:

```text
PASS authorization receipt signature
PASS outcome receipt signature
PASS request hash links both receipts to the TAP request
PASS outcome receipt chains to authorization receipt
```

The fixture is intentionally narrow: it does not propose TAP core changes. It demonstrates the evidence layer that can sit after TAP request authentication without overloading RFC 9421 with transaction-proof semantics.
