# Verifier vectors

Fixed receipts and key sets, and what a verifier must report about them. Where `implementations/` asks whether a
producer's receipts verify, this directory asks whether a verifier reaches the right outcome in the cases it can get
wrong while every signature is perfectly valid.

```bash
node verifier-vectors/run.mjs                                            # the pinned release, through npx
VERIFY_PKG=@veritasacta/verify@0.10.20 node verifier-vectors/run.mjs     # pin another release
VERIFY_CMD="node /path/to/verify-cli/cli.js" node verifier-vectors/run.mjs   # a local build
```

Exit status: 0 every case matched, 1 a case did not, 77 the pinned verifier cannot be installed here.

| Part | Draft section | Source |
|---|---|---|
| `key-window/` | -04 §5.5 (§9.2 of -03) | This repository. `key-window/scripts/generate.mjs` writes it; `--check` fails on a stale file. |
| `farley-receipt-signature` | -03 §5.1, §6.6, §9.2 | [giskard09/argentum-core](https://github.com/giskard09/argentum-core/tree/541ce84b4f970c1dd3d9e53f2a4562dbbc354e46/examples/conformance/farley-receipt-signature) (Apache-2.0), fetched at a pinned commit and never copied, so its `index.json` stays the source of truth. |
| `../conformance/check_embedded_key.sh` | §9.5 | [#24](https://github.com/ScopeBlind/agent-governance-testvectors/pull/24) (arian-gogani): a receipt's own key must never be trusted. |

## Key validity windows

One key (`test:rotating:ed25519`, seed `00..0b`, used nowhere else) with the window `[2026-01-01T00:00:00Z,
2026-06-01T00:00:00Z)`, and receipts it signed at different `issued_at` values:

| Receipt | Key set | Verdict | Code | Key status |
|---|---|---|---|---|
| `inside.json` | `jwks.json` | ACCEPT | | `inside` |
| `at-valid-from.json` | `jwks.json` | ACCEPT | | `inside` (the start is included) |
| `at-valid-until.json` | `jwks.json` | REJECT | `key_outside_validity_window` | `outside` (the end is excluded, as RFC 7519 treats `exp`) |
| `after-valid-until.json` | `jwks.json` | REJECT | `key_outside_validity_window` | `outside` |
| `before-valid-from.json` | `jwks.json` | REJECT | `key_outside_validity_window` | `outside` |
| `inside.json` | `jwks-no-window.json` | ACCEPT | | `no_window`: validity at issuance not established, never reported as valid |

`issued_at` is asserted by the signer, so a window catches a key still in use after an honest rotation, not a
compromised key backdated into its window. Bounding when a receipt was issued needs its position in a chain whose
head is committed outside the issuer (§9.7).

## Credit

The key-window cases follow a measurement by @giskard09 and @robertolocatelli81-dev on
[finos/ai-governance-framework#337](https://github.com/finos/ai-governance-framework/issues/337): under -03 a verifier
could apply a key's validity window or skip it and conform either way, so the verdict on a receipt from a rotated
key belonged to the verifier, not to the receipt. -04 §5.5 makes the rule determinate, and these vectors hold a
verifier to it. The `farley-receipt-signature` vectors are theirs; @astrogilda proposed the cases they grew from.

## In CI

The workflow runs this with the verifier pinned to the first release implementing §5.5 (`@veritasacta/verify@0.10.20`).
Until that release is on npm the step reports a skip rather than a failure, and the pin is the only line to change
when a later release should be held to the same cases.
