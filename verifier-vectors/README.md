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
`REVOCATION_CHECKED=1` scores `revocation/` for a verifier that reads `revoked_at`; see below.

| Part | Draft section | Source |
|---|---|---|
| `key-window/` | -04 §5.5 (§9.2 of -03) | This repository. `key-window/scripts/generate.mjs` writes it; `--check` fails on a stale file. |
| `farley-receipt-signature` | -03 §5.1, §6.6, §9.2 | [giskard09/argentum-core](https://github.com/giskard09/argentum-core/tree/541ce84b4f970c1dd3d9e53f2a4562dbbc354e46/examples/conformance/farley-receipt-signature) (Apache-2.0), fetched at a pinned commit and never copied, so its `index.json` stays the source of truth. |
| `../conformance/check_embedded_key.sh` | §9.5 | [#24](https://github.com/ScopeBlind/agent-governance-testvectors/pull/24) (arian-gogani): a receipt's own key must never be trusted. |
| `revocation/` | not defined by -03 or -04; §5.5, §9.2 | This repository. States the gap: a key revoked before `issued_at`. `revocation/scripts/generate.mjs --check`. |
| `timeliness/` | §6.7, §9.7 | This repository. One `issued_at`, alone and against an external chain commitment. `timeliness/scripts/check.mjs` evaluates the proposed rule. |

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

## Revocation: the gap, stated

Neither -03 nor -04 defines key revocation: §9.2 covers rotation through validity windows and nothing more, so a
verifier conforming to either accepts a receipt signed with a key its issuer revoked. One key (`test:revoked:ed25519`, seed `00..0c`) with the window
`[2026-01-01, 2027-01-01)` and a `revoked_at` of `2026-04-01T00:00:00Z`, a member no revision of the draft or RFC 7517
defines:

| Receipt | `issued_at` | Under -04 | Key status | If `revoked_at` is honoured |
|---|---|---|---|---|
| `before-revocation.json` | 2026-03-15 | ACCEPT | `inside` | ACCEPT |
| `after-revocation.json` | 2026-05-15 | ACCEPT | `inside` | REJECT `key_revoked` |

The second row is the finding: a conformant verifier reports the key as inside its window for a receipt signed after
the key was revoked. `REVOCATION_CHECKED=1` scores a verifier that reads `revoked_at` against the last column, so one
that does not read it is not scored as wrong. Even that verifier is beaten by a holder of the revoked key who dates a
receipt before `revoked_at`, because `issued_at` is the signer's word. The timeliness vectors show what bounds it.

## Timeliness: one `issued_at`, with and without its chain position

A receipt cannot prove when it was issued. Its position in a chain, against a commitment the issuer made outside the
chain, can (§9.7). One key (`test:chained:ed25519`, seed `00..0d`), a genesis receipt, and `receipt.json` at position 2
with `issued_at` 2026-02-15 and a §6.7 link to the genesis. `commitment.json` is the issuer's signed statement that the
chain held one receipt, with its terminal hash; `logged_at` is when a destination the issuer cannot rewrite recorded
it. The draft defines neither the commitment's format nor a rule that reads its time, so the type is namespaced to
this repository and the rule is proposed:

| Case | Given | Under -04 | Commitment read | Timeliness |
|---|---|---|---|---|
| `alone` | `receipt.json` | ACCEPT | ACCEPT | not established |
| `committed-after` | chain, commitment logged 2026-03-01 | ACCEPT | REJECT `issued_at_precedes_excluding_commitment` | contradicted |
| `committed-before` | chain, commitment logged 2026-02-01 | ACCEPT | ACCEPT | not before 2026-02-01 |

The receipt bytes are identical in all three. In `committed-after`, the issuer stated on 2026-03-01 that position 2
did not exist yet, and the receipt claims 2026-02-15: two signed statements from one issuer that cannot both be true.
The proposed rule: a receipt at position `p`, with an external commitment of count `c < p` recorded at `logged_at`,
was not issued before `logged_at`, and the commitment's `terminal_hash` must equal the link to position `c`.

`run.mjs` checks every receipt in the chain with the pinned verifier (each is valid, key inside its window) and runs
`timeliness/scripts/check.mjs`, which reaches both columns and catches three planted defects: a genesis altered after
signing, the two receipts in reverse order, and a commitment altered after signing.

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
