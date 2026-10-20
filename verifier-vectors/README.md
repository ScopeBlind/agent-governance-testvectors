# Verifier vectors

Fixed receipts and key sets, and what a verifier must report about them. Where `implementations/` asks whether a
producer's receipts verify, this directory asks whether a verifier reaches the right outcome in the cases it can get
wrong while every signature is perfectly valid.

```bash
node verifier-vectors/run.mjs                                            # the pinned release, through npx
VERIFY_PKG=@veritasacta/verify@0.10.25 node verifier-vectors/run.mjs     # pin another release (0.10.25 fails chain-link/)
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
| `signing-input/` | -03 §6.6 (unchanged in -04) | This repository. A signature member in the object canonicalized, `null` and `""` included, is refused even though the signature over it verifies. `signing-input/scripts/generate.mjs --check`. |
| `chain-link/` | -04 §6.7, §6.7.1, §5.3 | This repository. `previousReceiptHash` on a receipt checked alone, against a predecessor the caller supplies, and in a sequence: its form, how it is read, and a failed link check beside one that could not run. Every signature verifies. `chain-link/scripts/generate.mjs --check`. |
| `agent-evidence-vectors/` | -03 §5.1, §6.6, §9.2 | [probityai/agent-evidence-vectors](https://github.com/probityai/agent-evidence-vectors) 0.17.4 `vectors-receipt-signature`, installed from PyPI by hash and checked against the release's signed digest list, never copied. `agent-evidence-vectors/run.sh`. |

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

## Signing input: a signature member in the object canonicalized

-03 §6.6: "In either shape the object canonicalized MUST NOT contain a signature member, and that member MUST NOT be
included as null or as the empty string." Every receipt here is signed over `JCS(payload)` with its member inside, so the
signature verifies; the refusal has to come from the member itself. One key (`test:signing-input:ed25519`, seed `00..0e`):

| Receipt | Payload `signature` member | Expected | Code |
|---|---|---|---|
| `null-member.json` | `null` | REJECT | `signature_in_signing_input` (exit 1, invalid) |
| `empty-member.json` | `""` | REJECT | `signature_in_signing_input` (exit 1, invalid) |
| `string-member.json` | `"not the signature"` | REJECT | `signature_in_signing_input` (exit 1, invalid) |
| `no-member.json` | none | ACCEPT | |

@veritasacta/verify 0.10.20 accepts the first three; 0.10.21 refuses them.

## Chain links: the form of `previousReceiptHash`, and how it is read

-04 §6.7 keeps the link of -03: "The previousReceiptHash field MUST be the string `"sha256:"` followed by the lowercase
hex encoding of SHA-256(JCS(receipt))", the whole signed receipt, signature included. What -04 changes is how a verifier
reads one. It MUST recognize that form and the bare 64-hex form of earlier revisions, which an issuer MUST NOT emit. A
value naming another hash algorithm is undecidable, whether or not the verifier implements it, where -03 had a verifier
reject an algorithm it does not implement. Any other value is malformed, and a verifier MUST reject the receipt
"whether or not it holds the predecessor". §6.7.1, new in -04, says how a link is read against a predecessor the caller
supplies and in a sequence, and §5.3 how a failed check combines with one that could not run.

Every receipt here is signed over `JCS(payload)` with its link inside, so every signature verifies: a refusal has to come
from the link, or from how it is read. One key signs them all (`test:chain-link:ed25519`, seed `00..0f`). `genesis.json`
omits the link; every other receipt was issued five minutes later with the same fields, and they differ from one another
only in `previousReceiptHash`. `index.json` records, for each case, whether it is checked alone, against a supplied
predecessor or as a sequence, its verdict, outcome, code and exit status, and the -04 section it tests.

### Each receipt alone

| Receipt | `previousReceiptHash` | Expected | Code |
|---|---|---|---|
| `genesis.json` | none (§2.2) | ACCEPT | |
| `linked.json` | `sha256:` and the lowercase hex of SHA-256(JCS(`genesis.json`)) | ACCEPT | |
| `bare-hex-link.json` | the same 64 hex characters with no prefix | ACCEPT | |
| `null-link.json` | `null`, read as an omitted member (§6.7.1) | ACCEPT, with a warning | |
| `malformed-digest.json` | `sha256:not-a-digest` | REJECT | `malformed_chain_link` (exit 1, invalid) |
| `uppercase-hex.json` | the genesis digest in uppercase hex | REJECT | `malformed_chain_link` (exit 1, invalid) |
| `short-digest.json` | the genesis digest less its last character: 63 hex characters | REJECT | `malformed_chain_link` (exit 1, invalid) |
| `base64url-link.json` | `sha256:` and the genesis digest in base64url | REJECT | `malformed_chain_link` (exit 1, invalid) |
| `empty-link.json` | `""` | REJECT | `malformed_chain_link` (exit 1, invalid) |
| `non-string-link.json` | an object carrying the genesis digest | REJECT | `malformed_chain_link` (exit 1, invalid) |
| `sha3-256-link.json` | `sha3-256:` and 64 hex characters, the length of a SHA-256 digest | REJECT | `unsupported_chain_hash_algorithm` (exit 2, undecidable) |
| `sha512-link.json` | `sha512:` and 128 hex characters | REJECT | `unsupported_chain_hash_algorithm` (exit 2, undecidable) |

### Against a supplied predecessor

`verify <receipt> --previous <predecessor>`: the caller asserts that the receipt follows the predecessor. It does only if
its `previousReceiptHash` is the predecessor's §6.7 link, in either form, and "absence never satisfies a supplied
predecessor":

| Receipt | Predecessor | Expected | Code |
|---|---|---|---|
| `linked.json` | `genesis.json` | ACCEPT | |
| `bare-hex-link.json` | `genesis.json` | ACCEPT | |
| `no-link.json` | `genesis.json` | REJECT | `chain_break` (exit 1, invalid) |
| `null-link.json` | `genesis.json` | REJECT | `chain_break` (exit 1, invalid) |
| `payload-only-link.json` | `genesis.json` | REJECT | `chain_break` (exit 1, invalid) |
| `linked.json` | `no-link.json` | REJECT | `chain_break` (exit 1, invalid) |
| `uppercase-hex.json` | `genesis.json` | REJECT | `malformed_chain_link` (exit 1, invalid) |
| `sha3-256-link.json` | `genesis.json` | REJECT | `unsupported_chain_hash_algorithm` (exit 2, undecidable) |

`no-link.json` carries the fields of `genesis.json`, issued five minutes later, and no link: an unchained receipt, which
follows nothing. `payload-only-link.json` carries `sha256:` and the hex of SHA-256(JCS(the payload of `genesis.json`)):
no revision defines a link over the payload alone, and it would let a re-signed receipt keep the original's link.
`uppercase-hex.json` would name `genesis.json` if read without regard to case, and is malformed with the predecessor as
without it.

### Read as a sequence

`verify --replay-chain <file>`: a log read in order, as with one chain per session, with no succession asserted. Each line
that carries a link is checked against the line before it, except the first:

| Sequence | Lines | Expected | Chains | Code |
|---|---|---|---|---|
| `sequence-linked.jsonl` | `genesis.json`, `linked.json` | ACCEPT | 1 | |
| `sequence-new-chain.jsonl` | `genesis.json`, `no-link.json` | ACCEPT | 2 | |
| `sequence-null-link.jsonl` | `genesis.json`, `null-link.json` | ACCEPT, with a warning on line 2 | 2 | |
| `sequence-first-linked.jsonl` | `linked.json` | ACCEPT | 1 | |
| `sequence-payload-only.jsonl` | `genesis.json`, `payload-only-link.json` | REJECT | 1 | `chain_break` on line 2 (exit 1, invalid) |

A receipt with no link begins a new chain, and a verifier MUST NOT report it as linked to the line before it. A `null`
link is read the same way, and a verifier SHOULD warn that its issuer emitted a value it must not. A link on the first
receipt, whose predecessor the sequence does not hold, is reported, not failed. §6.7.1 also has a verifier say that this
predecessor was not supplied; that SHOULD is not scored, and @veritasacta/verify 0.10.26 does not say it.

### The combination rule

-04 §5.3: an outcome "is invalid if any check ran and failed, even if another could not run":

| Receipt | Key | Checks | Expected | Code |
|---|---|---|---|---|
| `malformed-digest.json` | none | the signature cannot be checked; the link is malformed | REJECT | `malformed_chain_link` (exit 1, invalid) |
| `sha3-256-link.json` | `jwks-window-ended.json` | the signature verifies; the link names another algorithm; the receipt was issued after the key's window ended | REJECT | `key_outside_validity_window` (exit 1, invalid) |

`jwks-window-ended.json` is `jwks.json` with the window `[2026-01-01T00:00:00Z, 2026-07-01T00:00:00Z)`, and every receipt
here was issued on 2026-07-15.

The codes, exit statuses, chain counts and warnings are @veritasacta/verify's: `run.mjs` reads `error`, `previous`,
`chains` and `chainBreaks` from its JSON, and `error` and `warning` from the line a sequence case turns on. Another
verifier is held to the verdict and the outcome.

@veritasacta/verify 0.10.21 accepts every malformed and other-algorithm link on a receipt alone, and does not warn on
`null`. 0.10.23 and 0.10.25 pass the twelve cases of a receipt alone and fail the other fifteen: they have no `--previous`
(the predecessor is read as a second file, exit 2), `--replay-chain` ignores `--jwks` and fails each line for want of a
key, and the two combination cases are undecidable (`no_public_key` and `unsupported_chain_hash_algorithm`, exit 2).
Given the key with `--key` instead, 0.10.25 passes four of the five sequences and fails the fifth only on line 2 of
`sequence-payload-only.jsonl`, which it counts as a break but reports as a valid line; 0.10.23 reads that link as a
legacy one, since `genesis.json` names no `spec`, counts no chains, and does not warn on the `null` line. 0.10.26 passes
all 27 cases.

## Credit

The key-window cases follow a measurement by @giskard09 and @robertolocatelli81-dev on
[finos/ai-governance-framework#337](https://github.com/finos/ai-governance-framework/issues/337): under -03 a verifier
could apply a key's validity window or skip it and conform either way, so the verdict on a receipt from a rotated
key belonged to the verifier, not to the receipt. -04 §5.5 makes the rule determinate, and these vectors hold a
verifier to it. The `farley-receipt-signature` vectors are theirs; @astrogilda proposed the cases they grew from.
The signing-input case is @astrogilda's, found with `vectors-receipt-signature` in
[probityai/agent-evidence-vectors](https://github.com/probityai/agent-evidence-vectors) 0.13.0 (`v5397adb77c3e6754`).

## In CI

The workflow runs this with the verifier pinned to `@veritasacta/verify@0.10.26`, the latest release, published with
npm provenance, and the first that checks a receipt against a supplied predecessor (`--previous`), reads `--jwks` with
`--replay-chain`, and combines checks as -04 §5.3 does. 0.10.25 was the first to refuse a payload-only link in a sequence
whatever the receipt before it cites, and to report each chain a sequence holds, 0.10.22 the first release that refuses a
malformed or other-algorithm chain link on a receipt checked alone (§6.7), and 0.10.21 the first implementing §5.5 and
the §6.6 refusal. If the pinned release is not on npm the step reports a skip rather than a failure, and the pin is the
only line to change when a later release should be held to the same cases.
