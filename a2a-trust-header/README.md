# a2a-trust-header: A2A#1742 fixtures and dual-provider verifier

Signed, JCS-canonical fixtures for the `x-agent-trust` header being
specified at [a2aproject/A2A#1742](https://github.com/a2aproject/A2A/issues/1742),
plus a consumer verifier that validates both APS and MolTrust emission
shapes against a single canonical schema.

- **Week 1 (done):** schema lock on the 5-field composite header.
- **Week 2 (done):** 6 APS fixtures + APS-only round-trip verifier. See [Week 2](#week-2--six-aps-fixtures) below.
- **Week 3 (done):** canonical JSON Schema, dual-provider consumer
  verifier, 3 MolTrust-shaped placeholder fixtures. See [Week 3](#week-3--canonical-schema--dual-provider-consumer-verifier) below.

---

## Week 2: six APS fixtures

Six signed, JCS-canonical fixtures for the `x-agent-trust` header being
specified at [a2aproject/A2A#1742](https://github.com/a2aproject/A2A/issues/1742).
The header carries trust signals about an agent across A2A calls so
receiving agents can decide whether to honor the request.

This directory is APS's contribution to the Week 2 cross-verification
milestone. Format conventions were locked in the #1742 thread with
@MoltyCel:

- Happy-path cases use `delegation_chain_root: "sha256:<hex>"`.
- Drift and revocation cases **must** carry `format_variant: true` at
  the fixture level to explicitly flag any deviation from the canonical
  shape.
- Cases exercise both trust_level trajectories and the Agent Card
  `trust.signals[]` cross-org pattern from [a2aproject/A2A#1628](https://github.com/a2aproject/A2A/issues/1628).

## The six fixtures

| # | File | Case | `format_variant` | expected_verifier_output |
|---|------|------|---|---|
| 1 | [`happy-path.json`](./happy-path.json) | Two-step delegation chain, monotonic narrowing, single `trusted` attestation | `false` | `valid` |
| 2 | [`trust-level-ascending.json`](./trust-level-ascending.json) | Trajectory `unknown → developing → trusted` across three independently-signed attestations | `false` | `valid` |
| 3 | [`trust-level-descending.json`](./trust-level-descending.json) | Reputation-decay trajectory `trusted → developing → flagged` | `false` | `valid` |
| 4 | [`drift-explicit-flag.json`](./drift-explicit-flag.json) | Two attestations with the same chain but divergent root algorithm (`sha256` → `keccak256`) | **`true`** | `invalid` |
| 5 | [`revocation-mid-chain.json`](./revocation-mid-chain.json) | Chain valid at T0, revoked at T1, use attempted at T2 produces a signed deny receipt | **`true`** | `deny` |
| 6 | [`shared-card-crossorg.json`](./shared-card-crossorg.json) | A2A Agent Card (per #1628) with `trust.signals[]` from orgA and orgB about the same subject agent, no self-attestation | `false` | `valid` |

## Fixture shape

Every fixture is a single JSON object:

```json
{
  "fixture": "<name>",
  "description": "...",
  "expected_verifier_output": "valid | invalid | deny",
  "format_variant": true | false,
  "format_variant_reason": "<only when format_variant=true>",
  "spec_refs": ["a2aproject/A2A#1742", ...],
  "header_name": "x-agent-trust",
  "header_value": { ... the signed blob that would go into the header ... }
}
```

`header_value` contains:

- `trust_header_version` — `"0.1"` for this round.
- `subject_agent` — `did:aps:<pubkey-prefix>` of the agent the header
  is asserting about.
- `delegation_chain` — ordered array of delegation links. Each link is
  a JCS-canonical object with an Ed25519 signature from the principal.
- `delegation_chain_root` — canonical form: `"sha256:<hex>"`. Computed
  as `sha256(canonicalizeJCS(delegation_chain))`. Non-standard
  algorithms (e.g., `keccak256:<hex>`) are permitted **only** in
  fixtures that also carry `format_variant: true`.
- `attestations` — ordered array of trust attestations. Each attestation
  is `{ payload, signature }` where `signature` covers the JCS-canonical
  `payload`. Attestations can be added by any issuer; self-attestation
  (issuer == subject) is explicitly not used in these fixtures.
- `agent_card` — present only in the shared-card fixture. Carries
  `trust.signals[]` per A2A#1628.
- `deny_receipt` — present only in the revocation fixture. A signed
  record from the gateway/issuer refusing the use of a revoked
  delegation, referenced from the corresponding attestation by
  `deny_receipt_ref: "sha256:<hex>"`.

## Crypto conventions

- **Ed25519** signatures (RFC 8032).
- **JCS** canonicalization (RFC 8785) over every signed payload.
- **SHA-256** for `delegation_chain_root` (happy path) and for
  `deny_receipt_ref`.
- Every signature object is
  `{ alg: "EdDSA", kid: "did:aps:<prefix>", pubkey: "<hex>", sig: "<hex>", canonicalization?: "RFC8785-JCS" }`.
  The `canonicalization` field is present on attestations and on the
  deny receipt; it's implied (JCS) on delegation links for brevity.

## Deterministic keys

Seeds are 32 bytes, right-aligned padding with zeros. The `aps_issuer`
seed (`0x00...01`) matches the test key in `fixtures/keys/` so these
fixtures can be cross-verified against the rest of the repo's vectors
with the same keypair.

| Role | Seed (tail) | Public key |
|------|------|------|
| `aps_issuer`    | `...01` | `4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29` |
| `org_a`         | `...02` | see [`_keys.json`](./_keys.json) |
| `org_b`         | `...03` | see [`_keys.json`](./_keys.json) |
| `subject_agent` | `...04` | see [`_keys.json`](./_keys.json) |
| `delegate_1`    | `...05` | see [`_keys.json`](./_keys.json) |
| `delegate_2`    | `...06` | see [`_keys.json`](./_keys.json) |

Private seeds are **not** included; verifiers only need the public
halves. Implementations should re-derive public keys from the listed
seed tails to confirm.

## Verifier verdict rules

A cross-verifier should assign a verdict per these rules (APS's
reference implementation in [`verify.ts`](./verify.ts) encodes them):

1. **`invalid`** — if any Ed25519 signature on a delegation link,
   attestation, or deny receipt fails to verify.
2. **`invalid`** — if attestations within the same header advertise
   `delegation_chain_root` under more than one hash algorithm
   (root-format drift).
3. **`deny`** — if the delegation chain contains a `status: "revoked"`
   link and a signed `deny_receipt` is attached.
4. **`valid`** — otherwise. A descending `trust_level` trajectory is
   still `valid`; the verifier's job is to surface the trajectory for
   downstream policy to act on, not to fail the header.

## Reproducing the fixtures

```bash
# From the repo root
npx tsx a2a-trust-header/generate.ts
# Round-trip verify
npx tsx a2a-trust-header/verify.ts
```

`generate.ts` emits every fixture to disk with fixed timestamps and
fixed seeds, so the six files are byte-reproducible. `verify.ts`
re-canonicalizes every signed payload, checks every signature, and
asserts the verdict matches `expected_verifier_output`.

## Implementation notes

- APS SDK used: `agent-passport-system@2.0.0`. The SDK exports
  `canonicalizeJCS`, `sign`, `verify`, and `publicKeyFromPrivate`
  from its top-level `src/index.ts`.
- The generator does not mutate APS SDK source; it imports from the
  published module path.
- Every signed payload is a flat JSON object so JCS canonicalization is
  unambiguous (no `undefined` values, no nested arrays of signable
  primitives).
- Timestamps (`issued_at`, `expires_at`, `revoked_at`, `attempted_at`)
  are fixed ISO-8601 values between 2026-04-18T12:00:00Z and T+15min.
  This keeps the fixtures reproducible while still exercising
  time-ordered logic (e.g., revocation mid-chain).

## Cross-implementation hook

Any implementation can claim conformance with these fixtures by reading
each file, re-canonicalizing every signed payload with an RFC 8785 JCS
implementation, and verifying every Ed25519 signature against its
advertised public key. The verdict for each fixture must match
`expected_verifier_output`.

Questions, format clarifications, or counter-examples: open a PR or
comment on [a2aproject/A2A#1742](https://github.com/a2aproject/A2A/issues/1742).

---

## Week 3: canonical schema + dual-provider consumer verifier

Week 3 turns the Week 1 schema lock into runnable artifacts and adds
MolTrust-shaped placeholder fixtures so the consumer verifier can
exercise both provider shapes end-to-end before MolTrust ships their
half.

### Canonical composite header schema

The canonical wire form is a **5-field composite**:

| Field | Type | Notes |
|---|---|---|
| `trust_level` | integer 0–4 | 0 = unverified / newly issued; 4 = highest-confidence issuer-backed |
| `attestation_count` | integer ≥ 0 | Number of attestations accumulated by the issuer at `last_verified` time |
| `last_verified` | ISO 8601 date-time | Consumers MAY apply a half-life policy (MolTrust default: 45 days) |
| `evidence_bundle` | string, `ipfs://…` or `https?://…` | Pointer to the full attestation bundle |
| `delegation_chain_root` | `sha256:<hex>` or `uri:https?://…` | Self-describing authority root |

Schema file: [`schema/a2a-trust-header.schema.json`](./schema/a2a-trust-header.schema.json).
Draft 2020-12. All 5 fields are required. `additionalProperties: true`
so providers can emit vendor-specific sibling fields without coupling
the canonical contract.

`delegation_chain_root` uses a `pattern` constraint to enforce the
self-describing form from Week 1 (`sha256:<hex>` | `uri:https?://…`).

### Composite view derivation

APS and MolTrust fixtures agree on the 5-field contract but differ in
how rich their native shape is. The consumer verifier reduces every
fixture to the canonical composite before schema validation:

- **MolTrust-shaped fixtures** (placeholder + real) carry the 5 fields
  directly on `header_value`. Derivation is `direct`: read the fields
  off `header_value` and validate.
- **APS-shaped fixtures** carry the 5 fields across the richer native
  structure: `trust_level` lives inside each attestation's payload,
  `attestation_count` = `len(attestations)`, `last_verified` = most
  recent attestation's `issued_at`, `evidence_bundle` = synthesized
  pointer to the APS gateway's public trust endpoint for the subject
  agent, `delegation_chain_root` = already on `header_value`.
  Derivation is `aps-synthesized`.

This split is the Week 1 agreement made operational: consumers see the
same 5 fields regardless of producer; producers keep their richer
native shape.

### Consumer verifier

[`consumer-verify.ts`](./consumer-verify.ts) discovers every `*.json`
fixture at the top of `a2a-trust-header/` and under
`moltrust-placeholder/`, classifies each by issuer, derives the
composite view, schema-validates via ajv, and verifies every Ed25519
signature it finds. Signature verification uses `@noble/ed25519`
(not the APS SDK) so MolTrust does not need to pull APS-specific code
to run this verifier.

```bash
# From repo root
cd a2a-trust-header
npm install
npx tsx consumer-verify.ts
```

Per-fixture row shape:

```
[PASS] happy-path.json  issuer=aps  schema=ok  sigs=3/3  root=ok  verdict=pass
         composite_derivation=aps-synthesized
```

Aggregate summary:

```
Consumer verify: aggregate
  APS fixtures:       6 / 6 pass
  MolTrust fixtures:  3 / 3 pass (placeholder)
  Unknown issuer:     0
  Schema failures:    0
  Signature failures: 0
  Chain-root drift:   0
```

Exit codes:

| Code | Meaning |
|---|---|
| `0` | all fixtures pass |
| `1` | any signature or chain-root failure |
| `2` | any schema failure |

### MolTrust placeholder fixtures

Three MolTrust-shaped fixtures live under
[`moltrust-placeholder/`](./moltrust-placeholder/). They are synthetic
references MolTrust can replace with their real emission when they ship
Week 3 on their side. Every placeholder fixture is marked with:

```json
{
  "_placeholder": true,
  "_replace_with_real_moltrust_emission": true
}
```

| # | File | What it exercises |
|---|---|---|
| 1 | [`trust-trajectory-decay.json`](./moltrust-placeholder/trust-trajectory-decay.json) | `trust_level` steps down 4 → 3 → 2 across three progressive emissions; `evidence_bundle` is an `ipfs://…` pointer |
| 2 | [`attestation-accumulation.json`](./moltrust-placeholder/attestation-accumulation.json) | `attestation_count` accumulates 2 → 7 → 15 with `trust_level` held at 3; `evidence_bundle` is an `https://…` URL |
| 3 | [`shared-happy-path-moltrust.json`](./moltrust-placeholder/shared-happy-path-moltrust.json) | Same `delegation_chain` + root as APS [`happy-path.json`](./happy-path.json), re-signed under MolTrust placeholder key with `issuer="moltrust"`: overlap-region proof |

#### Placeholder signing key

Placeholder fixtures are signed with a **deterministic test seed**:
32-byte right-aligned, tail `0xAA`. The public half is embedded in each
fixture's `moltrust_signing_key` field and as `signature.pubkey` on
every emission. This is test-only:

> Replace before production. Do not reuse the placeholder key in any
> issuer emission seen by a real consumer.

The generator that produced these fixtures,
[`moltrust-placeholder/generate-placeholder.ts`](./moltrust-placeholder/generate-placeholder.ts),
is committed so MolTrust can see exactly how the shape was constructed.

### MolTrust replacement workflow

When MolTrust ships Week 3 on their side:

1. Replace each placeholder file under `moltrust-placeholder/` with
   their real emission. Keep the filenames (trajectory / accumulation
   / shared-happy-path) so the consumer verifier picks them up
   automatically.
2. Drop the `_placeholder` / `_replace_with_real_moltrust_emission`
   fields.
3. Replace `moltrust_signing_key` with their production kid + pubkey,
   and re-sign every emission under that key.
4. Re-run `npx tsx consumer-verify.ts`. All 9 fixtures (6 APS + 3
   MolTrust real) must still pass schema + signature + chain-root
   checks.

The consumer verifier does not encode MolTrust import weighting
(0.3 weight, 45-day half-life, `POST /identity/resolve` before import).
Those are downstream policy decisions. What the verifier guarantees is
that every 5-field composite a MolTrust-aware consumer would read is
**schema-conformant, cryptographically verifiable, and chain-root
consistent**: the preconditions MolTrust weighting is built on top of.

### Ed25519 / canonicalization conventions

Both providers use the same cryptography:

- Ed25519 (RFC 8032) for all signatures.
- RFC 8785 JCS canonicalization over every signed payload.
- SHA-256 for `delegation_chain_root` in `sha256:<hex>` form.

The consumer verifier uses `canonicalizeJCS` from
`agent-passport-system` and `@noble/ed25519` for verification. It does
not require the APS SDK to verify MolTrust-shaped fixtures beyond the
canonicalization helper, which is a primitive, not APS-specific.

### Reproducing Week 3 artifacts

```bash
cd a2a-trust-header
npm install
# Regenerate placeholder fixtures (byte-reproducible under fixed seed)
npx tsx moltrust-placeholder/generate-placeholder.ts
# Round-trip APS fixtures through the APS-native verifier
npx tsx verify.ts
# Dual-provider schema + signature + chain-root verification
npx tsx consumer-verify.ts
```
