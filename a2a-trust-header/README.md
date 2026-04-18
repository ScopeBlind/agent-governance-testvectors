# a2a-trust-header — APS Week 2 fixtures

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
