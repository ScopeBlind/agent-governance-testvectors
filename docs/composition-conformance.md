# Composition conformance: reference, do not re-sign

This repository contains test vectors for agent-governance systems that need to
compose with each other without collapsing into a single vendor-specific receipt
format.

The core rule is simple:

> ACTA composes with APS, A2A, Hermes, and similar governance systems by
> referencing another receipt's content hash. It does not re-sign, reinterpret,
> or mutate the inner receipt.

That rule keeps each issuer's trust boundary intact:

- the inner receipt remains verifiable by its native verifier;
- the outer receipt can add routing, delegation, audit-walker, policy, or
  transport context;
- a verifier can prove linkage by recomputing the inner receipt hash and
  comparing it to the outer receipt's reference;
- no participant needs to disclose fields that were not disclosed by the inner
  receipt's own selective-disclosure policy.

## Pattern

A composed governance record SHOULD use this shape:

1. Produce the inner receipt under its native rules.
2. Canonicalize the inner receipt exactly as that receipt family specifies.
3. Compute a content hash, normally `sha256:<hex>` over canonical bytes.
4. Emit the outer receipt with a field such as `inner_receipt_hash`,
   `decision_receipt_hash`, `receipt_hash`, or a profile-specific equivalent.
5. Sign only the outer receipt's own canonical payload.
6. Verify by resolving the referenced inner receipt and checking that its hash
   matches the signed outer reference.

The outer receipt MUST NOT copy the inner signature as if it were its own, and
MUST NOT re-sign the inner payload unless it is explicitly creating a new
receipt with a new issuer and a new trust boundary.

## APS / ACTA

APS and ACTA overlap on Ed25519 signatures, hash-linked evidence, policy-aware
decisions, and offline verification. They differ in envelope shape and trust
semantics:

- APS has explicit delegation-chain roots and cascade revocation semantics.
- ACTA receipts are content-addressed, offline-verifiable decision receipts with
  selective-disclosure support.
- APS can wrap or reference ACTA receipts when it needs delegation or revocation
  context.
- ACTA can preserve APS-specific fields under a namespaced extension such as
  `x-aps`, but generic ACTA verifiers treat those fields as extension data
  unless a profile gives them semantics.

A safe APS ↔ ACTA bridge therefore references the inner receipt by content hash
and leaves native verification to the native verifier.

## A2A trust header vectors

The `a2a-trust-header/` fixtures exercise the same composition principle for the
A2A `x-agent-trust` header work:

- Week 2 covers signed APS-shaped fixtures.
- Week 3 adds a canonical five-field composite schema plus a dual-provider
  consumer verifier for APS and MolTrust-shaped fixtures.
- Consumers reduce each provider's richer native shape into the canonical
  composite view, then verify signatures and chain roots without needing to own
  either provider's issuance stack.

Run locally:

```bash
cd a2a-trust-header
npm ci
npm run verify
npm run consumer-verify
```

Expected result: six APS fixtures pass the APS verifier, and nine total fixtures
pass the dual-provider consumer verifier.

## Hermes / audit-walker composition

Hermes-style audit walkers should follow the same rule. The audit walker can
carry APS delegation evidence or traversal context while referencing an inner
ACTA decision receipt by hash. The audit walker should not re-sign the ACTA
receipt or claim native ACTA verification passed unless it either embeds or
resolves the exact receipt bytes and verifies them.

This gives a clean layered audit story:

- Hermes proves traversal / audit-walker context.
- APS proves delegation or authority-chain context.
- ACTA proves the decision receipt and selective disclosure boundary.
- A composed verifier proves that the layers refer to the same underlying event
  by content hash.

## Conformance checklist

A composed fixture is acceptable when all of these are true:

- The inner receipt verifies independently under its native verifier.
- The outer receipt verifies independently under its native verifier.
- The outer receipt's reference equals the canonical content hash of the inner
  receipt.
- The outer receipt does not replace the inner issuer's signature with its own.
- Namespaced extension fields are preserved, but not treated as normative by a
  generic verifier unless the profile says so.
- Selective-disclosure commitments stay inside the receipt family that created
  them; outer layers may reference them but should not reinterpret them.
