# Test keypair

**These keys are for conformance testing only. Do not use in production.**

The private seed is deterministic so every implementation uses the same
keypair without needing to share a key file. Run `node derive.js` (or the
equivalent in any Ed25519 library) to reproduce the public key.

## Seed

```
0000000000000000000000000000000000000000000000000000000000000001
```

(32 bytes of zeros followed by a single `01`. Chosen for uniqueness and
obvious non-production status.)

## Public key

From Ed25519 derivation of the seed above:

```
4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29
```

Implementations should derive the public key from the seed locally rather
than trusting this file, but the value is included here for cross-check.

## Why a fixed seed

Every implementation running these test vectors must produce byte-identical
JCS-canonical payloads AND byte-identical Ed25519 signatures. Ed25519 is
deterministic given a fixed seed and message, so fixing the seed makes the
signatures directly comparable across implementations.
