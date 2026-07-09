# Cold-chain test vectors

Sensor-evidence vectors for the receipt format applied to physical-world
provenance. Where the rest of this repo exercises agent tool-call
governance (Cedar policies over tool inputs), these vectors exercise the
same signed-receipt primitives over a stream of sensor readings: a
disposable evidence tag riding along with a pharmaceutical shipment,
producing per-reading attestations that batch-sign into Merkle epochs
and verify offline at destination.

This is the same receipt format, the same Ed25519 keypair conventions,
and the same v2 envelope shape used by `aps-gateway-enforcement/` and
`tap-bilateral-receipts/`. The difference is the `action.kind` and
the policy: instead of `exec` against `trusted_hosts`, the action is
`sensor.read` and the policy is a temperature-range admittance rule.

## Scenario

A pharma exporter ships insulin from Sydney to Singapore. A disposable
evidence tag (ATECC608B secure element + NTC thermistor + NFC) is
sealed into the carton at origin. Every 60 seconds the tag samples
temperature; the reading is signed inside the secure element; readings
are accumulated into a Merkle tree per hour-long epoch; only the epoch
root is broadcast. At destination, the importer taps the tag with a
phone, pulls the per-reading Merkle paths down to the epoch root,
verifies the chain offline against the issuer pubkey, and emits a
single PolicyReceipt (`allow` or `deny`) attesting cold-chain
compliance for the whole journey.

The receipts in this directory are illustrative. The shipment is
synthetic; the cryptographic shape matches a production deployment.

## The three vectors

| File | What it proves |
|------|----------------|
| [`pharma-shipment-pass.json`](./pharma-shipment-pass.json) | A 4-checkpoint shipment with all readings in the 2.0-8.0 C admittance band. Policy decision: `allow`. |
| [`pharma-shipment-excursion.json`](./pharma-shipment-excursion.json) | The same journey with a single 8.4 C excursion at minute 1800. Policy decision: `deny`. The signed receipt still verifies; the world it describes failed the policy. |
| [`merkle-batch-root.json`](./merkle-batch-root.json) | One epoch root over 60 readings, with per-reading Merkle paths. Shows the batching scheme that lets a low-power tag emit one signed root per hour instead of one signature per reading. |

## Receipt shape

All three vectors use the v2 structured envelope per
[`../expected/receipt-schema.json`](../expected/receipt-schema.json):

```json
{
  "payload": {
    "type": "scopeblind.receipt.v1",
    "decision": "allow",
    "action": { "kind": "sensor.read", "target": "..." },
    "policy_id": "cold-chain-pharma-2to8C",
    "sequence": 1,
    "prev_hash": "sha256:...",
    "timestamp": "...",
    "context": { "..." : "..." }
  },
  "signature": "...",
  "pubkey": "..."
}
```

The `context` object carries the sensor-specific fields: device id,
epoch number, reading count, temperature stats, Merkle root, hash
chain over epochs.

## Policy

The policy `cold-chain-pharma-2to8C` admits the shipment if every
reading in every epoch is in the closed interval `[2.0, 8.0]` degrees
Celsius. A single excursion of any magnitude is a `deny`. In a
production deployment this policy would be expressed in Cedar and
evaluated by the same engine used for tool-call policies in
`fixtures/policy/`.

## Cryptographic setup

| Field | Value |
|-------|-------|
| Algorithm | Ed25519 (RFC 8032) |
| Seed | `0000000000000000000000000000000000000000000000000000000000000001` (matches `fixtures/keys/README.md`) |
| Public key (hex) | `4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29` |
| Device kid | `dev:atecc608b:au-syd-pharma-0042` |
| Issuer | `coldchain:gateway:test` |
| Receipt shape | v2 envelope |

The fixed seed matches the rest of the repo so the cross-implementation
verifier can run cold-chain vectors against the same key material as
tool-call vectors. In production every tag has a per-device keypair
provisioned at manufacture; the secure element exposes only the public
key and signs without ever revealing the private key.

## Verifying these vectors

The reference verifier `@veritasacta/verify` accepts these vectors
unchanged because they conform to the v2 envelope shape. Schema check
is the same as for any other receipt in this repo:

```bash
./conformance/verify.sh cold-chain/
```

The Merkle batching is verified independently: the per-reading paths in
`merkle-batch-root.json` must hash up to the `merkle_root` field of the
epoch, and that root is what the per-epoch receipt signs.

## What this is not

These vectors do not propose a new wire format. They reuse the existing
v2 envelope to demonstrate that the format extends from agent tool-call
governance to physical-world sensor governance with no schema changes.

They do not standardize cold-chain temperature ranges or pharma
admittance bands; those vary by drug class and regulator. The
`cold-chain-pharma-2to8C` policy id is illustrative.

They do not test secure-element attestation (ATECC608B certificate
chain back to Microchip's CA); that is a separate concern handled at
device provisioning, out of scope for this repo.

## Files

```
cold-chain/
README.md                       This file.
pharma-shipment-pass.json       Journey passes the policy.
pharma-shipment-excursion.json  Journey fails the policy.
merkle-batch-root.json          One epoch root + 60 reading paths.
index.json                      Manifest entry for this category.
```
