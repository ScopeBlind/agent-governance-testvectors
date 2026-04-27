# GDI Driver

**Governed Decision Intelligence** conformance driver for
[`draft-farley-acta-signed-receipts`](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/).

- **License:** Apache-2.0
- **Spec:** https://github.com/mj3b/governed-decision-intelligence
- **Contact:** @mj3b

## What this driver adds

Standard conformance drivers emit receipts that capture the policy outcome
(allow/deny), the policy identifier, and chain integrity fields. This driver
embeds a **Governed Decision Record (GDR)** in the receipt's `gdr` field,
sealing the pre-decision reasoning state before the tool fires.

The `result_hash` field is `sha256(JCS(GDR))`, binding:

- `confidence_score` — numeric score against institutional thresholds
- `gate_classification` — `routine | elevated_review | mandatory_escalation | blocked | deferred`
- `reasoning_reconstruction` — plain-language explanation of the decision
- `evidence_sources` — completeness classification per input source
- `accountability_chain` — named roles and responsibilities

Receipt integrity (attribution, ordering, tamper detection) is independent
of payload semantics per the v1.1 spec. An auditor verifies the receipt
offline with `@veritasacta/verify`, then reads GDR fields from the now-attested
payload to assess decision quality.

## Bilateral pattern

For threat models requiring pre-execution intent binding, this driver supports
the bilateral pattern described in the v1.1 spec discussion
([VeritasActa/verify#1](https://github.com/VeritasActa/verify/issues/1)):

- Receipt 1: sealed over the pre-execution GDR (intent)
- Receipt 2: sealed over the post-execution result, chained via `previous_receipt_hash`

This binds both sides independently. The current driver emits single receipts
for v1.0 conformance; bilateral emission is in progress.

## Requirements

- Python 3.10+
- `pip install cryptography`

## Running

```bash
cd implementations/gdi
chmod +x run.sh
./run.sh
```

Receipts are written to `receipts/gdi/`. Run the conformance verifier:

```bash
./conformance/verify.sh receipts/gdi/
```
