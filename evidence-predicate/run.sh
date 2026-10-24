#!/usr/bin/env bash
# The evidence predicate suite: regenerate in check mode (fails on a stale
# artifact), judge every vector as a relying party, and, when npx is at hand,
# confirm each receipt verifies under the published verifier with the receipt
# signer's key given out of band. The verifier does not evaluate the predicate
# (Section 4.2: no verifier action required); the point is that a receipt
# carrying it is still a conformant decision_receipt.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
node "$ROOT/scripts/generate.mjs" --check
node "$ROOT/scripts/verify.mjs"
if command -v npx >/dev/null 2>&1 && [ "${EVIDENCE_SKIP_PUBLISHED_VERIFIER:-0}" != "1" ]; then
    KEY="$(node -e "const t=require('$ROOT/trust-policy.json'); process.stdout.write(t.receipt_signers['test:manager:meridian:ed25519'].public_key_hex)")"
    n=0
    for f in "$ROOT"/vectors/*/receipt.json; do
        npx --yes @veritasacta/verify --key "$KEY" "$f" >/dev/null 2>&1 || { echo "FAIL: published verifier rejected $f"; exit 1; }
        n=$((n+1))
    done
    echo "published verifier: $n receipts verify under the pinned signer key"
fi
