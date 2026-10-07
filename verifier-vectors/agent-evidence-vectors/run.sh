#!/usr/bin/env bash
# Replays the receipt-signature corpus of agent-evidence-vectors against the verifier pinned in run.mjs.
# Needs python3 with requirements.txt installed and `verify` on PATH. See README.md.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
release="v0.17.4"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

base="https://github.com/probityai/agent-evidence-vectors/releases/download/$release"
for asset in CORPUS-DIGESTS.txt CORPUS-DIGESTS.txt.sig cosign.pub; do
  curl -fsSL "$base/$asset" -o "$work/$asset"
done
cosign verify-blob --key "$work/cosign.pub" --signature "$work/CORPUS-DIGESTS.txt.sig" \
  --insecure-ignore-tlog=true "$work/CORPUS-DIGESTS.txt"
python3 "$here/check_digest.py" "$work/CORPUS-DIGESTS.txt"

agent-evidence-vectors --corpus vectors-receipt-signature \
  --verifier "python3 $here/adapter.py" --report "${REPORT:-receipts/agent-evidence-vectors-report.json}"
