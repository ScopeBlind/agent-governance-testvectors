#!/usr/bin/env bash
# Replays the receipt-signature corpus of agent-evidence-vectors against the verifier pinned in run.mjs.
# Needs python3 with requirements.txt installed and `verify` on PATH. See README.md.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
release="v0.17.4"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The signing key is pinned here by digest rather than trusted from the release it verifies.
# It is read from the repository at the release tag; the same key has signed every release
# since v0.10.0, so moving the release pin does not move this line.
key_sha256="15fccb1635dd1d9333146cb389f26fa3c3b9213aeed1da945ea1f51a2dc1be84"

base="https://github.com/probityai/agent-evidence-vectors/releases/download/$release"
for asset in CORPUS-DIGESTS.txt CORPUS-DIGESTS.txt.sig; do
  curl -fsSL "$base/$asset" -o "$work/$asset"
done
curl -fsSL "https://raw.githubusercontent.com/probityai/agent-evidence-vectors/$release/release/cosign.pub" \
  -o "$work/cosign.pub"
echo "$key_sha256  $work/cosign.pub" | sha256sum --check --quiet --strict
cosign verify-blob --key "$work/cosign.pub" --signature "$work/CORPUS-DIGESTS.txt.sig" \
  --insecure-ignore-tlog=true "$work/CORPUS-DIGESTS.txt"
python3 "$here/check_digest.py" "$work/CORPUS-DIGESTS.txt"

agent-evidence-vectors --corpus vectors-receipt-signature \
  --verifier "python3 $here/adapter.py" --report "${REPORT:-receipts/agent-evidence-vectors-report.json}"
