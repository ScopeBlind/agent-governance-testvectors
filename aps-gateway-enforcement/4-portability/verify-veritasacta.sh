#!/usr/bin/env bash
# Verifier 2 of 3 — @veritasacta/verify.
# Independent npm-published Ed25519 verifier. Polyglot v1/v2 support.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PUBKEY_HEX="4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29"
npx --yes @veritasacta/verify@0.3.0 "$DIR/receipt.json" --key "$PUBKEY_HEX" --json
