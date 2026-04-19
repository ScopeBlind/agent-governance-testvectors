#!/usr/bin/env bash
# Verifier 1 of 3 — APS SDK.
# Uses the APS SDK's own canonicalize() and verify() over the v2 envelope receipt.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
node "$DIR/../_scripts/verify-with-aps-sdk.mjs" "$DIR/receipt.json"
