#!/usr/bin/env bash
# nobulex conformance driver.
#
# Evaluates each fixture against fixtures/policy/autoresearch-safe.cedar and
# writes one signed receipt per fixture to receipts/nobulex/.
#
# Requires python3 and one of pynacl or cryptography for Ed25519:
#
#     pip install pynacl
#
# Receipts follow the `decision_receipt` shape used by this repository's own
# aps-gateway-enforcement vectors and accepted by @veritasacta/verify.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

command -v python3 >/dev/null 2>&1 || { echo "skip: python3 required"; exit 77; }

exec python3 "$SCRIPT_DIR/emit.py"
