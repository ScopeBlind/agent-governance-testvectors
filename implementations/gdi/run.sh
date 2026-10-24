#!/usr/bin/env bash
# GDI (Governed Decision Intelligence) conformance driver.
#
# Reads fixtures from ../../fixtures/inputs/
# Writes v2 envelope receipts (with embedded GDR payload) to ../../receipts/gdi/
#
# Signature verification requires --key because GDI uses the shared fixture
# keypair directly rather than a hosted JWKS endpoint. Pass the fixture
# public key to @veritasacta/verify:
#
#   ../../conformance/verify.sh ../../receipts/gdi
#
# The verifier accepts one receipt per invocation; do not pass a file glob.
#
# Apache-2.0. https://github.com/mj3b/governed-decision-intelligence

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

command -v python3 >/dev/null 2>&1 || { echo "skip: python3 not found"; exit 77; }
python3 -c "import cedarpy, rfc8785; from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey" \
    2>/dev/null || { echo "skip: pip install -r $SCRIPT_DIR/requirements.txt"; exit 77; }

python3 "$SCRIPT_DIR/gdi_driver.py"
