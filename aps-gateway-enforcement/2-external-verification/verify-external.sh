#!/usr/bin/env bash
# Verify the v2 envelope receipt with NOTHING but openssl, jq, and python3.
# No APS-specific code, no @veritasacta/* npm packages. The point: any system
# with the same Ed25519 public key can verify these receipts.
#
# Steps:
#   1. Extract the pubkey and kid from jwks.json (jq).
#   2. Convert hex pubkey -> raw bytes -> SPKI PEM (openssl + python3).
#   3. Reproduce the canonical message bytes from receipt.json (python3 stdlib).
#   4. Convert hex signature -> raw bytes (xxd).
#   5. openssl pkeyutl -verify -rawin (Ed25519 single-shot per RFC 8032).
#
# Exit 0 = signature valid, exit 1 = invalid, exit 2 = tooling missing.

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RECEIPT="$DIR/receipt.json"
JWKS="$DIR/jwks.json"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

for tool in openssl jq python3 xxd; do
  command -v "$tool" >/dev/null 2>&1 || { echo "missing required tool: $tool"; exit 2; }
done

# 1. Extract base64url x and kid from JWKS
JWK_X="$(jq -r '.keys[0].x' "$JWKS")"
JWK_KID="$(jq -r '.keys[0].kid' "$JWKS")"
RECEIPT_KID="$(jq -r '.kid' "$RECEIPT")"

if [ "$JWK_KID" != "$RECEIPT_KID" ]; then
  echo "kid mismatch: jwks=$JWK_KID receipt=$RECEIPT_KID"
  exit 1
fi

# 2. base64url -> raw 32-byte pubkey -> SPKI DER -> PEM
python3 - "$JWK_X" "$TMP/pub.spki.der" <<'PY'
import sys, base64
x_b64u = sys.argv[1]
out = sys.argv[2]
pad = '=' * (-len(x_b64u) % 4)
raw = base64.urlsafe_b64decode(x_b64u + pad)
assert len(raw) == 32, f"expected 32-byte Ed25519 pubkey, got {len(raw)}"
spki_prefix = bytes.fromhex('302a300506032b6570032100')
open(out, 'wb').write(spki_prefix + raw)
PY
openssl pkey -pubin -inform DER -in "$TMP/pub.spki.der" -out "$TMP/pub.pem"

# 3. Canonical message bytes (sorted keys recursively, no whitespace, signature stripped)
python3 - "$RECEIPT" "$TMP/message.bin" <<'PY'
import sys, json
receipt = json.load(open(sys.argv[1]))
receipt.pop('signature', None)
def sort(o):
    if isinstance(o, dict):
        return {k: sort(o[k]) for k in sorted(o.keys())}
    if isinstance(o, list):
        return [sort(x) for x in o]
    return o
canonical = json.dumps(sort(receipt), separators=(',', ':'), ensure_ascii=False)
open(sys.argv[2], 'wb').write(canonical.encode('utf-8'))
PY

# 4. hex signature -> 64 raw bytes
SIG_HEX="$(jq -r '.signature' "$RECEIPT")"
echo -n "$SIG_HEX" | xxd -r -p > "$TMP/sig.bin"
SIG_LEN="$(wc -c < "$TMP/sig.bin")"
if [ "$SIG_LEN" -ne 64 ]; then
  echo "expected 64-byte Ed25519 signature, got $SIG_LEN"
  exit 1
fi

# 5. openssl Ed25519 single-shot verify (RFC 8032 PureEdDSA)
if openssl pkeyutl -verify -inkey "$TMP/pub.pem" -pubin -rawin \
   -in "$TMP/message.bin" -sigfile "$TMP/sig.bin" >/dev/null 2>&1; then
  echo "VALID — openssl confirmed Ed25519 signature over canonical bytes"
  echo "  receipt: $RECEIPT"
  echo "  kid:     $RECEIPT_KID"
  echo "  signer:  $JWK_X (base64url Ed25519 pubkey from JWKS)"
  exit 0
else
  echo "INVALID — openssl rejected the signature"
  exit 1
fi
