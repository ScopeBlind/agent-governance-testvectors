#!/usr/bin/env bash
# Verifier 3 of 3 — in-toto / DSSE consumer.
# Verifies the DSSE envelope (intoto-envelope.json) using the standard DSSE
# PAE recipe per https://github.com/secure-systems-lab/dsse, with payloadType
# application/vnd.in-toto+json. Implementation is ~30 lines of plain Python
# (cryptography lib only) — no APS code in the verification path.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PUBKEY_HEX="4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29"

python3 - "$DIR/intoto-envelope.json" "$PUBKEY_HEX" <<'PY'
import sys, json, base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

env = json.load(open(sys.argv[1]))
pubkey_hex = sys.argv[2]
pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex))

payload_bytes = base64.b64decode(env['payload'])
payload_type = env['payloadType'].encode('utf-8')
# DSSE PAE: "DSSEv1 SP len(type) SP type SP len(payload) SP payload"
pae = b'DSSEv1 ' + str(len(payload_type)).encode() + b' ' + payload_type \
      + b' ' + str(len(payload_bytes)).encode() + b' ' + payload_bytes

ok_any = False
for s in env.get('signatures', []):
    sig = base64.b64decode(s['sig'])
    try:
        pub.verify(sig, pae)
        ok_any = True
        print(json.dumps({
            'valid': True,
            'verifier': 'in-toto-dsse',
            'payloadType': env['payloadType'],
            'keyid': s.get('keyid'),
            'predicateType': json.loads(payload_bytes).get('predicateType')
        }, indent=2))
        break
    except InvalidSignature:
        continue

if not ok_any:
    print(json.dumps({'valid': False, 'verifier': 'in-toto-dsse'}, indent=2))
    sys.exit(1)
PY
