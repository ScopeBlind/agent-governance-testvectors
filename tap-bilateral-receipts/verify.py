#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from nacl.signing import VerifyKey

ROOT = Path(__file__).resolve().parent


def b64url_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + ('=' * (-len(data) % 4)))


def jcs(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def sha256(data: bytes) -> str:
    return 'sha256:' + hashlib.sha256(data).hexdigest()


def load_json(name: str):
    return json.loads((ROOT / name).read_text())


def verify_receipt(name: str, expected_kid: str, public_key_hex: str) -> dict:
    receipt = load_json(name)
    protected_b64 = receipt['signature']['protected']
    protected = json.loads(b64url_decode(protected_b64))
    assert protected['kid'] == expected_kid, (protected['kid'], expected_kid)
    signing_input = protected_b64.encode('ascii') + b'.' + jcs(receipt['payload'])
    VerifyKey(bytes.fromhex(public_key_hex)).verify(signing_input, b64url_decode(receipt['signature']['sig']))
    return receipt


def main() -> None:
    request = load_json('tap-request.json')
    keys = {item['kid']: item for item in load_json('keys.json')['keys']}
    authz = verify_receipt('authorization-receipt.json', 'tap-agent-ed25519-test', keys['tap-agent-ed25519-test']['public_key_hex'])
    outcome = verify_receipt('outcome-receipt.json', 'tap-merchant-ed25519-test', keys['tap-merchant-ed25519-test']['public_key_hex'])

    request_hash = sha256(jcs(request))
    transaction_hash = sha256(jcs(request['transaction']))
    authz_hash = sha256(jcs(authz['payload']))

    assert authz['payload']['tap_request_hash'] == request_hash
    assert outcome['payload']['tap_request_hash'] == request_hash
    assert authz['payload']['transaction_payload_hash'] == transaction_hash
    assert outcome['payload']['transaction_payload_hash'] == transaction_hash
    assert outcome['payload']['previousReceiptHash'] == authz_hash
    assert outcome['payload']['authorization_receipt_hash'] == authz_hash

    print('PASS authorization receipt signature')
    print('PASS outcome receipt signature')
    print('PASS request hash links both receipts to the TAP request')
    print('PASS outcome receipt chains to authorization receipt')


if __name__ == '__main__':
    main()
