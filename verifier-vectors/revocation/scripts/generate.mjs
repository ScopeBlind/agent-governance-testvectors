#!/usr/bin/env node
// Deterministically generate the revocation vectors. They state a gap rather than a rule: neither
// draft-farley-acta-signed-receipts-03 nor -04 defines key revocation, so a verifier conforming to either accepts a
// receipt signed with a key its issuer has revoked, as long as the receipt is dated inside the key's validity window.
//
//   node verifier-vectors/revocation/scripts/generate.mjs          write the files
//   node verifier-vectors/revocation/scripts/generate.mjs --check  fail if a file is stale

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { canonicalize, keyPairFromSeed, signHex } from '../../../evidence-predicate/lib.mjs'

const DIR = path.dirname(path.dirname(fileURLToPath(import.meta.url)))
const CHECK = process.argv.includes('--check')

// A deterministic test key. Public, and MUST NOT be reused. Its seed is used nowhere else in this repository.
const KEY = keyPairFromSeed('000000000000000000000000000000000000000000000000000000000000000c')
const KID = 'test:revoked:ed25519'
const WINDOW = { valid_from: '2026-01-01T00:00:00Z', valid_until: '2027-01-01T00:00:00Z' }
// Not a member any revision of the draft or RFC 7517 defines. It is what a revocation handle would have to carry,
// and a verifier that does not read it is conformant.
const REVOKED_AT = '2026-04-01T00:00:00Z'
const x = Buffer.from(KEY.publicKeyHex, 'hex').toString('base64url')

function receipt(issuedAt) {
  const payload = {
    type: 'protectmcp:decision',
    tool_name: 'read_file',
    decision: 'allow',
    issued_at: issuedAt,
    issuer_id: KID,
    policy_digest: 'sha256:8ca92f7dfaaf6f4fee88f3892cd7122ab48912c0f9666f70df79b2973627b888',
  }
  return { payload, signature: { alg: 'EdDSA', kid: KID, sig: signHex(payload, KEY.privateKey) } }
}

// expected: the verdict a verifier conforming to -04 must reach. It reads the window and has no revocation rule.
// expected_if_revocation_checked: the verdict from a verifier that also honours revoked_at. A run declares which
// of the two it is scored against.
const CASES = [
  { file: 'before-revocation.json', issued_at: '2026-03-15T00:00:00Z', jwks: 'jwks.json',
    expected: 'ACCEPT', code: null, key_status: 'inside',
    expected_if_revocation_checked: 'ACCEPT', code_if_revocation_checked: null,
    note: 'Issued inside the window and before the key was revoked. Every verifier accepts it.' },
  { file: 'after-revocation.json', issued_at: '2026-05-15T00:00:00Z', jwks: 'jwks.json',
    expected: 'ACCEPT', code: null, key_status: 'inside',
    expected_if_revocation_checked: 'REJECT', code_if_revocation_checked: 'key_revoked',
    note: 'Issued inside the window and after the key was revoked. The draft defines no revocation, so a conformant verifier accepts it and reports the key as inside its window. That acceptance is the gap this vector records.' },
]

const files = new Map()
const json = (value) => JSON.stringify(value, null, 2) + '\n'
files.set('jwks.json', json({ keys: [{ kty: 'OKP', crv: 'Ed25519', kid: KID, x, use: 'sig', ...WINDOW, revoked_at: REVOKED_AT }] }))
for (const c of CASES) files.set(c.file, json(receipt(c.issued_at)))
files.set('index.json', json({
  suite: 'key-revocation',
  profile: 'draft-farley-acta-signed-receipts-04 Sections 5.2, 5.5 and 9.2, envelope shape. Neither -03 nor -04 defines key revocation.',
  key: { kid: KID, public_key_hex: KEY.publicKeyHex, seed: '00..0c', window: WINDOW, revoked_at: REVOKED_AT },
  verification_mode: 'archival: no freshness window (Section 9.1) is applied.',
  invocation: 'verify <file> --jwks <jwks> --mode receipt --json',
  scoring: 'expected is the verdict under -04, which has no revocation rule. expected_if_revocation_checked is the verdict from a verifier that also honours revoked_at. A run declares which one it is scored against (REVOCATION_CHECKED=1 in run.mjs), so a verifier that does not read revoked_at is not scored as wrong.',
  signer_asserted: 'issued_at is asserted by the signer. A holder of the revoked key who dates a receipt before revoked_at passes even a revocation-aware verifier. Bounding when a receipt was issued needs its chain position and an external commitment; see ../timeliness/.',
  cases: CASES.map(({ issued_at, ...c }) => ({
    ...c,
    issued_at,
    signed_input_hex: Buffer.from(canonicalize(receipt(issued_at).payload), 'utf8').toString('hex'),
  })),
}))

let stale = 0
for (const [name, text] of files) {
  const target = path.join(DIR, name)
  if (CHECK) {
    const current = fs.existsSync(target) ? fs.readFileSync(target, 'utf8') : null
    if (current !== text) { console.error(`stale: ${name}`); stale += 1 }
  } else {
    fs.writeFileSync(target, text)
  }
}
if (CHECK) {
  if (stale) process.exit(1)
  console.log(`revocation vectors: ${files.size} files current`)
} else {
  console.log(`revocation vectors: wrote ${files.size} files to ${DIR}`)
}
