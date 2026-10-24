#!/usr/bin/env node
// Deterministically generate the signing-input vectors (draft-farley-acta-signed-receipts-03 Section 6.6).
//
//   node verifier-vectors/signing-input/scripts/generate.mjs          write the files
//   node verifier-vectors/signing-input/scripts/generate.mjs --check  fail if a file is stale
//
// Section 6.6: "In either shape the object canonicalized MUST NOT contain a signature member, and that member MUST NOT
// be included as null or as the empty string." Each rejected receipt below is genuinely signed over JCS(payload), the
// member included, so its signature verifies: a verifier has to refuse it for what the payload carries, not because the
// signature check fails. The case was found by astrogilda in probityai/agent-evidence-vectors 0.13.0
// (vectors-receipt-signature, v5397adb77c3e6754).

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { keyPairFromSeed, signHex, verifyHex } from '../../../evidence-predicate/lib.mjs'

const DIR = path.dirname(path.dirname(fileURLToPath(import.meta.url)))
const CHECK = process.argv.includes('--check')

// A deterministic test key. Public, and MUST NOT be reused. Its seed is used nowhere else in this repository.
const KEY = keyPairFromSeed('000000000000000000000000000000000000000000000000000000000000000e')
const KID = 'test:signing-input:ed25519'
const x = Buffer.from(KEY.publicKeyHex, 'hex').toString('base64url')
const jwk = { kty: 'OKP', crv: 'Ed25519', kid: KID, x, use: 'sig' }

const FIELDS = {
  type: 'protectmcp:decision',
  tool_name: 'records.share',
  decision: 'allow',
  issued_at: '2026-07-15T12:00:00Z',
  issuer_id: KID,
  policy_digest: 'sha256:8ca92f7dfaaf6f4fee88f3892cd7122ab48912c0f9666f70df79b2973627b888',
}

// member: the value of the payload's signature member, or undefined for none.
const CASES = [
  { file: 'null-member.json', member: null, expected: 'REJECT', code: 'signature_in_signing_input',
    note: 'The payload carries "signature": null. The signature over JCS(payload) verifies; Section 6.6 still forbids the member.' },
  { file: 'empty-member.json', member: '', expected: 'REJECT', code: 'signature_in_signing_input',
    note: 'The payload carries "signature": "", which Section 6.6 names alongside null.' },
  { file: 'string-member.json', member: 'not the signature', expected: 'REJECT', code: 'signature_in_signing_input',
    note: 'Any signature member in the object canonicalized, whatever its value.' },
  { file: 'no-member.json', member: undefined, expected: 'ACCEPT', code: null,
    note: 'The twin: the same fields with no signature member. It verifies.' },
]

function receipt(member) {
  const payload = member === undefined ? { ...FIELDS } : { ...FIELDS, signature: member }
  const sig = signHex(payload, KEY.privateKey)
  if (!verifyHex(payload, sig, KEY.publicKeyHex)) throw new Error('a generated signature does not verify')
  return { payload, signature: { alg: 'EdDSA', kid: KID, sig } }
}

const files = new Map()
const json = (value) => JSON.stringify(value, null, 2) + '\n'
files.set('jwks.json', json({ keys: [jwk] }))
for (const c of CASES) files.set(c.file, json(receipt(c.member)))
files.set('index.json', json({
  suite: 'signing-input',
  profile: 'draft-farley-acta-signed-receipts-03 Section 6.6 (unchanged in -04), envelope shape',
  key: { kid: KID, public_key_hex: KEY.publicKeyHex, seed: '00..0e' },
  source: 'astrogilda, probityai/agent-evidence-vectors 0.13.0, vectors-receipt-signature v5397adb77c3e6754',
  invocation: 'verify <file> --jwks jwks.json --mode receipt --json',
  cases: CASES.map(({ member, ...c }) => ({ ...c, jwks: 'jwks.json' })),
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
  console.log(`signing-input vectors: ${files.size} files current`)
} else {
  console.log(`signing-input vectors: wrote ${files.size} files to ${DIR}`)
}
