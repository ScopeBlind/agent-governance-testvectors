#!/usr/bin/env node
// Deterministically generate the key validity window vectors
// (draft-farley-acta-signed-receipts-04 Section 5.5; Section 9.2 of -03).
//
//   node verifier-vectors/key-window/scripts/generate.mjs          write the files
//   node verifier-vectors/key-window/scripts/generate.mjs --check  fail if a file is stale

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { keyPairFromSeed, signHex } from '../../../evidence-predicate/lib.mjs'

const DIR = path.dirname(path.dirname(fileURLToPath(import.meta.url)))
const CHECK = process.argv.includes('--check')

// A deterministic test key. Public, and MUST NOT be reused. Its seed is used nowhere else in this repository.
const KEY = keyPairFromSeed('000000000000000000000000000000000000000000000000000000000000000b')
const KID = 'test:rotating:ed25519'
const WINDOW = { valid_from: '2026-01-01T00:00:00Z', valid_until: '2026-06-01T00:00:00Z' }
const x = Buffer.from(KEY.publicKeyHex, 'hex').toString('base64url')

const jwk = { kty: 'OKP', crv: 'Ed25519', kid: KID, x, use: 'sig' }

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

// Each case: the receipt, the key set the verifier is given, and what a verifier conforming to -04 Section 5.5
// must report. key_status is the verifier's own statement of what was established about the key at issuance.
const CASES = [
  { file: 'inside.json', issued_at: '2026-03-15T00:00:00Z', jwks: 'jwks.json', expected: 'ACCEPT', code: null, key_status: 'inside',
    note: 'Issued inside the window.' },
  { file: 'at-valid-from.json', issued_at: '2026-01-01T00:00:00Z', jwks: 'jwks.json', expected: 'ACCEPT', code: null, key_status: 'inside',
    note: 'Issued exactly at valid_from: the window includes its start.' },
  { file: 'at-valid-until.json', issued_at: '2026-06-01T00:00:00Z', jwks: 'jwks.json', expected: 'REJECT', code: 'key_outside_validity_window', key_status: 'outside',
    note: 'Issued exactly at valid_until: the window excludes its end, as RFC 7519 treats exp. Discriminates [from, until) from [from, until].' },
  { file: 'after-valid-until.json', issued_at: '2026-07-15T00:00:00Z', jwks: 'jwks.json', expected: 'REJECT', code: 'key_outside_validity_window', key_status: 'outside',
    note: 'A valid signature from a key already rotated out. issued_at is signer-asserted, so this catches honest rotation, not backdating.' },
  { file: 'before-valid-from.json', issued_at: '2025-12-01T00:00:00Z', jwks: 'jwks.json', expected: 'REJECT', code: 'key_outside_validity_window', key_status: 'outside',
    note: 'Issued before the key came into use.' },
  { file: 'inside.json', issued_at: '2026-03-15T00:00:00Z', jwks: 'jwks-no-window.json', expected: 'ACCEPT', code: null, key_status: 'no_window',
    note: 'The same receipt with a key set that carries no window: the signature verifies, and the key\'s validity at issuance is reported as not established, never as valid.' },
]

const files = new Map()
const json = (value) => JSON.stringify(value, null, 2) + '\n'
files.set('jwks.json', json({ keys: [{ ...jwk, ...WINDOW }] }))
files.set('jwks-no-window.json', json({ keys: [jwk] }))
for (const c of CASES) files.set(c.file, json(receipt(c.issued_at)))
files.set('index.json', json({
  suite: 'key-validity-windows',
  profile: 'draft-farley-acta-signed-receipts-04 Section 5.5 (Section 9.2 of -03), envelope shape',
  key: { kid: KID, public_key_hex: KEY.publicKeyHex, seed: '00..0b', window: WINDOW },
  verification_mode: 'archival: no freshness window (Section 9.1) is applied, so the dates are never "stale".',
  invocation: 'verify <file> --jwks <jwks> --mode receipt --json',
  cases: CASES.map(({ issued_at, ...c }) => ({ ...c, issued_at })),
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
  console.log(`key-window vectors: ${files.size} files current`)
} else {
  console.log(`key-window vectors: wrote ${files.size} files to ${DIR}`)
}
