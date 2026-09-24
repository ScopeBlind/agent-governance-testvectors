#!/usr/bin/env node
// Deterministically generate the timeliness vectors: one receipt with one issued_at, presented alone and then at
// its position in a chain whose prefix the issuer committed to outside the chain (draft-farley-acta-signed-receipts-04
// Section 9.7). A receipt cannot prove when it was issued. Its position against an external commitment can bound it,
// and neither -03 nor -04 defines the commitment's format or asks a verifier to read its time, so these vectors state
// the gap: a conformant verifier accepts all three cases.
//
//   node verifier-vectors/timeliness/scripts/generate.mjs          write the files
//   node verifier-vectors/timeliness/scripts/generate.mjs --check  fail if a file is stale

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { canonicalize, keyPairFromSeed, sha256Hex, signHex } from '../../../evidence-predicate/lib.mjs'

const DIR = path.dirname(path.dirname(fileURLToPath(import.meta.url)))
const CHECK = process.argv.includes('--check')

// A deterministic test key. Public, and MUST NOT be reused. Its seed is used nowhere else in this repository.
const KEY = keyPairFromSeed('000000000000000000000000000000000000000000000000000000000000000d')
const KID = 'test:chained:ed25519'
const WINDOW = { valid_from: '2026-01-01T00:00:00Z', valid_until: '2027-01-01T00:00:00Z' }
const x = Buffer.from(KEY.publicKeyHex, 'hex').toString('base64url')
const POLICY = 'sha256:8ca92f7dfaaf6f4fee88f3892cd7122ab48912c0f9666f70df79b2973627b888'

function sign(payload) {
  return { payload, signature: { alg: 'EdDSA', kid: KID, sig: signHex(payload, KEY.privateKey) } }
}

// Section 6.7: "sha256:" + hex(SHA-256(JCS(receipt))) over the whole signed receipt, signature included.
const link = (signed) => `sha256:${sha256Hex(signed)}`

const genesis = sign({
  type: 'protectmcp:decision', tool_name: 'read_file', decision: 'allow',
  issued_at: '2026-01-10T00:00:00Z', issuer_id: KID, policy_digest: POLICY,
})
const receipt = sign({
  type: 'protectmcp:decision', tool_name: 'payments.transfer', decision: 'allow',
  issued_at: '2026-02-15T00:00:00Z', issuer_id: KID, policy_digest: POLICY,
  previousReceiptHash: link(genesis),
})
// Section 9.7: "a commitment, external to the chain, to the number of receipts and the terminal hash at a given
// point, signed by the issuer". The draft names no format; this one carries exactly those two members. The type is
// namespaced to this repository because no revision defines one.
const commitment = sign({
  type: 'x-agent-governance-testvectors:chain-commitment', issuer_id: KID, count: 1, terminal_hash: link(genesis),
})

// logged_at is the time the destination the issuer cannot rewrite recorded the commitment. It is outside the signed
// bytes because the issuer does not assert it. The two values sit either side of the receipt's issued_at.
const CASES = [
  { name: 'alone', chain: ['receipt.json'], commitment: null, logged_at: null,
    expected: 'ACCEPT', code: null,
    expected_if_commitment_checked: 'ACCEPT', code_if_commitment_checked: null,
    timeliness: 'not_established',
    note: 'The receipt with nothing around it. Its signature verifies; its issued_at is the signer\'s word and nothing bounds it.' },
  { name: 'committed-after', chain: ['genesis.json', 'receipt.json'], commitment: 'commitment.json', logged_at: '2026-03-01T00:00:00Z',
    expected: 'ACCEPT', code: null,
    expected_if_commitment_checked: 'REJECT', code_if_commitment_checked: 'issued_at_precedes_excluding_commitment',
    timeliness: 'contradicted',
    note: 'The same receipt at position 2. On 2026-03-01 the issuer committed to a chain of one receipt, so position 2 did not exist then, and the receipt\'s issued_at of 2026-02-15 is contradicted by the issuer\'s own external commitment. -04 asks a verifier to read neither the commitment nor its time, so a conformant verifier accepts. That acceptance is the gap.' },
  { name: 'committed-before', chain: ['genesis.json', 'receipt.json'], commitment: 'commitment.json', logged_at: '2026-02-01T00:00:00Z',
    expected: 'ACCEPT', code: null,
    expected_if_commitment_checked: 'ACCEPT', code_if_commitment_checked: null,
    timeliness: 'not_before 2026-02-01T00:00:00Z',
    note: 'The conformant twin: the same receipt and the same signed commitment, logged on 2026-02-01, before issued_at. Position 2 not existing then is consistent with issuance on 2026-02-15, and the receipt is now bounded below. An upper bound needs a later commitment that includes it.' },
]

const files = new Map()
const json = (value) => JSON.stringify(value, null, 2) + '\n'
files.set('jwks.json', json({ keys: [{ kty: 'OKP', crv: 'Ed25519', kid: KID, x, use: 'sig', ...WINDOW }] }))
files.set('genesis.json', json(genesis))
files.set('receipt.json', json(receipt))
files.set('commitment.json', json(commitment))
const hex = (signed) => Buffer.from(canonicalize(signed.payload), 'utf8').toString('hex')
files.set('index.json', json({
  suite: 'receipt-timeliness',
  profile: 'draft-farley-acta-signed-receipts-04 Sections 5.3, 6.7 and 9.7, envelope shape. Neither -03 nor -04 defines the commitment format or a rule that reads its time.',
  key: { kid: KID, public_key_hex: KEY.publicKeyHex, seed: '00..0d', window: WINDOW },
  verification_mode: 'archival: no freshness window (Section 9.1) is applied.',
  invocation: 'verify <file> --jwks jwks.json --mode receipt --json, once per receipt in the chain',
  chain_rule: 'receipt.json carries previousReceiptHash = "sha256:" + hex(SHA-256(JCS(genesis.json))), Section 6.7.',
  proposed_rule: 'A receipt at chain position p, with an external commitment of count c < p recorded at logged_at by a destination the issuer cannot rewrite, was not issued before logged_at. If its issued_at is earlier, the issuer\'s two signed statements contradict each other and the receipt is rejected. The commitment\'s terminal_hash must equal the link to position c.',
  scoring: 'expected is the verdict under -04: every signature and the chain link verify, and nothing reads the commitment. expected_if_commitment_checked is the verdict under the proposed rule. scripts/check.mjs evaluates both.',
  signed_inputs: {
    'genesis.json': hex(genesis),
    'receipt.json': hex(receipt),
    'commitment.json': hex(commitment),
  },
  cases: CASES,
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
  console.log(`timeliness vectors: ${files.size} files current`)
} else {
  console.log(`timeliness vectors: wrote ${files.size} files to ${DIR}`)
}
