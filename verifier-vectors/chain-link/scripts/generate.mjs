#!/usr/bin/env node
// Deterministically generate the chain-link vectors (draft-farley-acta-signed-receipts-03 Section 6.7, unchanged in -04).
//
//   node verifier-vectors/chain-link/scripts/generate.mjs          write the files
//   node verifier-vectors/chain-link/scripts/generate.mjs --check  fail if a file is stale
//
// Section 6.7: "The previousReceiptHash field MUST be the string "sha256:" followed by the lowercase hex encoding of
// SHA-256(JCS(receipt))", and "A verifier MUST reject a previousReceiptHash whose prefix names an algorithm it does not
// implement, rather than assuming SHA-256 from the length." Each receipt below is checked alone, with no predecessor
// supplied, and each is genuinely signed over JCS(payload), its link included, so its signature verifies: a verifier has
// to refuse a bad link for its form, because no chain check will ever compare it with anything.

import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { canonicalize, keyPairFromSeed, sha256Hex, signHex, verifyHex } from '../../../evidence-predicate/lib.mjs'

const DIR = path.dirname(path.dirname(fileURLToPath(import.meta.url)))
const CHECK = process.argv.includes('--check')

// A deterministic test key. Public, and MUST NOT be reused. Its seed is used nowhere else in this repository.
const KEY = keyPairFromSeed('000000000000000000000000000000000000000000000000000000000000000f')
const KID = 'test:chain-link:ed25519'
const x = Buffer.from(KEY.publicKeyHex, 'hex').toString('base64url')
const jwk = { kty: 'OKP', crv: 'Ed25519', kid: KID, x, use: 'sig' }

const FIELDS = {
  type: 'protectmcp:decision',
  tool_name: 'records.share',
  decision: 'allow',
  issuer_id: KID,
  policy_digest: 'sha256:8ca92f7dfaaf6f4fee88f3892cd7122ab48912c0f9666f70df79b2973627b888',
}

// link: the payload's previousReceiptHash, or undefined for none.
function receipt(issuedAt, link) {
  const payload = { ...FIELDS, issued_at: issuedAt }
  if (link !== undefined) payload.previousReceiptHash = link
  const sig = signHex(payload, KEY.privateKey)
  if (!verifyHex(payload, sig, KEY.publicKeyHex)) throw new Error('a generated signature does not verify')
  return { payload, signature: { alg: 'EdDSA', kid: KID, sig } }
}

// The first receipt omits the member (Section 2.2). Every other receipt links to it, each in a different form.
const genesis = receipt('2026-07-15T12:00:00Z', undefined)
const digest = (algorithm) => crypto.createHash(algorithm).update(Buffer.from(canonicalize(genesis), 'utf8')).digest('hex')
const SHA256 = sha256Hex(genesis)

const CASES = [
  { file: 'genesis.json', link: undefined, expected: 'ACCEPT', code: null, exit: 0,
    note: 'The first receipt of a chain, which omits previousReceiptHash (Section 2.2).' },
  { file: 'linked.json', link: `sha256:${SHA256}`, expected: 'ACCEPT', code: null, exit: 0,
    note: 'The Section 6.7 form: "sha256:" and the lowercase hex of SHA-256(JCS(genesis.json)), its signature included.' },
  { file: 'malformed-digest.json', link: 'sha256:not-a-digest', expected: 'REJECT', code: 'malformed_chain_link', exit: 1,
    note: 'The prefix is right and what follows is not a digest, so the link cannot name any receipt.' },
  { file: 'uppercase-hex.json', link: `sha256:${SHA256.toUpperCase()}`, expected: 'REJECT', code: 'malformed_chain_link', exit: 1,
    note: 'The genesis digest in uppercase hex. Section 6.7 requires lowercase.' },
  { file: 'sha3-256-link.json', link: `sha3-256:${digest('sha3-256')}`, expected: 'REJECT', code: 'unsupported_chain_hash_algorithm', exit: 2,
    note: 'A SHA3-256 digest of genesis.json: 64 hex characters, the length of a SHA-256 digest, so the prefix has to be read.' },
  { file: 'sha512-link.json', link: `sha512:${digest('sha512')}`, expected: 'REJECT', code: 'unsupported_chain_hash_algorithm', exit: 2,
    note: 'A SHA-512 digest of genesis.json. A verifier that does not implement the algorithm cannot decide the link, and refuses it.' },
]

const files = new Map()
const json = (value) => JSON.stringify(value, null, 2) + '\n'
files.set('jwks.json', json({ keys: [jwk] }))
for (const c of CASES) files.set(c.file, json(c.file === 'genesis.json' ? genesis : receipt('2026-07-15T12:05:00Z', c.link)))
files.set('index.json', json({
  suite: 'chain-link',
  profile: 'draft-farley-acta-signed-receipts-03 Section 6.7 (unchanged in -04), envelope shape, each receipt checked alone',
  key: { kid: KID, public_key_hex: KEY.publicKeyHex, seed: '00..0f' },
  chain_rule: 'linked.json carries previousReceiptHash = "sha256:" + hex(SHA-256(JCS(genesis.json))), Section 6.7. Each rejected receipt carries a link in another form, and none needs its predecessor to be refused.',
  invocation: 'verify <file> --jwks jwks.json --mode receipt --json',
  cases: CASES.map(({ link, ...c }) => ({ ...c, jwks: 'jwks.json' })),
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
  console.log(`chain-link vectors: ${files.size} files current`)
} else {
  console.log(`chain-link vectors: wrote ${files.size} files to ${DIR}`)
}
