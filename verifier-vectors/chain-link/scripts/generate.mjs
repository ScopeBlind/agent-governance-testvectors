#!/usr/bin/env node
// Deterministically generate the chain-link vectors (draft-farley-acta-signed-receipts-04 Sections 6.7 and 6.7.1, and
// the combination rule of Section 5.3).
//
//   node verifier-vectors/chain-link/scripts/generate.mjs          write the files
//   node verifier-vectors/chain-link/scripts/generate.mjs --check  fail if a file is stale
//
// Section 6.7: "The previousReceiptHash field MUST be the string "sha256:" followed by the lowercase hex encoding of
// SHA-256(JCS(receipt))", where receipt is the whole signed receipt, signature included. A verifier recognizes that
// form and the bare 64-hex form of earlier revisions. A value naming another hash algorithm is undecidable, whether or
// not the verifier implements it. Any other value is malformed, and the receipt is invalid whether or not the verifier
// holds its predecessor.
//
// Section 6.7.1 says how a link is read. Against a predecessor the caller supplies, asserting succession, the receipt
// follows it only if its link is that receipt's link, in either form: an absent, null or other link is invalid, and one
// naming another algorithm undecidable. Read as a sequence, with no succession asserted, a receipt with no link begins
// a new chain, null is read as an omitted member with a warning, and a link on the first receipt is reported, not
// failed. In both, a link over the predecessor's payload alone is never that predecessor's link.
//
// Section 5.3: a verification that makes several checks is invalid if any check ran and failed, even when another
// could not run.
//
// Every receipt below is genuinely signed over JCS(payload), its link included, so its signature verifies: a refusal has
// to come from the link, or from how the link is read.

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
// The same key with a validity window (Section 5.5) that ended before any receipt here was issued.
const WINDOW_ENDED = { valid_from: '2026-01-01T00:00:00Z', valid_until: '2026-07-01T00:00:00Z' }

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

// The first receipt omits the member (Section 2.2). Every other receipt is issued five minutes later and differs from
// the others only in its link: the link to genesis.json in some form, another value, or none.
const genesis = receipt('2026-07-15T12:00:00Z', undefined)
const digest = (algorithm, encoding = 'hex') => crypto.createHash(algorithm).update(Buffer.from(canonicalize(genesis), 'utf8')).digest(encoding)
const SHA256 = sha256Hex(genesis)
const PAYLOAD_ONLY = sha256Hex(genesis.payload)

const RECEIPTS = new Map([
  ['genesis.json', genesis],
  ...[
    ['linked.json', `sha256:${SHA256}`],
    ['malformed-digest.json', 'sha256:not-a-digest'],
    ['uppercase-hex.json', `sha256:${SHA256.toUpperCase()}`],
    ['sha3-256-link.json', `sha3-256:${digest('sha3-256')}`],
    ['sha512-link.json', `sha512:${digest('sha512')}`],
    ['no-link.json', undefined],
    ['null-link.json', null],
    ['bare-hex-link.json', SHA256],
    ['payload-only-link.json', `sha256:${PAYLOAD_ONLY}`],
    ['short-digest.json', `sha256:${SHA256.slice(0, 63)}`],
    ['base64url-link.json', `sha256:${digest('sha256', 'base64url')}`],
    ['empty-link.json', ''],
    ['non-string-link.json', { sha256: SHA256 }],
  ].map(([file, link]) => [file, receipt('2026-07-15T12:05:00Z', link)]),
])

// Sequences: receipts in the order a log holds them, one per line, read with no succession asserted.
const SEQUENCES = new Map([
  ['sequence-linked.jsonl', ['genesis.json', 'linked.json']],
  ['sequence-new-chain.jsonl', ['genesis.json', 'no-link.json']],
  ['sequence-null-link.jsonl', ['genesis.json', 'null-link.json']],
  ['sequence-first-linked.jsonl', ['linked.json']],
  ['sequence-payload-only.jsonl', ['genesis.json', 'payload-only-link.json']],
])

// check: alone (the receipt with nothing else), supplied-predecessor (with the receipt the caller says it follows), or
// sequence (a log read in order). outcome is the Section 5.3 outcome and exit the verifier's status for it: 0 valid,
// 1 invalid, 2 undecidable. jwks null means no key is supplied at all.
const VALID = { expected: 'ACCEPT', outcome: 'valid', code: null, exit: 0 }
const INVALID = (code) => ({ expected: 'REJECT', outcome: 'invalid', code, exit: 1 })
const UNDECIDABLE = (code) => ({ expected: 'REJECT', outcome: 'undecidable', code, exit: 2 })
const alone = (file, verdict, section, note, extra = {}) => ({ file, check: 'alone', jwks: 'jwks.json', ...verdict, ...extra, section, note })
const after = (file, previous, verdict, section, note) => ({ file, check: 'supplied-predecessor', previous, jwks: 'jwks.json', ...verdict, section, note })
const sequence = (file, verdict, seq, section, note) => ({ file, check: 'sequence', sequence: SEQUENCES.get(file), jwks: 'jwks.json', ...verdict, ...seq, section, note })

const S67 = '-04 Section 6.7'
const S671 = '-04 Section 6.7.1'
const CASES = [
  // Each receipt alone: the form of the link, with nothing to compare it with.
  alone('genesis.json', VALID, '-04 Section 2.2',
    'The first receipt of a chain, which omits previousReceiptHash (Section 2.2).'),
  alone('linked.json', VALID, S67,
    'The Section 6.7 form: "sha256:" and the lowercase hex of SHA-256(JCS(genesis.json)), its signature included.'),
  alone('malformed-digest.json', INVALID('malformed_chain_link'), S67,
    'The prefix is right and what follows is not a digest, so the link cannot name any receipt.'),
  alone('uppercase-hex.json', INVALID('malformed_chain_link'), S67,
    'The genesis digest in uppercase hex. Section 6.7 requires lowercase.'),
  alone('sha3-256-link.json', UNDECIDABLE('unsupported_chain_hash_algorithm'), S67,
    'A SHA3-256 digest of genesis.json: 64 hex characters, the length of a SHA-256 digest, so the prefix has to be read.'),
  alone('sha512-link.json', UNDECIDABLE('unsupported_chain_hash_algorithm'), S67,
    'A SHA-512 digest of genesis.json. Section 6.7 defines links under SHA-256 alone, so the link is undecidable whether or not the verifier implements SHA-512, and the outcome names the algorithm.'),
  alone('null-link.json', VALID, S671,
    'previousReceiptHash is null, which an issuer MUST NOT emit (Section 2.2). Checked alone, null is read as an omitted member, so the receipt begins a chain, and the verifier SHOULD warn that its issuer emitted it.', { warn: true }),
  alone('bare-hex-link.json', VALID, S67,
    'The genesis link as bare hex with no prefix, the encoding of earlier revisions. A verifier MUST recognize it; an issuer MUST NOT emit it.'),
  alone('short-digest.json', INVALID('malformed_chain_link'), S67,
    'The genesis digest with its last character dropped: 63 hex characters, the wrong length.'),
  alone('base64url-link.json', INVALID('malformed_chain_link'), S67,
    'The genesis digest in base64url after the "sha256:" prefix. Another encoding is malformed.'),
  alone('empty-link.json', INVALID('malformed_chain_link'), S67,
    'The empty string. Section 2.2 has a first receipt omit the member instead, and Section 6.7 makes the empty string malformed.'),
  alone('non-string-link.json', INVALID('malformed_chain_link'), S67,
    'An object carrying the genesis digest. A link is a string, and a value that is not one is malformed.'),

  // Against a supplied predecessor: the caller asserts the receipt follows it.
  after('linked.json', 'genesis.json', VALID, S671,
    'previousReceiptHash is the Section 6.7 link of the receipt supplied, so the receipt follows it.'),
  after('bare-hex-link.json', 'genesis.json', VALID, S671,
    'The same link as bare hex. The receipt follows its predecessor if the member is that receipt\'s link in either form.'),
  after('no-link.json', 'genesis.json', INVALID('chain_break'), S671,
    'No previousReceiptHash. Absence never satisfies a supplied predecessor: an unchained receipt does not follow the receipt supplied.'),
  after('null-link.json', 'genesis.json', INVALID('chain_break'), S671,
    'A null link is never a link to any receipt, so against a supplied predecessor it fails as an absent one does.'),
  after('payload-only-link.json', 'genesis.json', INVALID('chain_break'), S671,
    '"sha256:" and the hex of SHA-256(JCS(genesis.json payload)), the payload alone. No revision defines that link, and it would let a re-signed receipt keep the original\'s link.'),
  after('linked.json', 'no-link.json', INVALID('chain_break'), S671,
    'A well-formed link to genesis.json, checked against another receipt. It names a receipt, not the one supplied.'),
  after('sha3-256-link.json', 'genesis.json', UNDECIDABLE('unsupported_chain_hash_algorithm'), S671,
    'A link naming another hash algorithm cannot be compared with the predecessor\'s link, so whether the receipt follows it is undecidable, not invalid.'),
  after('uppercase-hex.json', 'genesis.json', INVALID('malformed_chain_link'), S67,
    'The genesis digest in uppercase hex, against the receipt it would name if read without regard to case. A malformed link is invalid with the predecessor as without it.'),

  // Read as a sequence: one log, no succession asserted.
  sequence('sequence-linked.jsonl', VALID, { line: 2, chains: 1, chain_breaks: 0 }, S671,
    'genesis.json, then linked.json: one chain.'),
  sequence('sequence-new-chain.jsonl', VALID, { line: 2, chains: 2, chain_breaks: 0 }, S671,
    'genesis.json, then no-link.json. A later receipt that omits the member begins a new chain; it is never reported as linked to the receipt before it, and is not a break.'),
  sequence('sequence-null-link.jsonl', VALID, { line: 2, chains: 2, chain_breaks: 0, warn: true }, S671,
    'genesis.json, then null-link.json. In a sequence null is read as an omitted member, so line 2 begins a new chain, and the verifier SHOULD warn that its issuer emitted it.'),
  sequence('sequence-first-linked.jsonl', VALID, { line: 1, chains: 1, chain_breaks: 0 }, S671,
    'linked.json alone, as the first receipt of a sequence that does not hold genesis.json. A link on the first receipt is reported, not failed: nothing before it was supplied.'),
  sequence('sequence-payload-only.jsonl', INVALID('chain_break'), { line: 2, chains: 1, chain_breaks: 1 }, S671,
    'genesis.json, then payload-only-link.json. A link over the payload alone does not follow line 1 in a sequence either.'),

  // The combination rule: a check that ran and failed decides, even when another could not run.
  alone('malformed-digest.json', INVALID('malformed_chain_link'), '-04 Section 5.3',
    'No key is supplied, so the signature cannot be checked (undecidable), and the link is malformed (invalid). A failed check outweighs one that could not run: invalid.', { jwks: null }),
  alone('sha3-256-link.json', INVALID('key_outside_validity_window'), '-04 Section 5.3',
    'The signature verifies and the link names another algorithm (undecidable), but the key set bounds the key to [2026-01-01, 2026-07-01) and the receipt was issued on 2026-07-15 (invalid, Section 5.5). The failed window check decides: invalid.', { jwks: 'jwks-window-ended.json' }),
]

const files = new Map()
const json = (value) => JSON.stringify(value, null, 2) + '\n'
files.set('jwks.json', json({ keys: [jwk] }))
files.set('jwks-window-ended.json', json({ keys: [{ ...jwk, ...WINDOW_ENDED }] }))
for (const [name, r] of RECEIPTS) files.set(name, json(r))
for (const [name, members] of SEQUENCES) files.set(name, members.map((m) => JSON.stringify(RECEIPTS.get(m)) + '\n').join(''))
files.set('index.json', json({
  suite: 'chain-link',
  profile: 'draft-farley-acta-signed-receipts-04 Sections 6.7 and 6.7.1, and the combination rule of Section 5.3, envelope shape: each receipt checked alone, against a supplied predecessor, or read as a sequence',
  key: { kid: KID, public_key_hex: KEY.publicKeyHex, seed: '00..0f' },
  chain_rule: 'A link is "sha256:" + hex(SHA-256(JCS(previous receipt))), signature included, or the same 64 hex characters bare (Section 6.7). linked.json carries the link to genesis.json, and every other receipt issued after genesis.json differs from it only in that member. Against a supplied predecessor the receipt follows it only if its previousReceiptHash is that receipt\'s link, in either form. Read as a sequence, a receipt with no link, or a null one, begins a new chain, and a link on the first receipt is reported, not failed (Section 6.7.1).',
  invocation: {
    alone: 'verify <file> --jwks <jwks> --mode receipt --json (with no --jwks when jwks is null)',
    'supplied-predecessor': 'verify <file> --previous <previous> --jwks <jwks> --mode receipt --json',
    sequence: 'verify --replay-chain <file> --jwks <jwks> --json',
  },
  scoring: 'expected, outcome and exit are the verdict under -04 Section 5.3; code names the check that decided it. For a sequence, line is the receipt the case turns on, code is that line\'s, chains is the number of chains the verifier reports the sequence holds, and chain_breaks the links it reports broken. warn is true where the verifier SHOULD warn that an issuer emitted a null link.',
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
  console.log(`chain-link vectors: ${files.size} files current`)
} else {
  console.log(`chain-link vectors: wrote ${files.size} files to ${DIR}`)
}
