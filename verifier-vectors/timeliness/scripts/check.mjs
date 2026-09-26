#!/usr/bin/env node
// Reference evaluation of the timeliness vectors, dependency-free. For each case it computes the -04 verdict
// (signatures under jwks.json, and the Section 6.7 chain link) and the verdict under the proposed commitment rule,
// and compares both to index.json. It then plants two defects the -04 checks must catch, so a pass here cannot come
// from a check that never fires.
//
//   node verifier-vectors/timeliness/scripts/check.mjs
//
// Exit: 0 every verdict matched and every planted defect was caught, 1 otherwise.

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { sha256Hex, verifyHex } from '../../../evidence-predicate/lib.mjs'

const DIR = path.dirname(path.dirname(fileURLToPath(import.meta.url)))
const read = (name) => JSON.parse(fs.readFileSync(path.join(DIR, name), 'utf8'))
const index = read('index.json')
const [jwk] = read('jwks.json').keys
const publicKeyHex = Buffer.from(jwk.x, 'base64url').toString('hex')
const link = (signed) => `sha256:${sha256Hex(signed)}`
const ts = (s) => Date.parse(s)

const signatureOk = (signed) => signed.signature.kid === jwk.kid && verifyHex(signed.payload, signed.signature.sig, publicKeyHex)
const inWindow = (signed) => ts(signed.payload.issued_at) >= ts(jwk.valid_from) && ts(signed.payload.issued_at) < ts(jwk.valid_until)

// The -04 verdict for a chain: every receipt verifies inside its key's window, and every link reproduces.
function verdict04(chain) {
  for (let i = 0; i < chain.length; i += 1) {
    if (!signatureOk(chain[i])) return { verdict: 'REJECT', code: 'signature_invalid' }
    if (!inWindow(chain[i])) return { verdict: 'REJECT', code: 'key_outside_validity_window' }
    if (i > 0 && chain[i].payload.previousReceiptHash !== link(chain[i - 1])) return { verdict: 'REJECT', code: 'chain_link_mismatch' }
  }
  return { verdict: 'ACCEPT', code: null }
}

// The proposed rule, applied to the last receipt of the chain, which is the one under test.
function verdictWithCommitment(chain, commitment, loggedAt) {
  const base = verdict04(chain)
  if (base.verdict !== 'ACCEPT' || !commitment) return base
  if (!signatureOk(commitment)) return { verdict: 'REJECT', code: 'commitment_signature_invalid' }
  const { count, terminal_hash: terminal } = commitment.payload
  if (count < 1 || count > chain.length || terminal !== link(chain[count - 1])) return { verdict: 'REJECT', code: 'commitment_does_not_match_chain' }
  const position = chain.length
  if (position > count && ts(chain[position - 1].payload.issued_at) < ts(loggedAt)) {
    return { verdict: 'REJECT', code: 'issued_at_precedes_excluding_commitment' }
  }
  return { verdict: 'ACCEPT', code: null }
}

let failed = 0
let passed = 0
const ok = (msg) => { passed += 1; console.log(`  ok    ${msg}`) }
const bad = (msg) => { failed += 1; console.log(`  FAIL  ${msg}`) }
const same = (got, verdict, code) => got.verdict === verdict && got.code === code

console.log('=== timeliness: reference evaluation ===')
for (const c of index.cases) {
  const chain = c.chain.map(read)
  const commitment = c.commitment ? read(c.commitment) : null
  const a = verdict04(chain)
  if (same(a, c.expected, c.code)) ok(`${c.name} under -04: ${a.verdict}`)
  else bad(`${c.name} under -04: ${a.verdict} ${a.code || ''}, expected ${c.expected} ${c.code || ''}`)
  const b = verdictWithCommitment(chain, commitment, c.logged_at)
  if (same(b, c.expected_if_commitment_checked, c.code_if_commitment_checked)) ok(`${c.name} with the commitment read: ${b.verdict}${b.code ? ` (${b.code})` : ''}`)
  else bad(`${c.name} with the commitment read: ${b.verdict} ${b.code || ''}, expected ${c.expected_if_commitment_checked} ${c.code_if_commitment_checked || ''}`)
}

console.log('=== timeliness: planted defects ===')
const genesis = read('genesis.json')
const receipt = read('receipt.json')
const tamperedGenesis = { ...genesis, payload: { ...genesis.payload, decision: 'deny' } }
const planted = [
  ['a genesis receipt altered after signing', verdict04([tamperedGenesis, receipt]), 'signature_invalid'],
  ['the same two receipts in reverse order: both signatures valid, the link does not reproduce', verdict04([receipt, genesis]), 'chain_link_mismatch'],
  ['a commitment altered after signing', verdictWithCommitment([genesis, receipt],
    (() => { const c = read('commitment.json'); return { ...c, payload: { ...c.payload, count: 2 } } })(), '2026-03-01T00:00:00Z'), 'commitment_signature_invalid'],
]
for (const [what, got, code] of planted) {
  if (got.verdict === 'REJECT' && got.code === code) ok(`caught: ${what} (${code})`)
  else bad(`not caught: ${what}: ${got.verdict} ${got.code || ''}`)
}
console.log(`\n${passed} passed, ${failed} failed`)
process.exit(failed ? 1 : 0)
