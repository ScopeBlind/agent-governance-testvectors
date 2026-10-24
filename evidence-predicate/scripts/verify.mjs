#!/usr/bin/env node
// Verify the evidence predicate vectors as a relying party would, with no
// project-specific dependencies: Section 4.3's four conditions per entry.

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { evidenceClaim, sha256Hex, validateEvidenceEntry, verifyHex, verifyReceipt } from '../lib.mjs'

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)))
const trust = JSON.parse(fs.readFileSync(path.join(ROOT, 'trust-policy.json'), 'utf8'))
const vectorsDir = path.join(ROOT, 'vectors')
const ids = fs.readdirSync(vectorsDir).filter((name) => /^\d\d-/.test(name)).sort()
let failures = 0
const fail = (id, message) => { failures += 1; console.error(`FAIL ${id}: ${message}`) }

// One entry, one verdict. Section 4.3: independent corroboration requires (1) a
// sig, (2) a key obtained out of band whose id equals source.kid, (3) that key
// distinct from the receipt signer's key and, by the relying party's own
// policy, in a distinct control domain, and (4) the sig verifying over the JCS
// bytes of the claim. Anything less is the signer's own word.
function judge(entry, receiptSigner) {
  const source = entry.source
  const pinned = source.kid ? trust.source_keys[source.kid] : undefined
  const r = {
    dimension: entry.dimension,
    source_signature_present: typeof source.sig === 'string',
    source_signature_valid: false,
    source_key_out_of_band: Boolean(pinned),
    source_key_distinct: Boolean(pinned && pinned.public_key_hex !== receiptSigner.public_key_hex),
    source_control_domain_distinct: Boolean(pinned && pinned.control_domain !== receiptSigner.control_domain),
  }
  if (r.source_signature_present && pinned) r.source_signature_valid = verifyHex(evidenceClaim(entry), source.sig, pinned.public_key_hex)
  r.independent_corroboration = r.source_signature_present && r.source_key_out_of_band && r.source_signature_valid && r.source_key_distinct && r.source_control_domain_distinct
  r.reason = !r.source_signature_present ? 'source_signature_absent'
    : !r.source_key_out_of_band ? 'source_key_not_pinned'
    : !r.source_signature_valid ? 'source_signature_invalid'
    : !r.source_key_distinct || !r.source_control_domain_distinct ? 'source_key_not_independent'
    : 'independent_source_signature_verified'
  return r
}

for (const id of ids) {
  const dir = path.join(vectorsDir, id)
  const receipt = JSON.parse(fs.readFileSync(path.join(dir, 'receipt.json'), 'utf8'))
  const expected = JSON.parse(fs.readFileSync(path.join(dir, 'expected.json'), 'utf8'))
  const receiptSigner = trust.receipt_signers[receipt.kid]
  if (!receiptSigner) { fail(id, 'receipt signer is not pinned by the out-of-band trust policy'); continue }
  const receiptOk = verifyReceipt(receipt, receiptSigner.public_key_hex)
  if (receiptOk !== expected.receipt_signature_valid) fail(id, `receipt_signature_valid: expected ${expected.receipt_signature_valid}, got ${receiptOk}`)
  if (`sha256:${sha256Hex(receipt)}` !== expected.receipt_digest) fail(id, 'receipt digest does not match the committed artifact')

  const evidence = receipt.payload?.evidence
  if (!Array.isArray(evidence)) { fail(id, 'payload.evidence must be an array (Section 4)'); continue }
  const results = []
  evidence.forEach((entry, i) => {
    const structural = validateEvidenceEntry(entry)
    if (structural) { fail(id, `entry ${i}: ${structural}`); return }
    results.push(receiptOk ? judge(entry, receiptSigner) : { dimension: entry.dimension, independent_corroboration: false, reason: 'receipt_signature_invalid' })
  })
  if (results.length !== expected.entries.length) { fail(id, `expected ${expected.entries.length} entries, judged ${results.length}`); continue }
  expected.entries.forEach((want, i) => {
    for (const [key, value] of Object.entries(want)) {
      if (results[i][key] !== value) fail(id, `entry ${i} ${key}: expected ${JSON.stringify(value)}, got ${JSON.stringify(results[i][key])}`)
    }
  })
  const independent = results.filter((r) => r.independent_corroboration).map((r) => r.dimension)
  if (JSON.stringify(independent) !== JSON.stringify(expected.independent_dimensions)) fail(id, `independent dimensions: expected ${JSON.stringify(expected.independent_dimensions)}, got ${JSON.stringify(independent)}`)
  if (expected.signed_claim_omits_as_of) {
    evidence.forEach((entry, i) => {
      const omits = !Object.hasOwn(evidenceClaim(entry), 'as_of')
      if (omits !== expected.signed_claim_omits_as_of[i]) fail(id, `entry ${i}: signed claim as_of presence differs from expected`)
    })
  }
  const claims = JSON.parse(fs.readFileSync(path.join(dir, 'source-claims.json'), 'utf8'))
  evidence.forEach((entry, i) => {
    const want = entry.source.sig ? evidenceClaim(entry) : null
    if (JSON.stringify(claims[i]) !== JSON.stringify(want)) fail(id, `entry ${i}: committed source claim differs from the reconstructed claim`)
  })
  console.log(`${id}: ${results.map((r) => `${r.dimension} ${r.independent_corroboration ? 'independent' : 'not independent'} (${r.reason})`).join('; ')}`)
}

// Structural negatives: each must be rejected for exactly the reason on file.
const invalidDir = path.join(ROOT, 'invalid')
for (const name of fs.readdirSync(invalidDir).filter((n) => n.endsWith('.json')).sort()) {
  const { reason, entry } = JSON.parse(fs.readFileSync(path.join(invalidDir, name), 'utf8'))
  const got = validateEvidenceEntry(entry)
  if (got !== reason) fail(`invalid/${name}`, `expected rejection ${JSON.stringify(reason)}, got ${JSON.stringify(got)}`)
  else console.log(`invalid/${name}: rejected (${reason})`)
}

if (failures) { console.error(`${failures} failure(s)`); process.exit(1) }
console.log(`verified ${ids.length} evidence predicate vectors`)
