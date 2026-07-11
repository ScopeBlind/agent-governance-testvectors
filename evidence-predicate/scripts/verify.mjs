#!/usr/bin/env node
// Verify the evidence predicate vectors without project-specific dependencies.

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { evidenceClaim, sha256Hex, verifyHex } from '../lib.mjs'

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)))
const trust = JSON.parse(fs.readFileSync(path.join(ROOT, 'trust-policy.json'), 'utf8'))
const vectorsDir = path.join(ROOT, 'vectors')
const ids = fs.readdirSync(vectorsDir).filter((name) => /^\d\d-/.test(name)).sort()
let failures = 0

function fail(id, message) {
  failures += 1
  console.error(`${id}: ${message}`)
}

function validateEvidenceEntry(entry) {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return 'entry must be an object'
  const allowed = new Set(['dimension', 'state', 'source', 'as_of'])
  for (const key of Object.keys(entry)) if (!allowed.has(key)) return `unknown field ${key}`
  if (typeof entry.dimension !== 'string' || entry.dimension.length === 0) return 'dimension must be a non-empty string'
  if (!['verified', 'failed', 'unknown', 'not_applicable'].includes(entry.state)) return 'invalid state'
  if (Object.hasOwn(entry, 'as_of') && typeof entry.as_of !== 'string') return 'as_of must be omitted or an RFC 3339 string'
  if (!entry.source || typeof entry.source !== 'object' || Array.isArray(entry.source)) return 'source must be an object'
  const sourceAllowed = new Set(['authority', 'ref', 'kid', 'sig'])
  for (const key of Object.keys(entry.source)) if (!sourceAllowed.has(key)) return `unknown source field ${key}`
  if (typeof entry.source.authority !== 'string' || entry.source.authority.length === 0) return 'source.authority must be a non-empty string'
  if (typeof entry.source.ref !== 'string' || entry.source.ref.length === 0) return 'source.ref must be a non-empty string'
  if (entry.source.kid !== undefined && (typeof entry.source.kid !== 'string' || entry.source.kid.length === 0)) return 'source.kid must be a non-empty string'
  if (entry.source.sig !== undefined && !/^[0-9a-f]{128}$/.test(entry.source.sig)) return 'source.sig must be 128 lowercase hex characters'
  return null
}

for (const id of ids) {
  const dir = path.join(vectorsDir, id)
  const receipt = JSON.parse(fs.readFileSync(path.join(dir, 'receipt.json'), 'utf8'))
  const expected = JSON.parse(fs.readFileSync(path.join(dir, 'expected.json'), 'utf8'))
  const evidence = receipt?.payload?.evidence?.[0]
  const receiptSigner = trust.receipt_signers[receipt.kid]
  const sourceSigner = evidence?.source?.kid ? trust.source_keys[evidence.source.kid] : null

  const schemaError = validateEvidenceEntry(evidence)
  if (schemaError) {
    fail(id, `evidence entry schema violation: ${schemaError}`)
    continue
  }

  if (!receiptSigner) {
    fail(id, 'receipt signer is not pinned by the out-of-band trust policy')
    continue
  }
  const { signature, ...unsignedReceipt } = receipt
  const result = {
    receipt_signature_valid: verifyHex(unsignedReceipt, signature, receiptSigner.public_key_hex),
    source_signature_valid: sourceSigner ? verifyHex(evidenceClaim(evidence), evidence?.source?.sig, sourceSigner.public_key_hex) : false,
    source_key_out_of_band: Boolean(sourceSigner),
    source_key_distinct: Boolean(sourceSigner && sourceSigner.public_key_hex !== receiptSigner.public_key_hex),
    source_control_domain_distinct: Boolean(sourceSigner && sourceSigner.control_domain !== receiptSigner.control_domain),
  }
  result.independent_corroboration = Boolean(
    result.receipt_signature_valid &&
    result.source_signature_valid &&
    result.source_key_out_of_band &&
    result.source_key_distinct &&
    result.source_control_domain_distinct,
  )
  result.reason = !result.receipt_signature_valid ? 'receipt_signature_invalid'
    : !result.source_key_out_of_band ? 'source_key_not_pinned'
    : !result.source_signature_valid ? 'source_signature_invalid'
    : !result.source_key_distinct || !result.source_control_domain_distinct ? 'source_key_not_independent'
    : 'independent_source_signature_verified'

  const signedClaimOmitsAsOf = !Object.hasOwn(evidenceClaim(evidence), 'as_of')
  for (const [key, value] of Object.entries(expected)) {
    if (key === 'receipt_digest') continue
    if (key === 'signed_claim_omits_as_of') {
      if (signedClaimOmitsAsOf !== value) fail(id, `${key}: expected ${JSON.stringify(value)}, got ${JSON.stringify(signedClaimOmitsAsOf)}`)
      continue
    }
    if (result[key] !== value) fail(id, `${key}: expected ${JSON.stringify(value)}, got ${JSON.stringify(result[key])}`)
  }
  const expectedDigest = `sha256:${sha256Hex(receipt)}`
  if (expected.receipt_digest !== expectedDigest) fail(id, 'receipt digest does not match expected artifact')
  if (id === '02-independent-without-as-of' && !signedClaimOmitsAsOf) {
    fail(id, 'claim contains as_of when evidence omitted it')
  }
  if (failures === 0) console.log(`${id}: ${result.independent_corroboration ? 'independent' : 'not independent'} (${result.reason})`)
}

const nullAsOf = JSON.parse(fs.readFileSync(path.join(ROOT, 'invalid', 'null-as-of-entry.json'), 'utf8'))
if (validateEvidenceEntry(nullAsOf) !== 'as_of must be omitted or an RFC 3339 string') {
  fail('invalid/null-as-of-entry', 'nullable as_of was not rejected')
} else {
  console.log('invalid/null-as-of-entry: rejected nullable as_of')
}

if (failures) process.exit(1)
console.log(`verified ${ids.length} evidence predicate vectors`)
