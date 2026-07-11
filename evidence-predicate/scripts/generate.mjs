#!/usr/bin/env node
// Deterministically generate the evidence predicate reference vectors.

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { evidenceClaim, keyPairFromSeed, sha256Hex, signHex } from '../lib.mjs'

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)))
const CHECK = process.argv.includes('--check')
const RECEIPT = keyPairFromSeed('0000000000000000000000000000000000000000000000000000000000000001')
const CUSTODIAN = keyPairFromSeed('0000000000000000000000000000000000000000000000000000000000000002')

const receiptKid = 'test:manager:meridian:ed25519'
const custodianKid = 'test:custodian:demo:ed25519'

const trustPolicy = {
  type: 'scopeblind.evidence_trust_policy.v1',
  receipt_signers: {
    [receiptKid]: {
      public_key_hex: RECEIPT.publicKeyHex,
      control_domain: 'manager:meridian',
    },
  },
  source_keys: {
    [custodianKid]: {
      public_key_hex: CUSTODIAN.publicKeyHex,
      control_domain: 'custodian:demo',
    },
    [receiptKid]: {
      public_key_hex: RECEIPT.publicKeyHex,
      control_domain: 'manager:meridian',
    },
  },
}

function makeEvidence({ asOf, sourceKey, sourceKid, authority = 'custodian:demo' }) {
  const entry = {
    dimension: 'provenance',
    state: 'verified',
    source: {
      authority,
      ref: 'sha256:6e0a9aa1f9d5c8ce3d545fb7b1d452f84514e93f493f94f24fa7c8180cb49ac4',
      kid: sourceKid,
    },
    ...(asOf ? { as_of: asOf } : {}),
  }
  entry.source.sig = signHex(evidenceClaim(entry), sourceKey.privateKey)
  return entry
}

function makeReceipt({ id, evidence }) {
  const unsigned = {
    type: 'scopeblind.receipt.v1',
    algorithm: 'ed25519',
    kid: receiptKid,
    issuer: 'manager:meridian',
    issued_at: '2026-07-11T12:00:00Z',
    payload: {
      decision: 'deny',
      action: { kind: 'trade.submit', target: 'restricted-security' },
      receipt_id: id,
      evidence: [evidence],
    },
  }
  return { ...unsigned, signature: signHex(unsigned, RECEIPT.privateKey) }
}

const sourceAsOf = '2026-07-11T11:59:00Z'
const independent = makeEvidence({ asOf: sourceAsOf, sourceKey: CUSTODIAN, sourceKid: custodianKid })
const noAsOf = makeEvidence({ sourceKey: CUSTODIAN, sourceKid: custodianKid })
const forgedKid = makeEvidence({ asOf: sourceAsOf, sourceKey: RECEIPT, sourceKid: custodianKid })
const selfCorroboration = makeEvidence({ asOf: sourceAsOf, sourceKey: RECEIPT, sourceKid: receiptKid, authority: 'manager:meridian' })

const vectors = [
  {
    id: '01-independent-corroboration',
    receipt: makeReceipt({ id: 'evidence-01', evidence: independent }),
    expected: {
      receipt_signature_valid: true,
      source_signature_valid: true,
      source_key_out_of_band: true,
      source_key_distinct: true,
      source_control_domain_distinct: true,
      independent_corroboration: true,
      reason: 'independent_source_signature_verified',
    },
  },
  {
    id: '02-independent-without-as-of',
    receipt: makeReceipt({ id: 'evidence-02', evidence: noAsOf }),
    expected: {
      receipt_signature_valid: true,
      source_signature_valid: true,
      source_key_out_of_band: true,
      source_key_distinct: true,
      source_control_domain_distinct: true,
      independent_corroboration: true,
      reason: 'independent_source_signature_verified',
      signed_claim_omits_as_of: true,
    },
  },
  {
    id: '03-forged-trusted-kid',
    receipt: makeReceipt({ id: 'evidence-03', evidence: forgedKid }),
    expected: {
      receipt_signature_valid: true,
      source_signature_valid: false,
      source_key_out_of_band: true,
      source_key_distinct: true,
      source_control_domain_distinct: true,
      independent_corroboration: false,
      reason: 'source_signature_invalid',
    },
  },
  {
    id: '04-self-corroboration',
    receipt: makeReceipt({ id: 'evidence-04', evidence: selfCorroboration }),
    expected: {
      receipt_signature_valid: true,
      source_signature_valid: true,
      source_key_out_of_band: true,
      source_key_distinct: false,
      source_control_domain_distinct: false,
      independent_corroboration: false,
      reason: 'source_key_not_independent',
    },
  },
]

function json(value) {
  return `${JSON.stringify(value, null, 2)}\n`
}

function writeOrCheck(file, content) {
  if (CHECK) {
    if (!fs.existsSync(file) || fs.readFileSync(file, 'utf8') !== content) {
      throw new Error(`stale generated artifact: ${path.relative(ROOT, file)}`)
    }
    return
  }
  fs.mkdirSync(path.dirname(file), { recursive: true })
  fs.writeFileSync(file, content)
}

writeOrCheck(path.join(ROOT, 'trust-policy.json'), json(trustPolicy))
for (const vector of vectors) {
  const dir = path.join(ROOT, 'vectors', vector.id)
  writeOrCheck(path.join(dir, 'receipt.json'), json(vector.receipt))
  writeOrCheck(path.join(dir, 'expected.json'), json({
    ...vector.expected,
    receipt_digest: `sha256:${sha256Hex(vector.receipt)}`,
  }))
  writeOrCheck(path.join(dir, 'source-claim.json'), json(evidenceClaim(vector.receipt.payload.evidence[0])))
}

console.log(`${CHECK ? 'checked' : 'generated'} ${vectors.length} evidence predicate vectors`)
