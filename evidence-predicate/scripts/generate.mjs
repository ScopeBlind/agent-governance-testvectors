#!/usr/bin/env node
// Deterministically generate the evidence predicate vectors
// (draft-farley-acta-signed-receipts-03, Sections 4, 4.3 and 9.9).

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { evidenceClaim, keyPairFromSeed, sha256Hex, signHex, signReceipt } from '../lib.mjs'

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)))
const CHECK = process.argv.includes('--check')

// Deterministic test keys. Public, and MUST NOT be reused.
const RECEIPT = keyPairFromSeed('0000000000000000000000000000000000000000000000000000000000000001')
const CUSTODIAN = keyPairFromSeed('0000000000000000000000000000000000000000000000000000000000000002')
const ADMINISTRATOR = keyPairFromSeed('0000000000000000000000000000000000000000000000000000000000000003')

const receiptKid = 'test:manager:meridian:ed25519'
const custodianKid = 'test:custodian:demo:ed25519'
const administratorKid = 'test:administrator:demo:ed25519'
const relabelledKid = 'test:administrator:relabel:ed25519'

// The relying party's out-of-band trust policy. It is deliberately outside
// every receipt: Section 4.3 condition 2 (the key comes from here, never from
// the receipt) and condition 3 (the control domain is the relying party's own
// determination). The last entry is a trap: the receipt signer's key bytes
// pinned under a fresh name and a different domain label, as a relying party
// might be talked into doing. Section 4.3 says the key bytes decide.
const trustPolicy = {
  type: 'scopeblind.evidence_trust_policy.v1',
  receipt_signers: {
    [receiptKid]: { public_key_hex: RECEIPT.publicKeyHex, control_domain: 'manager:meridian' },
  },
  source_keys: {
    [custodianKid]: { public_key_hex: CUSTODIAN.publicKeyHex, control_domain: 'custodian:demo' },
    [administratorKid]: { public_key_hex: ADMINISTRATOR.publicKeyHex, control_domain: 'administrator:demo' },
    [receiptKid]: { public_key_hex: RECEIPT.publicKeyHex, control_domain: 'manager:meridian' },
    [relabelledKid]: { public_key_hex: RECEIPT.publicKeyHex, control_domain: 'administrator:relabel' },
  },
}

const SUBJECT = 'sha256:6e0a9aa1f9d5c8ce3d545fb7b1d452f84514e93f493f94f24fa7c8180cb49ac4'

function attested({ dimension, state, asOf, signer, kid, authority, alg }) {
  const entry = {
    dimension,
    state,
    source: { authority, ref: SUBJECT, kid, ...(alg ? { alg } : {}) },
    ...(asOf ? { as_of: asOf } : {}),
  }
  entry.source.sig = signHex(evidenceClaim(entry), signer.privateKey)
  return entry
}

// Section 4.3, last paragraph: a self-attested basis, marked runtime:<component>,
// carries no signature. The label is advisory; the absence of a verifiable
// independent sig is what a relying party goes by.
function runtimeSelfAttested({ dimension, state }) {
  return { dimension, state, source: { authority: 'runtime:request-origin', ref: 'request/origin-header' } }
}

function receipt({ id, decision, evidence }) {
  const unsigned = {
    v: 2,
    type: 'decision_receipt',
    algorithm: 'ed25519',
    kid: receiptKid,
    issuer: 'manager:meridian',
    issued_at: '2026-09-13T12:00:00Z',
    payload: {
      decision,
      request_id: id,
      agent_id: 'agent:trading-desk:1',
      tool: 'trade.submit',
      params_hash: 'sha256:2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881',
      policy_id: 'restricted-securities',
      policy_digest: 'sha256:5dbdea0fbf9f2c0c47a7b9a0f7d3b4a0f5b8e2b0b6b32f4b7f5f2ab3c3f0d6e1',
      evidence,
    },
  }
  return signReceipt(unsigned, RECEIPT.privateKey)
}

const AS_OF = '2026-09-13T11:59:00Z'
const independent = (r) => ({ ...r, source_signature_present: true, source_signature_valid: true, source_key_out_of_band: true, source_key_distinct: true, source_control_domain_distinct: true, independent_corroboration: true, reason: 'independent_source_signature_verified' })

const vectors = [
  {
    id: '01-independent-corroboration',
    about: 'An allow whose data_rights basis is attested by the custodian, a key the relying party pinned out of band, distinct from the receipt signer.',
    receipt: receipt({ id: 'ev-01', decision: 'allow', evidence: [attested({ dimension: 'data_rights', state: 'satisfied', asOf: AS_OF, signer: CUSTODIAN, kid: custodianKid, authority: 'custodian:demo', alg: 'EdDSA' })] }),
    expected: { entries: [independent({ dimension: 'data_rights' })], independent_dimensions: ['data_rights'] },
  },
  {
    id: '02-deny-on-failed-freshness',
    about: 'A deny whose basis is a failed freshness check attested by an independent administrator; the entry carries no as_of, so the signed claim omits it.',
    receipt: receipt({ id: 'ev-02', decision: 'deny', evidence: [attested({ dimension: 'freshness', state: 'failed', signer: ADMINISTRATOR, kid: administratorKid, authority: 'administrator:demo' })] }),
    expected: { entries: [independent({ dimension: 'freshness' })], independent_dimensions: ['freshness'], signed_claim_omits_as_of: [true] },
  },
  {
    id: '03-forged-trusted-kid',
    about: 'The custodian\'s kid is named, but the receipt signer made the signature. The named key does not verify it. Section 9.9: a named-key forgery.',
    receipt: receipt({ id: 'ev-03', decision: 'allow', evidence: [attested({ dimension: 'data_rights', state: 'satisfied', asOf: AS_OF, signer: RECEIPT, kid: custodianKid, authority: 'custodian:demo' })] }),
    expected: { entries: [{ dimension: 'data_rights', source_signature_present: true, source_signature_valid: false, source_key_out_of_band: true, source_key_distinct: true, source_control_domain_distinct: true, independent_corroboration: false, reason: 'source_signature_invalid' }], independent_dimensions: [] },
  },
  {
    id: '04-self-corroboration',
    about: 'The receipt signer signs the claim with its own pinned key. Everything verifies, and it is still the signer\'s own word. Section 9.9: self-corroboration.',
    receipt: receipt({ id: 'ev-04', decision: 'allow', evidence: [attested({ dimension: 'data_rights', state: 'satisfied', asOf: AS_OF, signer: RECEIPT, kid: receiptKid, authority: 'manager:meridian' })] }),
    expected: { entries: [{ dimension: 'data_rights', source_signature_present: true, source_signature_valid: true, source_key_out_of_band: true, source_key_distinct: false, source_control_domain_distinct: false, independent_corroboration: false, reason: 'source_key_not_independent' }], independent_dimensions: [] },
  },
  {
    id: '05-relabelled-signer-key',
    about: 'The signer\'s key bytes, pinned by the relying party under a fresh kid and a different domain label. The label says independent; the bytes say otherwise. Section 4.3: the source key MUST NOT equal the receipt signer\'s key.',
    receipt: receipt({ id: 'ev-05', decision: 'allow', evidence: [attested({ dimension: 'data_rights', state: 'satisfied', asOf: AS_OF, signer: RECEIPT, kid: relabelledKid, authority: 'administrator:relabel' })] }),
    expected: { entries: [{ dimension: 'data_rights', source_signature_present: true, source_signature_valid: true, source_key_out_of_band: true, source_key_distinct: false, source_control_domain_distinct: true, independent_corroboration: false, reason: 'source_key_not_independent' }], independent_dimensions: [] },
  },
  {
    id: '06-extension-dimension',
    about: 'A vendor dimension in the x-<vendor>:<name> form, independently attested. Unknown dimensions stay ignorable; known ones are checked like any other.',
    receipt: receipt({ id: 'ev-06', decision: 'allow', evidence: [attested({ dimension: 'x-usetruth:contradiction', state: 'satisfied', asOf: AS_OF, signer: CUSTODIAN, kid: custodianKid, authority: 'custodian:demo' })] }),
    expected: { entries: [independent({ dimension: 'x-usetruth:contradiction' })], independent_dimensions: ['x-usetruth:contradiction'] },
  },
  {
    id: '07-runtime-self-attested',
    about: 'A basis the runtime asserts about itself: no kid, no sig, authority runtime:<component>. It is the signer\'s claim and raises no assurance.',
    receipt: receipt({ id: 'ev-07', decision: 'deny', evidence: [runtimeSelfAttested({ dimension: 'provenance', state: 'unverified' })] }),
    expected: { entries: [{ dimension: 'provenance', source_signature_present: false, source_signature_valid: false, source_key_out_of_band: false, source_key_distinct: false, source_control_domain_distinct: false, independent_corroboration: false, reason: 'source_signature_absent' }], independent_dimensions: [] },
  },
  {
    id: '08-mixed-entries',
    about: 'Two entries on one receipt: an independently attested data_rights and a runtime-asserted provenance. Section 9.9: the two MUST be visibly distinguished.',
    receipt: receipt({ id: 'ev-08', decision: 'allow', evidence: [attested({ dimension: 'data_rights', state: 'satisfied', asOf: AS_OF, signer: CUSTODIAN, kid: custodianKid, authority: 'custodian:demo' }), runtimeSelfAttested({ dimension: 'provenance', state: 'unverified' })] }),
    expected: { entries: [independent({ dimension: 'data_rights' }), { dimension: 'provenance', source_signature_present: false, source_signature_valid: false, source_key_out_of_band: false, source_key_distinct: false, source_control_domain_distinct: false, independent_corroboration: false, reason: 'source_signature_absent' }], independent_dimensions: ['data_rights'] },
  },
]

// Structurally invalid entries, each rejected for the reason named.
const invalid = {
  'null-as-of-entry': { entry: { dimension: 'provenance', state: 'satisfied', as_of: null, source: { authority: 'custodian:demo', ref: SUBJECT, kid: custodianKid, sig: '00' } }, reason: 'as_of must be omitted or an RFC 3339 string' },
  'old-state-vocabulary': { entry: { dimension: 'provenance', state: 'verified', source: { authority: 'custodian:demo', ref: SUBJECT } }, reason: 'invalid state "verified"' },
  'extension-hyphen-form': { entry: { dimension: 'x-usetruth-contradiction', state: 'satisfied', source: { authority: 'custodian:demo', ref: SUBJECT } }, reason: 'invalid dimension "x-usetruth-contradiction": a core value or x-<vendor>:<name>' },
  'unnamespaced-dimension': { entry: { dimension: 'contradiction', state: 'satisfied', source: { authority: 'custodian:demo', ref: SUBJECT } }, reason: 'invalid dimension "contradiction": a core value or x-<vendor>:<name>' },
  'inline-key-in-source': { entry: { dimension: 'provenance', state: 'satisfied', source: { authority: 'custodian:demo', ref: SUBJECT, kid: custodianKid, key: { kty: 'OKP', crv: 'Ed25519', x: 'dCK5iHWYBo4yxESKlJrbKQ0PTjW54BsO5fGh5gD-JnQ' } } }, reason: 'unknown source field key' },
  'sig-without-kid': { entry: { dimension: 'provenance', state: 'satisfied', source: { authority: 'custodian:demo', ref: SUBJECT, sig: '00' } }, reason: 'source.sig without source.kid cannot be verified under a pinned key' },
}

const json = (value) => `${JSON.stringify(value, null, 2)}\n`
function writeOrCheck(file, content) {
  if (CHECK) {
    if (!fs.existsSync(file) || fs.readFileSync(file, 'utf8') !== content) throw new Error(`stale generated artifact: ${path.relative(ROOT, file)}`)
    return
  }
  fs.mkdirSync(path.dirname(file), { recursive: true })
  fs.writeFileSync(file, content)
}

writeOrCheck(path.join(ROOT, 'trust-policy.json'), json(trustPolicy))
for (const vector of vectors) {
  const dir = path.join(ROOT, 'vectors', vector.id)
  writeOrCheck(path.join(dir, 'receipt.json'), json(vector.receipt))
  writeOrCheck(path.join(dir, 'expected.json'), json({ about: vector.about, receipt_signature_valid: true, ...vector.expected, receipt_digest: `sha256:${sha256Hex(vector.receipt)}` }))
  writeOrCheck(path.join(dir, 'source-claims.json'), json(vector.receipt.payload.evidence.map((entry) => (entry.source.sig ? evidenceClaim(entry) : null))))
}
for (const [name, { entry, reason }] of Object.entries(invalid)) {
  writeOrCheck(path.join(ROOT, 'invalid', `${name}.json`), json({ reason, entry }))
}
console.log(`${CHECK ? 'checked' : 'generated'} ${vectors.length} evidence predicate vectors and ${Object.keys(invalid).length} invalid entries`)
