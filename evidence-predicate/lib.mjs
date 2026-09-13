// Dependency-free helpers for the evidence predicate vectors
// (draft-farley-acta-signed-receipts-03, Section 4).
//
// The fixtures use only strings, booleans, finite integers, arrays and
// objects with ASCII member names. For that value set, sorted-key JSON with no
// whitespace is byte-for-byte JCS (RFC 8785). Production implementations MUST
// use a complete RFC 8785 implementation.

import crypto from 'node:crypto'

const PRIVATE_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex')
const PUBLIC_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex')

// Section 4.1: the closed core vocabularies, and the extension form.
export const CORE_DIMENSIONS = ['data_rights', 'provenance', 'compliance', 'freshness', 'consent', 'identity', 'authorization', 'integrity']
export const EXTENSION_DIMENSION = /^x-[a-z0-9]+:[a-z0-9_.-]+$/
export const STATES = ['satisfied', 'unverified', 'stale', 'failed', 'not_applicable']

export function canonicalize(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`
}

export function keyPairFromSeed(seedHex) {
  const seed = Buffer.from(seedHex, 'hex')
  if (seed.length !== 32) throw new Error('Ed25519 seed must be 32 bytes')
  const privateKey = crypto.createPrivateKey({ key: Buffer.concat([PRIVATE_PKCS8_PREFIX, seed]), format: 'der', type: 'pkcs8' })
  const publicDer = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' })
  return { privateKey, publicKeyHex: publicDer.subarray(-32).toString('hex') }
}

export function publicKeyFromHex(publicKeyHex) {
  const raw = Buffer.from(publicKeyHex, 'hex')
  if (raw.length !== 32) throw new Error('Ed25519 public key must be 32 bytes')
  return crypto.createPublicKey({ key: Buffer.concat([PUBLIC_SPKI_PREFIX, raw]), format: 'der', type: 'spki' })
}

export function signHex(value, privateKey) {
  return crypto.sign(null, Buffer.from(canonicalize(value), 'utf8'), privateKey).toString('hex')
}

export function verifyHex(value, signatureHex, publicKeyHex) {
  if (!/^[0-9a-f]{128}$/.test(signatureHex || '')) return false
  return crypto.verify(null, Buffer.from(canonicalize(value), 'utf8'), publicKeyFromHex(publicKeyHex), Buffer.from(signatureHex, 'hex'))
}

export function sha256Hex(value) {
  return crypto.createHash('sha256').update(Buffer.from(canonicalize(value), 'utf8')).digest('hex')
}

// Section 4.1: the signed claim is { dimension, ref, state } plus as_of when
// the entry carries one. An absent as_of is omitted, never null.
export function evidenceClaim(entry) {
  const claim = { dimension: entry.dimension, ref: entry.source.ref, state: entry.state }
  if (Object.hasOwn(entry, 'as_of')) claim.as_of = entry.as_of
  return claim
}

// A decision_receipt (the shape @veritasacta/verify checks): the signature is
// over the JCS bytes of the receipt with the signature member removed.
export function signReceipt(unsigned, privateKey) {
  return { ...unsigned, signature: signHex(unsigned, privateKey) }
}

export function verifyReceipt(receipt, publicKeyHex) {
  const { signature, ...unsigned } = receipt
  return verifyHex(unsigned, signature, publicKeyHex)
}

// Structural validation of one evidence entry against Section 4.1. Returns
// null when the entry is well formed, otherwise the reason it is not.
export function validateEvidenceEntry(entry) {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return 'entry must be an object'
  const allowed = new Set(['dimension', 'state', 'source', 'as_of'])
  for (const key of Object.keys(entry)) if (!allowed.has(key)) return `unknown field ${key}`
  if (typeof entry.dimension !== 'string') return 'dimension must be a string'
  if (!CORE_DIMENSIONS.includes(entry.dimension) && !EXTENSION_DIMENSION.test(entry.dimension)) {
    return `invalid dimension ${JSON.stringify(entry.dimension)}: a core value or x-<vendor>:<name>`
  }
  if (!STATES.includes(entry.state)) return `invalid state ${JSON.stringify(entry.state)}`
  if (Object.hasOwn(entry, 'as_of') && (typeof entry.as_of !== 'string' || Number.isNaN(Date.parse(entry.as_of)))) {
    return 'as_of must be omitted or an RFC 3339 string'
  }
  const source = entry.source
  if (!source || typeof source !== 'object' || Array.isArray(source)) return 'source must be an object'
  const sourceAllowed = new Set(['authority', 'ref', 'kid', 'alg', 'sig'])
  for (const key of Object.keys(source)) if (!sourceAllowed.has(key)) return `unknown source field ${key}`
  if (typeof source.authority !== 'string' || source.authority.length === 0) return 'source.authority must be a non-empty string'
  if (typeof source.ref !== 'string' || source.ref.length === 0) return 'source.ref must be a non-empty string'
  if (source.kid !== undefined && (typeof source.kid !== 'string' || source.kid.length === 0)) return 'source.kid must be a non-empty string'
  if (source.alg !== undefined && source.alg !== 'EdDSA') return `unsupported source.alg ${JSON.stringify(source.alg)} for these vectors`
  if (source.sig !== undefined && !/^[0-9a-f]+$/.test(source.sig)) return 'source.sig must be lowercase hexadecimal'
  if (source.sig !== undefined && source.kid === undefined) return 'source.sig without source.kid cannot be verified under a pinned key'
  return null
}
