// Minimal, dependency-free crypto helpers for the evidence predicate vectors.
//
// The fixtures use only finite integers and ASCII strings. For that restricted
// value set, sorted-key JSON serialization is byte-for-byte JCS. Production
// implementations MUST use a complete RFC 8785 implementation.

import crypto from 'node:crypto'

const PRIVATE_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex')
const PUBLIC_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex')

export function canonicalize(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`

  return `{${Object.keys(value).sort().map((key) =>
    `${JSON.stringify(key)}:${canonicalize(value[key])}`
  ).join(',')}}`
}

export function keyPairFromSeed(seedHex) {
  const seed = Buffer.from(seedHex, 'hex')
  if (seed.length !== 32) throw new Error('Ed25519 seed must be 32 bytes')

  const privateKey = crypto.createPrivateKey({
    key: Buffer.concat([PRIVATE_PKCS8_PREFIX, seed]),
    format: 'der',
    type: 'pkcs8',
  })
  const publicDer = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' })
  return { privateKey, publicKeyHex: publicDer.subarray(-32).toString('hex') }
}

export function publicKeyFromHex(publicKeyHex) {
  const raw = Buffer.from(publicKeyHex, 'hex')
  if (raw.length !== 32) throw new Error('Ed25519 public key must be 32 bytes')
  return crypto.createPublicKey({
    key: Buffer.concat([PUBLIC_SPKI_PREFIX, raw]),
    format: 'der',
    type: 'spki',
  })
}

export function signHex(value, privateKey) {
  return crypto.sign(null, Buffer.from(canonicalize(value), 'utf8'), privateKey).toString('hex')
}

export function verifyHex(value, signatureHex, publicKeyHex) {
  if (!/^[0-9a-f]{128}$/.test(signatureHex || '')) return false
  return crypto.verify(
    null,
    Buffer.from(canonicalize(value), 'utf8'),
    publicKeyFromHex(publicKeyHex),
    Buffer.from(signatureHex, 'hex'),
  )
}

export function sha256Hex(value) {
  return crypto.createHash('sha256').update(Buffer.from(canonicalize(value), 'utf8')).digest('hex')
}

export function evidenceClaim(entry) {
  const claim = {
    dimension: entry.dimension,
    ref: entry.source.ref,
    state: entry.state,
  }
  if (Object.hasOwn(entry, 'as_of')) claim.as_of = entry.as_of
  return claim
}
