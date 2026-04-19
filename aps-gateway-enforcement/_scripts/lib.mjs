// Shared crypto + canonicalization for the APS gateway enforcement vectors.
//
// Two canonicalization functions live in different ecosystems:
//   - APS SDK `canonicalize()`         (sorted keys, null-stripped, ASCII keys)
//   - @veritasacta/artifacts `canonicalize()` (sorted keys, NO null-stripping, ASCII keys)
//
// All vector artifacts are constructed with NO null/undefined values so the two
// canonicalizers produce byte-identical output. That property is what makes the
// same Ed25519 signature verifiable under both APS SDK and @veritasacta/verify.

import crypto from 'node:crypto'
import fs from 'node:fs'

const HEX_PRIVATE_SEED = '0000000000000000000000000000000000000000000000000000000000000001'

const PRIVATE_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex')
const PUBLIC_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex')

function hexToBytes(hex) {
  if (!hex || hex.length % 2 !== 0) throw new Error(`bad hex length ${hex?.length}`)
  return Buffer.from(hex, 'hex')
}

function bytesToHex(buf) {
  return Buffer.from(buf).toString('hex')
}

function base64url(buf) {
  return Buffer.from(buf).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export const SEED_HEX = HEX_PRIVATE_SEED

export function loadKeyPair() {
  const privDer = Buffer.concat([PRIVATE_PKCS8_PREFIX, hexToBytes(HEX_PRIVATE_SEED)])
  const privKey = crypto.createPrivateKey({ key: privDer, format: 'der', type: 'pkcs8' })
  const pubKey = crypto.createPublicKey(privKey)
  const pubDer = pubKey.export({ type: 'spki', format: 'der' })
  const pubHex = bytesToHex(pubDer.subarray(-32))
  return { privateKey: privKey, publicKeyHex: pubHex, privateKeyHex: HEX_PRIVATE_SEED }
}

export function ed25519SignHex(messageBytes, privateKey) {
  const sig = crypto.sign(null, messageBytes, privateKey)
  return bytesToHex(sig)
}

export function ed25519VerifyHex(messageBytes, signatureHex, publicKeyHex) {
  const pubDer = Buffer.concat([PUBLIC_SPKI_PREFIX, hexToBytes(publicKeyHex)])
  const pubKey = crypto.createPublicKey({ key: pubDer, format: 'der', type: 'spki' })
  return crypto.verify(null, messageBytes, pubKey, hexToBytes(signatureHex))
}

// Canonicalize: sorted keys at every nesting level, ASCII keys only,
// no null-stripping (matches @veritasacta/artifacts SPEC.md exactly).
// Vectors must not include null/undefined so APS canonicalize() also matches.
export function canonicalize(obj) {
  return JSON.stringify(obj, (_key, value) => {
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      const sorted = {}
      for (const k of Object.keys(value).sort()) {
        if (!/^[\x20-\x7E]*$/.test(k)) {
          throw new Error(`Non-ASCII key "${k}" in artifact payload.`)
        }
        sorted[k] = value[k]
      }
      return sorted
    }
    return value
  })
}

// JWK thumbprint (RFC 7638) for an Ed25519 public key — matches what
// @veritasacta/artifacts uses for `kid`.
export function jwkThumbprint(publicKeyHex) {
  const x = base64url(hexToBytes(publicKeyHex))
  const jwk = `{"crv":"Ed25519","kty":"OKP","x":"${x}"}`
  return base64url(crypto.createHash('sha256').update(jwk).digest())
}

export function jwksFor(publicKeyHex, kid) {
  return {
    keys: [
      {
        kty: 'OKP',
        crv: 'Ed25519',
        kid,
        x: base64url(hexToBytes(publicKeyHex)),
        use: 'sig',
        alg: 'EdDSA'
      }
    ]
  }
}

export function sha256Hex(input) {
  const buf = typeof input === 'string' ? Buffer.from(input, 'utf8') : Buffer.from(input)
  return crypto.createHash('sha256').update(buf).digest('hex')
}

// Build a v2 envelope receipt and sign it. Returns the artifact with
// `signature` appended. Verifies under @veritasacta/verify (v2 shape) and
// APS SDK (canonicalize() returns identical bytes when no nulls).
export function makeV2Receipt({ type, issuer, issued_at, payload, key }) {
  const kid = jwkThumbprint(key.publicKeyHex)
  const envelope = {
    v: 2,
    type,
    algorithm: 'ed25519',
    kid,
    issuer,
    issued_at,
    payload
  }
  const message = Buffer.from(canonicalize(envelope), 'utf8')
  const signature = ed25519SignHex(message, key.privateKey)
  return { ...envelope, signature }
}

export function verifyV2Receipt(receipt, publicKeyHex) {
  const { signature, ...rest } = receipt
  const message = Buffer.from(canonicalize(rest), 'utf8')
  return ed25519VerifyHex(message, signature, publicKeyHex)
}

// DSSE Pre-Authentication Encoding (PAE) per the in-toto / DSSE spec:
//   PAE(type, payload) = "DSSEv1" SP LEN(type) SP type SP LEN(payload) SP payload
// where LEN is the ASCII-decimal byte length.
export function dssePAE(payloadType, payloadBytes) {
  const typeBytes = Buffer.from(payloadType, 'utf8')
  const header = Buffer.from(
    `DSSEv1 ${typeBytes.length} ${payloadType} ${payloadBytes.length} `,
    'utf8'
  )
  return Buffer.concat([header, payloadBytes])
}

// Build a DSSE envelope around an in-toto Statement.
export function makeDSSEEnvelope({ payloadType, statement, key }) {
  const payloadBytes = Buffer.from(JSON.stringify(statement, null, 2), 'utf8')
  const pae = dssePAE(payloadType, payloadBytes)
  const sig = ed25519SignHex(pae, key.privateKey)
  return {
    payloadType,
    payload: payloadBytes.toString('base64'),
    signatures: [
      {
        keyid: jwkThumbprint(key.publicKeyHex),
        sig: Buffer.from(sig, 'hex').toString('base64')
      }
    ]
  }
}

export function verifyDSSEEnvelope(envelope, publicKeyHex) {
  const payloadBytes = Buffer.from(envelope.payload, 'base64')
  const pae = dssePAE(envelope.payloadType, payloadBytes)
  for (const sig of envelope.signatures) {
    const sigHex = Buffer.from(sig.sig, 'base64').toString('hex')
    if (ed25519VerifyHex(pae, sigHex, publicKeyHex)) return true
  }
  return false
}

export function writeJSON(path, obj) {
  // Pretty-printed for human review; canonical bytes are recomputed at sign/verify.
  fs.writeFileSync(path, JSON.stringify(obj, null, 2) + '\n')
}
