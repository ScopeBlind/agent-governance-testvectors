#!/usr/bin/env node
// Verify a v2 envelope receipt using the APS SDK's own canonicalize() and
// verify() primitives. This is the strict requirement: every signed.json in
// this directory must verify cleanly under the SDK that produced the format.
//
// Usage:
//   node aps-gateway-enforcement/_scripts/verify-with-aps-sdk.mjs <receipt.json>

import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

const SDK_PATH = process.env.APS_SDK_PATH || '/Users/tima/agent-passport-system/dist/src/index.js'

let canonicalize, verify
try {
  const sdk = await import(SDK_PATH)
  canonicalize = sdk.canonicalize
  verify = sdk.verify
} catch (err) {
  console.error('Could not load APS SDK from', SDK_PATH)
  console.error('Set APS_SDK_PATH env var or `npm install agent-passport-system` first.')
  console.error(err.message)
  process.exit(2)
}

const target = process.argv[2]
if (!target) {
  console.error('Usage: verify-with-aps-sdk.mjs <receipt.json>')
  process.exit(2)
}

const receipt = JSON.parse(readFileSync(resolve(target), 'utf8'))
const { signature, ...payload } = receipt

if (!signature) {
  console.error('No signature field on artifact')
  process.exit(2)
}

const message = canonicalize(payload)
const publicKeyHex = process.env.APS_PUBLIC_KEY
  || '4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29'

const ok = verify(message, signature, publicKeyHex)

if (ok) {
  console.log(JSON.stringify({
    valid: true,
    verifier: 'aps-sdk',
    canonical_form: 'aps canonicalize() (sorted-keys, null-stripping)',
    publicKey: publicKeyHex,
    artifact: target
  }, null, 2))
  process.exit(0)
} else {
  console.log(JSON.stringify({
    valid: false,
    verifier: 'aps-sdk',
    artifact: target
  }, null, 2))
  process.exit(1)
}
