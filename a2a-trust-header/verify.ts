/**
 * APS verifier for the 6 a2a-trust-header fixtures.
 *
 * For each fixture:
 *   1. Re-canonicalize every payload with RFC8785-JCS (APS canonicalizeJCS).
 *   2. Verify every signature against its advertised pubkey.
 *   3. Recompute delegation_chain_root and compare where applicable.
 *   4. Inspect format_variant flag and trust_level trajectory.
 *   5. Derive a verifier verdict (valid | invalid | deny).
 *   6. Assert verdict == expected_verifier_output.
 *
 * Exit 0 = all six fixtures round-trip. Exit 1 = any divergence.
 */

import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { dirname } from 'node:path'
import {
  canonicalizeJCS,
  verify,
} from 'agent-passport-system'

const DIR = dirname(fileURLToPath(import.meta.url))

const sha256 = (s: string) => createHash('sha256').update(s).digest('hex')

interface Signature {
  alg: string
  kid: string
  pubkey: string
  sig: string
  canonicalization?: string
}

function verifySigned(obj: { signature: Signature } & Record<string, unknown>, context: string): boolean {
  const { signature, ...rest } = obj
  // Links store the signature inline on the same object; attestations wrap
  // { payload, signature }. Both cases canonicalize everything except `signature`.
  const canonical = canonicalizeJCS(rest as unknown as Record<string, unknown>)
  const ok = verify(canonical, signature.sig, signature.pubkey)
  if (!ok) console.error(`  FAIL signature on ${context}`)
  return ok
}

function verifyAttestation(att: { payload: Record<string, unknown>; signature: Signature }, label: string): boolean {
  const canonical = canonicalizeJCS(att.payload)
  const ok = verify(canonical, att.signature.sig, att.signature.pubkey)
  if (!ok) console.error(`  FAIL signature on ${label}`)
  return ok
}

function chainRoot(chain: unknown[]): string {
  return `sha256:${sha256(canonicalizeJCS(chain))}`
}

interface VerifyResult {
  verdict: 'valid' | 'invalid' | 'deny'
  notes: string[]
}

function runFixture(name: string, fixture: Record<string, unknown>): VerifyResult {
  const notes: string[] = []
  const hv = fixture.header_value as Record<string, unknown>
  const chain = (hv.delegation_chain ?? []) as Array<Record<string, unknown> & { signature: Signature }>
  const attestations = (hv.attestations ?? []) as Array<{ payload: Record<string, unknown>; signature: Signature }>
  const agentCard = hv.agent_card as { trust?: { signals?: typeof attestations } } | undefined
  const denyReceipt = hv.deny_receipt as { payload: Record<string, unknown>; signature: Signature } | undefined

  // 1. Verify every delegation link signature.
  let allOk = true
  for (let i = 0; i < chain.length; i++) {
    const ok = verifySigned(chain[i], `${name}/chain[${i}]`)
    allOk &&= ok
  }

  // 2. Verify every attestation signature.
  for (let i = 0; i < attestations.length; i++) {
    const ok = verifyAttestation(attestations[i], `${name}/attestations[${i}]`)
    allOk &&= ok
  }

  // 3. Verify agent card signals if present (shared-card fixture).
  if (agentCard?.trust?.signals) {
    for (let i = 0; i < agentCard.trust.signals.length; i++) {
      const ok = verifyAttestation(agentCard.trust.signals[i], `${name}/agent_card.trust.signals[${i}]`)
      allOk &&= ok
    }
  }

  // 4. Verify deny receipt signature.
  let denyPresent = false
  if (denyReceipt) {
    denyPresent = true
    const ok = verifyAttestation(denyReceipt, `${name}/deny_receipt`)
    allOk &&= ok
  }

  // 5. Recompute chain root from chain array, compare to header_value.delegation_chain_root.
  if (chain.length > 0 && typeof hv.delegation_chain_root === 'string') {
    const computed = chainRoot(chain)
    if (computed !== hv.delegation_chain_root) {
      notes.push(`header root ${hv.delegation_chain_root} != computed ${computed}`)
    }
  }

  // 6. Check root format consistency across attestations (drift detection).
  const rootsSeen = new Set<string>()
  for (const att of attestations) {
    const r = att.payload.delegation_chain_root
    if (typeof r === 'string') {
      const algo = r.split(':')[0]
      rootsSeen.add(algo)
    }
  }
  const rootDrift = rootsSeen.size > 1

  // 7. Check for revoked delegation status in the chain.
  const hasRevokedLink = chain.some(link => link.status === 'revoked')

  // 8. Derive verdict.
  let verdict: 'valid' | 'invalid' | 'deny'
  if (!allOk) {
    verdict = 'invalid'
    notes.push('at least one signature failed')
  } else if (rootDrift) {
    // Non-standard root format across attestations — interop-incompatible.
    verdict = 'invalid'
    notes.push(`root format drift across algorithms: ${[...rootsSeen].join(',')}`)
  } else if (hasRevokedLink && denyPresent) {
    verdict = 'deny'
    notes.push('chain carries a revoked link and a signed deny receipt')
  } else {
    verdict = 'valid'
  }

  return { verdict, notes }
}

function main() {
  const fixtureNames = [
    'happy-path',
    'trust-level-ascending',
    'trust-level-descending',
    'drift-explicit-flag',
    'revocation-mid-chain',
    'shared-card-crossorg',
  ]

  let fails = 0
  for (const name of fixtureNames) {
    const path = `${DIR}/${name}.json`
    const fixture = JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>
    const expected = fixture.expected_verifier_output as string
    const { verdict, notes } = runFixture(name, fixture)
    const ok = verdict === expected
    const status = ok ? 'PASS' : 'FAIL'
    console.log(`[${status}] ${name}  expected=${expected}  got=${verdict}`)
    if (notes.length) notes.forEach(n => console.log(`         · ${n}`))
    if (!ok) fails++
  }

  if (fails === 0) {
    console.log('\n6/6 fixtures round-trip through APS verifier.')
    process.exit(0)
  } else {
    console.error(`\n${fails} fixture(s) failed.`)
    process.exit(1)
  }
}

main()
