/**
 * MolTrust-shaped placeholder generator for Week 3 of A2A#1742.
 *
 * Emits 3 synthetic fixtures that MolTrust replaces with their real
 * emission when they ship Week 3 on their side. Every fixture:
 *
 *   - is marked _placeholder: true and _replace_with_real_moltrust_emission: true
 *   - carries the canonical 5-field composite header natively on header_value
 *     (trust_level / attestation_count / last_verified / evidence_bundle /
 *      delegation_chain_root) so schema validation passes end-to-end
 *   - is Ed25519-signed with a deterministic test seed (documented below)
 *   - uses RFC 8785 JCS canonicalization (the same one APS uses) so both
 *     providers share canonicalization conventions
 *
 * The placeholder signing key is a TEST SEED. Seed tail `0xAA`. The public
 * half is written to every fixture's `moltrust_signing_key.pubkey` field for
 * round-trip verification. MolTrust replaces this with their production
 * kid + pubkey when they take over the shape.
 *
 * Run: npx tsx a2a-trust-header/moltrust-placeholder/generate-placeholder.ts
 */

import { readFileSync, writeFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { dirname } from 'node:path'
import {
  canonicalizeJCS,
  sign,
  publicKeyFromPrivate,
} from 'agent-passport-system'

const DIR = dirname(fileURLToPath(import.meta.url))

// Deterministic test seed: tail 0xAA, 32-byte right-aligned.
// MolTrust must replace this with their production signing key when they
// take over the shape. Private seed stays in this generator only; fixtures
// carry only the public half.
const PLACEHOLDER_SEED = '00000000000000000000000000000000000000000000000000000000000000aa'
const PLACEHOLDER_PUB  = publicKeyFromPrivate(PLACEHOLDER_SEED)
const PLACEHOLDER_KID  = 'moltrust-placeholder-v1'

// Synthetic subject agent for placeholder fixtures. Matches the APS
// happy-path subject_agent so the shared-happy-path fixture overlaps.
const SUBJECT_AGENT_PUB = publicKeyFromPrivate(
  '0000000000000000000000000000000000000000000000000000000000000004',
)
const APS_ISSUER_PUB = publicKeyFromPrivate(
  '0000000000000000000000000000000000000000000000000000000000000001',
)
const DELEGATE_1_PUB = publicKeyFromPrivate(
  '0000000000000000000000000000000000000000000000000000000000000005',
)

// Fixed timestamps for byte-reproducibility.
const T0 = '2026-04-18T12:00:00Z'
const T1 = '2026-04-18T12:05:00Z'
const T2 = '2026-04-18T12:10:00Z'
const T3 = '2026-04-18T12:15:00Z'

const sha256 = (s: string) => createHash('sha256').update(s).digest('hex')
const did = (pubHex: string) => `did:aps:${pubHex.slice(0, 32)}`
const chainRoot = (chain: unknown[]) =>
  `sha256:${sha256(canonicalizeJCS(chain))}`

interface EmissionInput {
  trust_level: number
  attestation_count: number
  last_verified: string
  evidence_bundle: string
  delegation_chain_root: string
  subject_agent: string
  extra?: Record<string, unknown>
}

// Sign a MolTrust-shaped emission. The signed payload is the composite
// header object itself (5 canonical fields + subject_agent + any extra
// vendor fields); the signature lives as a sibling field.
function signEmission(e: EmissionInput) {
  const payload = {
    trust_level: e.trust_level,
    attestation_count: e.attestation_count,
    last_verified: e.last_verified,
    evidence_bundle: e.evidence_bundle,
    delegation_chain_root: e.delegation_chain_root,
    subject_agent: e.subject_agent,
    issuer: 'moltrust',
    ...(e.extra ?? {}),
  }
  const canonical = canonicalizeJCS(payload)
  const sig = sign(canonical, PLACEHOLDER_SEED)
  return {
    ...payload,
    signature: {
      alg: 'EdDSA',
      kid: PLACEHOLDER_KID,
      pubkey: PLACEHOLDER_PUB,
      canonicalization: 'RFC8785-JCS',
      sig,
    },
  }
}

function writeFixture(name: string, fixture: unknown) {
  const path = `${DIR}/${name}.json`
  writeFileSync(path, JSON.stringify(fixture, null, 2) + '\n')
  console.log(`  wrote ${name}.json`)
}

// Standard placeholder disclaimer carried on every fixture.
const placeholderMeta = {
  _placeholder: true,
  _replace_with_real_moltrust_emission: true,
  _placeholder_notes:
    'Test-only MolTrust shape emitted by APS as a structural reference. ' +
    'Deterministic signing seed (tail 0xAA) is documented in ' +
    'moltrust-placeholder/generate-placeholder.ts. MolTrust replaces this ' +
    'with production emission + real signing key when Week 3 ships on their side.',
}

// ═════════════════════════════════════════════════════════════════════
// 1. trust-trajectory-decay.json
//    trust_level steps down 4 → 3 → 2 across three progressive emissions.
//    evidence_bundle is ipfs://... placeholder pointer.
// ═════════════════════════════════════════════════════════════════════

{
  const chain = [
    {
      delegated_by: APS_ISSUER_PUB,
      delegated_to: DELEGATE_1_PUB,
      scope: ['tool:read'],
      issued_at: T0,
      expires_at: T3,
    },
  ]
  const root = chainRoot(chain)
  const evidenceBundle =
    'ipfs://bafkreigh2akiscaildcqabsyg3dfr6chu3fgpregiymsck7e7aqa4s52zy'

  const emissions = [4, 3, 2].map((trustLevel, i) =>
    signEmission({
      trust_level: trustLevel,
      attestation_count: (i + 1) * 2,
      last_verified: [T0, T1, T2][i],
      evidence_bundle: evidenceBundle,
      delegation_chain_root: root,
      subject_agent: did(SUBJECT_AGENT_PUB),
      extra: {
        sequence: i,
        decay_reason:
          i === 0 ? null : i === 1 ? 'behavioral_drift_observed' : 'policy_violation_confirmed',
      },
    }),
  )

  // The header_value IS the latest emission (what a live consumer would see
  // on the wire), plus a trajectory[] so consumers can inspect the series.
  const latest = emissions[emissions.length - 1]
  writeFixture('trust-trajectory-decay', {
    fixture: 'trust-trajectory-decay',
    description:
      'MolTrust-shaped placeholder: trust_level decay trajectory 4 → 3 → 2 across ' +
      'three progressive emissions over the same delegation_chain_root. The header_value ' +
      'mirrors the latest (decayed) emission; the trajectory[] field lets consumers ' +
      'inspect the series. evidence_bundle is an ipfs:// placeholder pointer. ' +
      'Every emission is Ed25519-signed with the placeholder test seed. MolTrust ' +
      'replaces this with their production emission shape.',
    expected_verifier_output: 'valid',
    format_variant: false,
    spec_refs: ['a2aproject/A2A#1742'],
    header_name: 'x-agent-trust',
    moltrust_signing_key: {
      kid: PLACEHOLDER_KID,
      pubkey: PLACEHOLDER_PUB,
      seed_tail: '0xAA',
      notes: 'Deterministic test seed. Replace before production.',
    },
    ...placeholderMeta,
    header_value: {
      ...latest,
      trajectory: emissions,
    },
  })
}

// ═════════════════════════════════════════════════════════════════════
// 2. attestation-accumulation.json
//    attestation_count grows 2 → 7 → 15 across three progressive emissions.
//    trust_level holds at 3 throughout.
// ═════════════════════════════════════════════════════════════════════

{
  const chain = [
    {
      delegated_by: APS_ISSUER_PUB,
      delegated_to: SUBJECT_AGENT_PUB,
      scope: ['tool:read', 'tool:write'],
      issued_at: T0,
      expires_at: T3,
    },
  ]
  const root = chainRoot(chain)
  const evidenceBundle =
    'https://moltrust.example/bundles/' +
    sha256(canonicalizeJCS({ subject: did(SUBJECT_AGENT_PUB), root }))

  const counts = [2, 7, 15]
  const times = [T0, T1, T2]
  const emissions = counts.map((count, i) =>
    signEmission({
      trust_level: 3,
      attestation_count: count,
      last_verified: times[i],
      evidence_bundle: evidenceBundle,
      delegation_chain_root: root,
      subject_agent: did(SUBJECT_AGENT_PUB),
      extra: { sequence: i, delta_from_previous: i === 0 ? count : count - counts[i - 1] },
    }),
  )

  const latest = emissions[emissions.length - 1]
  writeFixture('attestation-accumulation', {
    fixture: 'attestation-accumulation',
    description:
      'MolTrust-shaped placeholder: attestation_count accumulation 2 → 7 → 15 across ' +
      'three progressive emissions with trust_level held at 3. Demonstrates the ' +
      'accumulation dimension of the 5-field composite header: an agent with many ' +
      'concurring attestations is meaningfully distinct from one with few, even at ' +
      'the same trust_level. evidence_bundle is an https:// URL. MolTrust replaces ' +
      'this with their production emission shape.',
    expected_verifier_output: 'valid',
    format_variant: false,
    spec_refs: ['a2aproject/A2A#1742'],
    header_name: 'x-agent-trust',
    moltrust_signing_key: {
      kid: PLACEHOLDER_KID,
      pubkey: PLACEHOLDER_PUB,
      seed_tail: '0xAA',
      notes: 'Deterministic test seed. Replace before production.',
    },
    ...placeholderMeta,
    header_value: {
      ...latest,
      trajectory: emissions,
    },
  })
}

// ═════════════════════════════════════════════════════════════════════
// 3. shared-happy-path-moltrust.json
//    Overlap-region fixture: same agent_card + delegation_chain +
//    delegation_chain_root as APS happy-path, re-signed under MolTrust
//    placeholder key with issuer='moltrust'. Demonstrates both providers
//    can emit identical content on the shared happy-path space with only
//    signing key + issuer differentiating.
// ═════════════════════════════════════════════════════════════════════

{
  // Rebuild the happy-path chain from the APS seeds so the chain root
  // matches APS happy-path.json byte-for-byte. Needs APS seeds to re-sign
  // the delegation links; we re-emit the links without signatures here
  // because the chain root is computed over the LINK CONTENT only after
  // APS's canonicalization, and APS signs each link with the principal's
  // key. For this placeholder we just import the APS happy-path chain
  // as-is from disk and reuse its root (see below).

  // Load the APS happy-path fixture to reuse its chain + root verbatim.
  // This gives us byte-identical overlap with the APS fixture.
  const apsHappyPath = JSON.parse(
    readFileSync(`${DIR}/../happy-path.json`, 'utf8'),
  ) as {
    header_value: {
      subject_agent: string
      delegation_chain: unknown[]
      delegation_chain_root: string
    }
  }

  const chain = apsHappyPath.header_value.delegation_chain
  const root = apsHappyPath.header_value.delegation_chain_root
  const subject = apsHappyPath.header_value.subject_agent

  const evidenceBundle =
    'https://moltrust.example/bundles/shared-happy-path-' + sha256(root)

  const emission = signEmission({
    trust_level: 4,
    attestation_count: 1,
    last_verified: T0,
    evidence_bundle: evidenceBundle,
    delegation_chain_root: root,
    subject_agent: subject,
    extra: {
      overlap_with: 'happy-path.json',
      overlap_note:
        'Same delegation_chain and delegation_chain_root as the APS happy-path ' +
        'fixture. Only issuer, signing key, and the 4 accumulation fields differ.',
    },
  })

  writeFixture('shared-happy-path-moltrust', {
    fixture: 'shared-happy-path-moltrust',
    description:
      'MolTrust-shaped placeholder sharing the APS happy-path delegation chain + root ' +
      'byte-for-byte, re-signed under the MolTrust placeholder key with ' +
      'issuer="moltrust". Demonstrates that both providers can emit identical ' +
      'content over the shared happy-path space with only issuer + signing key ' +
      'differentiation. MolTrust replaces this with their production emission shape.',
    expected_verifier_output: 'valid',
    format_variant: false,
    spec_refs: ['a2aproject/A2A#1742', 'a2aproject/A2A#1628'],
    header_name: 'x-agent-trust',
    moltrust_signing_key: {
      kid: PLACEHOLDER_KID,
      pubkey: PLACEHOLDER_PUB,
      seed_tail: '0xAA',
      notes: 'Deterministic test seed. Replace before production.',
    },
    ...placeholderMeta,
    header_value: {
      ...emission,
      delegation_chain: chain,
      overlap_ref: {
        source: 'happy-path.json',
        shared_fields: ['delegation_chain', 'delegation_chain_root', 'subject_agent'],
      },
    },
  })
}

console.log('\n3 MolTrust-shaped placeholder fixtures generated.')
