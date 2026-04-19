/**
 * APS Week 2 fixture generator for a2aproject/A2A#1742 x-agent-trust header.
 *
 * Produces 6 Ed25519-signed, JCS-canonical fixtures covering:
 *   happy-path, trust-level ascending/descending, drift, revocation, shared-card.
 *
 * Run: npx tsx a2a-trust-header/generate.ts
 *
 * All signatures use deterministic seeds so the fixtures are byte-reproducible
 * across machines. Seeds used:
 *   APS issuer   : 0x00...01  (matches fixtures/keys/ test seed)
 *   orgA issuer  : 0x00...02
 *   orgB issuer  : 0x00...03
 *   subject agent: 0x00...04
 *   delegate #1  : 0x00...05
 *   delegate #2  : 0x00...06
 */

import { writeFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import {
  publicKeyFromPrivate,
  sign,
  canonicalizeJCS,
} from '/Users/tima/agent-passport-system/src/index.js'

// ── Deterministic seeds ────────────────────────────────────────────────
const seed = (tail: string) =>
  '0'.repeat(64 - tail.length) + tail

const APS_ISSUER_SEED   = seed('01')
const ORG_A_SEED        = seed('02')
const ORG_B_SEED        = seed('03')
const SUBJECT_AGENT_SEED = seed('04')
const DELEGATE_1_SEED   = seed('05')
const DELEGATE_2_SEED   = seed('06')

const APS_ISSUER_PUB    = publicKeyFromPrivate(APS_ISSUER_SEED)
const ORG_A_PUB         = publicKeyFromPrivate(ORG_A_SEED)
const ORG_B_PUB         = publicKeyFromPrivate(ORG_B_SEED)
const SUBJECT_AGENT_PUB = publicKeyFromPrivate(SUBJECT_AGENT_SEED)
const DELEGATE_1_PUB    = publicKeyFromPrivate(DELEGATE_1_SEED)
const DELEGATE_2_PUB    = publicKeyFromPrivate(DELEGATE_2_SEED)

// ── Fixed timestamps for reproducibility ───────────────────────────────
const T0 = '2026-04-18T12:00:00Z'
const T1 = '2026-04-18T12:05:00Z'
const T2 = '2026-04-18T12:10:00Z'
const T3 = '2026-04-18T12:15:00Z'

const sha256 = (s: string) => createHash('sha256').update(s).digest('hex')

function did(pubHex: string): string {
  return `did:aps:${pubHex.slice(0, 32)}`
}

// Compute chain root = sha256 over JCS(chain array)
function chainRoot(chain: unknown[]): string {
  return `sha256:${sha256(canonicalizeJCS(chain))}`
}

interface AttestationInput {
  trust_level: 'unknown' | 'developing' | 'trusted' | 'flagged' | 'revoked'
  issued_at: string
  delegation_chain_root: string
  issuer_seed: string
  issuer_pub: string
  subject_agent: string
  extra?: Record<string, unknown>
}

function signAttestation(a: AttestationInput) {
  const payload: Record<string, unknown> = {
    agent_id: a.subject_agent,
    trust_level: a.trust_level,
    delegation_chain_root: a.delegation_chain_root,
    issued_at: a.issued_at,
    issuer: did(a.issuer_pub),
    ...(a.extra ?? {}),
  }
  const canonical = canonicalizeJCS(payload)
  const sig = sign(canonical, a.issuer_seed)
  return {
    payload,
    signature: {
      alg: 'EdDSA',
      kid: did(a.issuer_pub),
      pubkey: a.issuer_pub,
      canonicalization: 'RFC8785-JCS',
      sig,
    },
  }
}

// A delegation link: principal → delegate, scope, signed by principal.
function signDelegationLink(opts: {
  by_seed: string
  by_pub: string
  to_pub: string
  scope: string[]
  issued_at: string
  expires_at: string
  spend_limit?: number
  status?: 'active' | 'revoked'
  revoked_at?: string
}) {
  const payload: Record<string, unknown> = {
    delegated_by: opts.by_pub,
    delegated_to: opts.to_pub,
    scope: opts.scope,
    issued_at: opts.issued_at,
    expires_at: opts.expires_at,
    ...(opts.spend_limit !== undefined ? { spend_limit: opts.spend_limit } : {}),
    ...(opts.status ? { status: opts.status } : {}),
    ...(opts.revoked_at ? { revoked_at: opts.revoked_at } : {}),
  }
  const canonical = canonicalizeJCS(payload)
  const sig = sign(canonical, opts.by_seed)
  return {
    ...payload,
    signature: {
      alg: 'EdDSA',
      kid: did(opts.by_pub),
      pubkey: opts.by_pub,
      sig,
    },
  }
}

function writeFixture(name: string, fixture: unknown) {
  const path = `/Users/tima/agent-governance-testvectors/a2a-trust-header/${name}.json`
  writeFileSync(path, JSON.stringify(fixture, null, 2) + '\n')
  console.log(`  wrote ${name}.json`)
}

// ═════════════════════════════════════════════════════════════════════
// 1. happy-path.json
// ═════════════════════════════════════════════════════════════════════

{
  const chain = [
    signDelegationLink({
      by_seed: APS_ISSUER_SEED,
      by_pub: APS_ISSUER_PUB,
      to_pub: DELEGATE_1_PUB,
      scope: ['tool:read', 'tool:write'],
      issued_at: T0,
      expires_at: T3,
    }),
    signDelegationLink({
      by_seed: DELEGATE_1_SEED,
      by_pub: DELEGATE_1_PUB,
      to_pub: SUBJECT_AGENT_PUB,
      scope: ['tool:read'],
      issued_at: T0,
      expires_at: T3,
    }),
  ]
  const root = chainRoot(chain)
  const attestation = signAttestation({
    trust_level: 'trusted',
    issued_at: T0,
    delegation_chain_root: root,
    issuer_seed: APS_ISSUER_SEED,
    issuer_pub: APS_ISSUER_PUB,
    subject_agent: did(SUBJECT_AGENT_PUB),
    extra: {
      evidence_tier: 'infrastructure',
      monotonic_narrowing: true,
    },
  })
  writeFixture('happy-path', {
    fixture: 'happy-path',
    description:
      'Full two-step delegation chain with monotonic scope narrowing, signed by APS issuer. ' +
      'trust_level=trusted, delegation_chain_root in canonical sha256:<hex> form. ' +
      'Reference case for the x-agent-trust header baseline.',
    expected_verifier_output: 'valid',
    format_variant: false,
    spec_refs: ['a2aproject/A2A#1742', 'a2aproject/A2A#1628'],
    header_name: 'x-agent-trust',
    header_value: {
      trust_header_version: '0.1',
      subject_agent: did(SUBJECT_AGENT_PUB),
      delegation_chain: chain,
      delegation_chain_root: root,
      attestations: [attestation],
    },
  })
}

// ═════════════════════════════════════════════════════════════════════
// 2. trust-level-ascending.json — unknown → developing → trusted
// ═════════════════════════════════════════════════════════════════════

{
  const chain = [
    signDelegationLink({
      by_seed: APS_ISSUER_SEED,
      by_pub: APS_ISSUER_PUB,
      to_pub: SUBJECT_AGENT_PUB,
      scope: ['tool:read'],
      issued_at: T0,
      expires_at: T3,
    }),
  ]
  const root = chainRoot(chain)
  const levels: Array<'unknown' | 'developing' | 'trusted'> = [
    'unknown',
    'developing',
    'trusted',
  ]
  const times = [T0, T1, T2]
  const attestations = levels.map((lvl, i) =>
    signAttestation({
      trust_level: lvl,
      issued_at: times[i],
      delegation_chain_root: root,
      issuer_seed: APS_ISSUER_SEED,
      issuer_pub: APS_ISSUER_PUB,
      subject_agent: did(SUBJECT_AGENT_PUB),
      extra: { sequence: i, evidence_tier: i === 0 ? 'self-declared' : i === 1 ? 'behavioral' : 'infrastructure' },
    }),
  )
  writeFixture('trust-level-ascending', {
    fixture: 'trust-level-ascending',
    description:
      'Trajectory of three attestations on the same subject agent, rising trust_level ' +
      '(unknown → developing → trusted) as evidence tier strengthens. ' +
      'Each attestation is independently signed and JCS-canonical. All over the same ' +
      'delegation_chain_root (sha256 form). Verifier should accept all three signatures ' +
      'and surface the monotone upward trajectory.',
    expected_verifier_output: 'valid',
    format_variant: false,
    trust_level_trajectory: levels,
    spec_refs: ['a2aproject/A2A#1742'],
    header_name: 'x-agent-trust',
    header_value: {
      trust_header_version: '0.1',
      subject_agent: did(SUBJECT_AGENT_PUB),
      delegation_chain: chain,
      delegation_chain_root: root,
      attestations,
    },
  })
}

// ═════════════════════════════════════════════════════════════════════
// 3. trust-level-descending.json — trusted → developing → flagged
// ═════════════════════════════════════════════════════════════════════

{
  const chain = [
    signDelegationLink({
      by_seed: APS_ISSUER_SEED,
      by_pub: APS_ISSUER_PUB,
      to_pub: SUBJECT_AGENT_PUB,
      scope: ['tool:read', 'tool:write'],
      issued_at: T0,
      expires_at: T3,
    }),
  ]
  const root = chainRoot(chain)
  const levels: Array<'trusted' | 'developing' | 'flagged'> = [
    'trusted',
    'developing',
    'flagged',
  ]
  const times = [T0, T1, T2]
  const reasons: Array<string | null> = [
    null,
    'behavioral_drift_observed',
    'policy_violation_confirmed',
  ]
  const attestations = levels.map((lvl, i) =>
    signAttestation({
      trust_level: lvl,
      issued_at: times[i],
      delegation_chain_root: root,
      issuer_seed: APS_ISSUER_SEED,
      issuer_pub: APS_ISSUER_PUB,
      subject_agent: did(SUBJECT_AGENT_PUB),
      extra: {
        sequence: i,
        ...(reasons[i] ? { reason: reasons[i] } : {}),
      },
    }),
  )
  writeFixture('trust-level-descending', {
    fixture: 'trust-level-descending',
    description:
      'Reputation-decay trajectory: trusted → developing → flagged across three attestations. ' +
      'All signatures verify; the final attestation carries reason=policy_violation_confirmed. ' +
      'Verifier should accept signatures (output=valid) and surface the descending trajectory ' +
      'so downstream policy can decide whether to honor the most recent trust_level.',
    expected_verifier_output: 'valid',
    format_variant: false,
    trust_level_trajectory: levels,
    spec_refs: ['a2aproject/A2A#1742'],
    header_name: 'x-agent-trust',
    header_value: {
      trust_header_version: '0.1',
      subject_agent: did(SUBJECT_AGENT_PUB),
      delegation_chain: chain,
      delegation_chain_root: root,
      attestations,
    },
  })
}

// ═════════════════════════════════════════════════════════════════════
// 4. drift-explicit-flag.json — root format changes from sha256 to keccak256
// ═════════════════════════════════════════════════════════════════════

{
  const chain = [
    signDelegationLink({
      by_seed: APS_ISSUER_SEED,
      by_pub: APS_ISSUER_PUB,
      to_pub: SUBJECT_AGENT_PUB,
      scope: ['tool:read'],
      issued_at: T0,
      expires_at: T3,
    }),
  ]
  const rootSha = chainRoot(chain)
  // Non-standard variant: same bytes, different advertised hash algorithm
  const rootKeccak = `keccak256:${sha256(canonicalizeJCS(chain))}`

  // Attestation 1 — canonical sha256 root
  const att1 = signAttestation({
    trust_level: 'trusted',
    issued_at: T0,
    delegation_chain_root: rootSha,
    issuer_seed: APS_ISSUER_SEED,
    issuer_pub: APS_ISSUER_PUB,
    subject_agent: did(SUBJECT_AGENT_PUB),
  })
  // Attestation 2 — same chain, but root advertised as keccak256 (drift)
  const att2 = signAttestation({
    trust_level: 'trusted',
    issued_at: T1,
    delegation_chain_root: rootKeccak,
    issuer_seed: APS_ISSUER_SEED,
    issuer_pub: APS_ISSUER_PUB,
    subject_agent: did(SUBJECT_AGENT_PUB),
    extra: { format_variant_note: 'delegation_chain_root hash algorithm diverges from sha256 baseline' },
  })

  writeFixture('drift-explicit-flag', {
    fixture: 'drift-explicit-flag',
    description:
      'Drift case: two attestations over the same delegation chain, but the second advertises ' +
      'the chain root under a non-standard hash algorithm (keccak256 instead of sha256). ' +
      'Per MoltyCel agreement, this non-canonical shape MUST carry format_variant=true at the ' +
      'fixture level. The signatures both verify; the verifier should flag the root-format ' +
      'drift and refuse to treat att2 as interoperable with the sha256 baseline.',
    expected_verifier_output: 'invalid',
    format_variant: true,
    format_variant_reason: 'delegation_chain_root hash algorithm changes sha256 → keccak256 between attestations',
    spec_refs: ['a2aproject/A2A#1742'],
    header_name: 'x-agent-trust',
    header_value: {
      trust_header_version: '0.1',
      subject_agent: did(SUBJECT_AGENT_PUB),
      delegation_chain: chain,
      delegation_chain_root: rootSha,
      attestations: [att1, att2],
    },
  })
}

// ═════════════════════════════════════════════════════════════════════
// 5. revocation-mid-chain.json — chain revoked at step 2, deny receipt at step 3
// ═════════════════════════════════════════════════════════════════════

{
  // Step 1 — delegation minted, valid
  const link1 = signDelegationLink({
    by_seed: APS_ISSUER_SEED,
    by_pub: APS_ISSUER_PUB,
    to_pub: DELEGATE_1_PUB,
    scope: ['tool:read'],
    issued_at: T0,
    expires_at: T3,
    status: 'active',
  })
  // Step 2 — principal revokes link1 at T1
  const link1Revoked = signDelegationLink({
    by_seed: APS_ISSUER_SEED,
    by_pub: APS_ISSUER_PUB,
    to_pub: DELEGATE_1_PUB,
    scope: ['tool:read'],
    issued_at: T0,
    expires_at: T3,
    status: 'revoked',
    revoked_at: T1,
  })
  // Step 3 — delegate attempts to use the revoked delegation → gateway emits deny receipt
  const denyReceiptPayload = {
    type: 'deny_receipt',
    subject_agent: did(DELEGATE_1_PUB),
    attempted_at: T2,
    attempted_scope: 'tool:read',
    reason: 'delegation_revoked',
    revoked_delegation: {
      delegated_by: APS_ISSUER_PUB,
      delegated_to: DELEGATE_1_PUB,
      revoked_at: T1,
    },
  }
  const denyReceiptCanonical = canonicalizeJCS(denyReceiptPayload)
  const denyReceipt = {
    payload: denyReceiptPayload,
    signature: {
      alg: 'EdDSA',
      kid: did(APS_ISSUER_PUB),
      pubkey: APS_ISSUER_PUB,
      canonicalization: 'RFC8785-JCS',
      sig: sign(denyReceiptCanonical, APS_ISSUER_SEED),
    },
  }

  const chain = [link1, link1Revoked]
  const root = chainRoot(chain)

  const attestation = signAttestation({
    trust_level: 'revoked',
    issued_at: T2,
    delegation_chain_root: root,
    issuer_seed: APS_ISSUER_SEED,
    issuer_pub: APS_ISSUER_PUB,
    subject_agent: did(DELEGATE_1_PUB),
    extra: {
      revoked_at: T1,
      deny_receipt_ref: `sha256:${sha256(denyReceiptCanonical)}`,
    },
  })

  writeFixture('revocation-mid-chain', {
    fixture: 'revocation-mid-chain',
    description:
      'Revocation case: chain is valid at step 1 (T0), revoked at step 2 (T1), use attempted at ' +
      'step 3 (T2) produces a signed deny receipt. The chain carries both the active and the ' +
      'revoked delegation records so a verifier can reconstruct the state transition. ' +
      'Per MoltyCel agreement, revocation cases carry format_variant=true because the chain ' +
      'contains a status=revoked link that deviates from the pure happy-path shape.',
    expected_verifier_output: 'deny',
    format_variant: true,
    format_variant_reason: 'delegation chain includes a status=revoked link alongside the original active link',
    revocation_timestamp: T1,
    spec_refs: ['a2aproject/A2A#1742'],
    header_name: 'x-agent-trust',
    header_value: {
      trust_header_version: '0.1',
      subject_agent: did(DELEGATE_1_PUB),
      delegation_chain: chain,
      delegation_chain_root: root,
      attestations: [attestation],
      deny_receipt: denyReceipt,
    },
  })
}

// ═════════════════════════════════════════════════════════════════════
// 6. shared-card-crossorg.json — orgA + orgB share a trust card per A2A#1628
// ═════════════════════════════════════════════════════════════════════

{
  const chain = [
    signDelegationLink({
      by_seed: APS_ISSUER_SEED,
      by_pub: APS_ISSUER_PUB,
      to_pub: SUBJECT_AGENT_PUB,
      scope: ['tool:read', 'commerce:preflight'],
      issued_at: T0,
      expires_at: T3,
    }),
  ]
  const root = chainRoot(chain)

  // Two independent signals from orgA and orgB over the SAME subject agent.
  // No self-attestation: orgA does not sign on its own behalf, it signs about the subject.
  const signalA = signAttestation({
    trust_level: 'trusted',
    issued_at: T0,
    delegation_chain_root: root,
    issuer_seed: ORG_A_SEED,
    issuer_pub: ORG_A_PUB,
    subject_agent: did(SUBJECT_AGENT_PUB),
    extra: { issuer_org: 'orgA', evidence_tier: 'infrastructure', issuer_domain: 'orga.example' },
  })
  const signalB = signAttestation({
    trust_level: 'trusted',
    issued_at: T1,
    delegation_chain_root: root,
    issuer_seed: ORG_B_SEED,
    issuer_pub: ORG_B_PUB,
    subject_agent: did(SUBJECT_AGENT_PUB),
    extra: { issuer_org: 'orgB', evidence_tier: 'behavioral', issuer_domain: 'orgb.example' },
  })

  // A2A Agent Card v2 — trust.signals[] per #1628
  const agentCard = {
    name: 'subject-agent',
    agent_id: did(SUBJECT_AGENT_PUB),
    pubkey: SUBJECT_AGENT_PUB,
    trust: {
      signals: [signalA, signalB],
    },
  }

  writeFixture('shared-card-crossorg', {
    fixture: 'shared-card-crossorg',
    description:
      'A2A Agent Card (per #1628) carrying trust.signals[] from two independent orgs (orgA + orgB) ' +
      'about the same subject agent. Each signal is independently Ed25519-signed by its org key. ' +
      'Neither signal is self-attested: the issuer of each signal is distinct from the subject ' +
      'agent. Verifier should accept both signatures and surface that the subject has two ' +
      'cross-org trust signals concurring at trust_level=trusted.',
    expected_verifier_output: 'valid',
    format_variant: false,
    spec_refs: ['a2aproject/A2A#1742', 'a2aproject/A2A#1628'],
    header_name: 'x-agent-trust',
    header_value: {
      trust_header_version: '0.1',
      subject_agent: did(SUBJECT_AGENT_PUB),
      delegation_chain: chain,
      delegation_chain_root: root,
      agent_card: agentCard,
    },
  })
}

// ── Public key registry for verifier ───────────────────────────────────

writeFixture('_keys', {
  description:
    'Deterministic Ed25519 public keys used across the six fixtures. Seeds follow the ' +
    'fixtures/keys/ convention (32-byte tail). Seeds themselves are NOT reproduced here; ' +
    'verifier only needs the public halves.',
  keys: {
    aps_issuer:    { pubkey: APS_ISSUER_PUB,    did: did(APS_ISSUER_PUB) },
    org_a:         { pubkey: ORG_A_PUB,         did: did(ORG_A_PUB) },
    org_b:         { pubkey: ORG_B_PUB,         did: did(ORG_B_PUB) },
    subject_agent: { pubkey: SUBJECT_AGENT_PUB, did: did(SUBJECT_AGENT_PUB) },
    delegate_1:    { pubkey: DELEGATE_1_PUB,    did: did(DELEGATE_1_PUB) },
    delegate_2:    { pubkey: DELEGATE_2_PUB,    did: did(DELEGATE_2_PUB) },
  },
})

console.log('\nAll six fixtures generated.')
