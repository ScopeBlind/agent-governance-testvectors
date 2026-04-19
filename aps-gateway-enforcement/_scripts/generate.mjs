#!/usr/bin/env node
// Deterministically generate every signed artifact in this directory.
//
// Run after editing the vector inputs:
//   node aps-gateway-enforcement/_scripts/generate.mjs
//
// Uses the repo-wide deterministic Ed25519 seed
// (fixtures/keys/README.md: 0x00…01) so output is byte-identical across runs.

import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import {
  loadKeyPair,
  jwkThumbprint,
  jwksFor,
  canonicalize,
  sha256Hex,
  makeV2Receipt,
  verifyV2Receipt,
  makeDSSEEnvelope,
  verifyDSSEEnvelope,
  writeJSON
} from './lib.mjs'

const __filename = fileURLToPath(import.meta.url)
const ROOT = dirname(dirname(__filename))

const key = loadKeyPair()
const KID = jwkThumbprint(key.publicKeyHex)
const ISSUER = 'aps:gateway:test'

console.log('Public key:', key.publicKeyHex)
console.log('JWK thumbprint (kid):', KID)

// Shared key + JWKS files
writeJSON(join(ROOT, '_keys', 'jwks.json'), jwksFor(key.publicKeyHex, KID))
writeJSON(join(ROOT, '_keys', 'public-key.json'), {
  algorithm: 'ed25519',
  publicKeyHex: key.publicKeyHex,
  kid: KID,
  derivation: 'Ed25519 seed = 32 bytes of 0x00 followed by 0x01 (see fixtures/keys/README.md)'
})

// ─────────────────────────────────────────────────────────────────────────────
// Vector 1 — fail-closed enforcement
// Policy passes; signing fails (signing-key-unavailable). executeToolCall()
// is never invoked. Output is a structured PolicyEvaluationError, no signed
// receipt, audit log only.
// ─────────────────────────────────────────────────────────────────────────────

const v1Input = {
  request_id: 'req-vec1-001',
  agent_id: 'aps:agent:research-bot',
  tool: 'http.get',
  params: { url: 'https://example.com/data' },
  delegation_id: 'dlg-vec1-research-bot-001',
  policy_id: 'autoresearch-safe',
  timestamp: '2026-04-18T12:00:00Z'
}
writeJSON(join(ROOT, '1-fail-closed', 'input.json'), v1Input)

const v1FaultInjection = {
  description: 'Simulate a transient signing-key-unavailable fault. The HSM is reachable, the policy engine is healthy, but the receipt-signing key cannot be loaded for this request.',
  fault: {
    component: 'receipt-signer',
    error: 'signing_key_unavailable',
    error_detail: 'kid=' + KID + ' not loaded in HSM session',
    transient: true
  }
}
writeJSON(join(ROOT, '1-fail-closed', 'fault-injection.json'), v1FaultInjection)

const v1ExpectedOutput = {
  ok: false,
  decision: 'fail_closed',
  error: {
    code: 'PolicyEvaluationError',
    reason: 'signing_unavailable',
    detail: 'Policy evaluation succeeded but receipt signing failed; no execution permitted.',
    transient: true
  },
  policy_decision: 'allow',
  receipt: null,
  side_effects: {
    tool_invoked: false,
    state_mutated: false,
    audit_log_entry_written: true
  },
  audit_log_entry_ref: 'audit-log.json'
}
writeJSON(join(ROOT, '1-fail-closed', 'expected-output.json'), v1ExpectedOutput)

const v1AuditLog = {
  audit_log_entry_id: 'aud-vec1-001',
  request_id: v1Input.request_id,
  agent_id: v1Input.agent_id,
  tool: v1Input.tool,
  delegation_id: v1Input.delegation_id,
  policy_id: v1Input.policy_id,
  timestamp: v1Input.timestamp,
  policy_decision: 'allow',
  signing_outcome: 'failed',
  signing_error: 'signing_key_unavailable',
  enforcement_outcome: 'fail_closed',
  tool_invoked: false,
  signed: false,
  note: 'Deliberately unsigned: this entry records a signing failure. No execution occurred. Operator must not sign-after-the-fact; operators may only retry the original request, which produces a fresh audit entry.'
}
writeJSON(join(ROOT, '1-fail-closed', 'audit-log.json'), v1AuditLog)

console.log('Vector 1 (fail-closed): wrote 4 files (no signed artifacts — the point of the vector)')

// ─────────────────────────────────────────────────────────────────────────────
// Vector 2 — external verification
// A real v2 envelope receipt + JWKS that any standard Ed25519 verifier
// (openssl, jose CLI, browser SubtleCrypto) can verify with no APS code.
// ─────────────────────────────────────────────────────────────────────────────

const v2Input = {
  request_id: 'req-vec2-002',
  agent_id: 'aps:agent:research-bot',
  tool: 'http.get',
  params: { url: 'https://example.com/data' },
  delegation_id: 'dlg-vec2-research-bot-002',
  policy_id: 'autoresearch-safe',
  timestamp: '2026-04-18T12:01:00Z'
}
writeJSON(join(ROOT, '2-external-verification', 'input.json'), v2Input)

const v2Receipt = makeV2Receipt({
  type: 'decision_receipt',
  issuer: ISSUER,
  issued_at: v2Input.timestamp,
  payload: {
    decision: 'allow',
    request_id: v2Input.request_id,
    agent_id: v2Input.agent_id,
    delegation_id: v2Input.delegation_id,
    tool: v2Input.tool,
    params_hash: 'sha256:' + sha256Hex(canonicalize(v2Input.params)),
    policy_id: v2Input.policy_id,
    policy_digest: 'sha256:' + sha256Hex('autoresearch-safe-v1'),
    reason_code: 'policy_match',
    tier: 'signed-known'
  },
  key
})
writeJSON(join(ROOT, '2-external-verification', 'receipt.json'), v2Receipt)
writeJSON(join(ROOT, '2-external-verification', 'jwks.json'), jwksFor(key.publicKeyHex, KID))

// Provide the canonical bytes (the exact message the signature was over)
// so a third-party verifier can prove the round-trip without touching APS code.
const v2Canonical = canonicalize({ ...v2Receipt, signature: undefined })
const { signature: _v2Sig, ...v2Bare } = v2Receipt
const v2CanonicalBytes = canonicalize(v2Bare)
import('node:fs').then(({ writeFileSync }) => {
  writeFileSync(join(ROOT, '2-external-verification', 'canonical.txt'), v2CanonicalBytes)
})

const v2ExpectedOutput = {
  ok: true,
  decision: 'allow',
  receipt_signature_valid: true,
  receipt_canonical_sha256: sha256Hex(v2CanonicalBytes),
  verifier: 'openssl + plain Ed25519 (RFC 8032). No APS-specific code required.',
  jwks_kid_matches_receipt: true
}
writeJSON(join(ROOT, '2-external-verification', 'expected-output.json'), v2ExpectedOutput)

if (!verifyV2Receipt(v2Receipt, key.publicKeyHex)) {
  throw new Error('Vector 2 receipt failed self-verification under APS canonical form')
}
console.log('Vector 2 (external-verification): wrote receipt + jwks + canonical bytes')

// ─────────────────────────────────────────────────────────────────────────────
// Vector 3 — state-drift detection
// Delegation D1 is active when the receipt is signed; revoked before
// executeToolCall(); re-verification at execution time aborts with
// state_hash_mismatch. Before/after state dumps prove the drift.
// ─────────────────────────────────────────────────────────────────────────────

const v3Input = {
  request_id: 'req-vec3-003',
  agent_id: 'aps:agent:research-bot',
  tool: 'http.post',
  params: { url: 'https://example.com/submit', body: { topic: 'analysis' } },
  delegation_id: 'dlg-vec3-research-bot-003',
  policy_id: 'autoresearch-safe',
  timestamp_signed_at: '2026-04-18T12:02:00Z',
  timestamp_executed_at: '2026-04-18T12:02:03Z'
}
writeJSON(join(ROOT, '3-state-drift', 'input.json'), v3Input)

const v3DelegationActive = {
  delegation_id: v3Input.delegation_id,
  delegator: 'aps:agent:operator-prime',
  delegated_to: v3Input.agent_id,
  scope: ['http.get', 'http.post'],
  spend_limit: { amount: 100, currency: 'USD' },
  not_before: '2026-04-18T12:00:00Z',
  not_after: '2026-04-18T18:00:00Z',
  status: 'active',
  status_at: v3Input.timestamp_signed_at
}
writeJSON(join(ROOT, '3-state-drift', 'state-at-signing.json'), v3DelegationActive)

const v3StateAtSigningHash = 'sha256:' + sha256Hex(canonicalize(v3DelegationActive))

const v3Receipt = makeV2Receipt({
  type: 'decision_receipt',
  issuer: ISSUER,
  issued_at: v3Input.timestamp_signed_at,
  payload: {
    decision: 'allow',
    request_id: v3Input.request_id,
    agent_id: v3Input.agent_id,
    delegation_id: v3Input.delegation_id,
    tool: v3Input.tool,
    params_hash: 'sha256:' + sha256Hex(canonicalize(v3Input.params)),
    policy_id: v3Input.policy_id,
    policy_digest: 'sha256:' + sha256Hex('autoresearch-safe-v1'),
    reason_code: 'policy_match',
    tier: 'signed-known',
    state_hash_at_signing: v3StateAtSigningHash
  },
  key
})
writeJSON(join(ROOT, '3-state-drift', 'receipt.json'), v3Receipt)

const v3DelegationRevoked = {
  delegation_id: v3Input.delegation_id,
  delegator: 'aps:agent:operator-prime',
  delegated_to: v3Input.agent_id,
  scope: ['http.get', 'http.post'],
  spend_limit: { amount: 100, currency: 'USD' },
  not_before: '2026-04-18T12:00:00Z',
  not_after: '2026-04-18T18:00:00Z',
  status: 'revoked',
  status_at: '2026-04-18T12:02:01Z',
  revocation_reason: 'operator_initiated',
  revoked_by: 'aps:agent:operator-prime'
}
writeJSON(join(ROOT, '3-state-drift', 'state-at-execution.json'), v3DelegationRevoked)

const v3StateAtExecutionHash = 'sha256:' + sha256Hex(canonicalize(v3DelegationRevoked))

const v3ExpectedOutput = {
  ok: false,
  decision: 'aborted',
  error: {
    code: 'StateHashMismatch',
    reason: 'state_hash_mismatch',
    detail: 'Delegation state changed between receipt-signing and executeToolCall(); aborting fail-closed per the gateway invariant that the executor re-verifies state immediately before each side-effecting call.',
    component: 'aps-gateway:executeToolCall'
  },
  state_hash_at_signing: v3StateAtSigningHash,
  state_hash_at_execution: v3StateAtExecutionHash,
  state_diff: {
    delegation_status: { before: 'active', after: 'revoked' },
    detected_drift_field: 'status'
  },
  receipt_signature_valid: true,
  side_effects: { tool_invoked: false, state_mutated: false, audit_log_entry_written: true }
}
writeJSON(join(ROOT, '3-state-drift', 'expected-output.json'), v3ExpectedOutput)

if (!verifyV2Receipt(v3Receipt, key.publicKeyHex)) {
  throw new Error('Vector 3 receipt failed self-verification')
}
console.log('Vector 3 (state-drift): wrote receipt + before/after states + abort response')

// ─────────────────────────────────────────────────────────────────────────────
// Vector 4 — receipt portability
// One decision, three independent verifier ecosystems. The v2 envelope is
// verifiable by APS SDK and @veritasacta/verify (same canonical bytes). The
// in-toto / DSSE envelope wraps the v2 envelope as a Statement predicate so a
// DSSE consumer accepts it.
// ─────────────────────────────────────────────────────────────────────────────

const v4Input = {
  request_id: 'req-vec4-004',
  agent_id: 'aps:agent:research-bot',
  tool: 'http.get',
  params: { url: 'https://example.com/portable' },
  delegation_id: 'dlg-vec4-research-bot-004',
  policy_id: 'autoresearch-safe',
  timestamp: '2026-04-18T12:03:00Z'
}
writeJSON(join(ROOT, '4-portability', 'input.json'), v4Input)

const v4Receipt = makeV2Receipt({
  type: 'decision_receipt',
  issuer: ISSUER,
  issued_at: v4Input.timestamp,
  payload: {
    decision: 'allow',
    request_id: v4Input.request_id,
    agent_id: v4Input.agent_id,
    delegation_id: v4Input.delegation_id,
    tool: v4Input.tool,
    params_hash: 'sha256:' + sha256Hex(canonicalize(v4Input.params)),
    policy_id: v4Input.policy_id,
    policy_digest: 'sha256:' + sha256Hex('autoresearch-safe-v1'),
    reason_code: 'policy_match',
    tier: 'signed-known'
  },
  key
})
writeJSON(join(ROOT, '4-portability', 'receipt.json'), v4Receipt)
writeJSON(join(ROOT, '4-portability', 'jwks.json'), jwksFor(key.publicKeyHex, KID))

// in-toto Statement with the receipt as predicate
const v4Statement = {
  _type: 'https://in-toto.io/Statement/v1',
  subject: [
    {
      name: v4Input.request_id,
      digest: {
        sha256: sha256Hex(canonicalize(v4Input.params))
      }
    }
  ],
  predicateType: 'https://aeoess.com/aps/decision-receipt/v2',
  predicate: v4Receipt
}
writeJSON(join(ROOT, '4-portability', 'in-toto-statement.json'), v4Statement)

const v4Envelope = makeDSSEEnvelope({
  payloadType: 'application/vnd.in-toto+json',
  statement: v4Statement,
  key
})
writeJSON(join(ROOT, '4-portability', 'intoto-envelope.json'), v4Envelope)

const v4ExpectedOutput = {
  ok: true,
  decision: 'allow',
  verifiers: {
    'aps-sdk': 'VALID',
    'veritasacta-verify': 'VALID',
    'in-toto-dsse': 'VALID'
  },
  same_signing_key_for_all: true,
  same_logical_decision: true
}
writeJSON(join(ROOT, '4-portability', 'expected-output.json'), v4ExpectedOutput)

if (!verifyV2Receipt(v4Receipt, key.publicKeyHex)) {
  throw new Error('Vector 4 v2 receipt failed self-verification')
}
if (!verifyDSSEEnvelope(v4Envelope, key.publicKeyHex)) {
  throw new Error('Vector 4 DSSE envelope failed self-verification')
}
console.log('Vector 4 (portability): wrote v2 receipt + in-toto Statement + DSSE envelope')

console.log('\nAll vectors generated and self-verified.')
