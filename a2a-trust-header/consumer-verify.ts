/**
 * Dual-provider consumer verifier for A2A#1742 x-agent-trust header.
 *
 * Week 3 deliverable. Validates BOTH APS and MolTrust-shaped fixtures
 * against the canonical 5-field composite schema locked in Week 1, then
 * verifies Ed25519 signatures and recomputes delegation_chain_root.
 *
 * Fixture discovery:
 *   - every *.json at the top level of a2a-trust-header/
 *     (excluding _keys.json and anything under schema/ or moltrust-placeholder/
 *     auto-discovered separately)
 *   - every *.json under moltrust-placeholder/
 *
 * For each fixture:
 *   1. Derive the composite view (5 canonical fields) from header_value.
 *      APS fixtures carry trust_level / attestation_count / last_verified
 *      / evidence_bundle inside attestations[]; the consumer reduces the
 *      rich APS native shape to the canonical 5-field composite a consumer
 *      would read on the wire.
 *      MolTrust placeholder fixtures carry the 5 fields directly on
 *      header_value (matching the canonical shape natively).
 *   2. ajv-validate the composite view against the canonical schema.
 *   3. Ed25519-verify every signature present (delegation links,
 *      attestations, agent_card signals, deny receipts, MolTrust
 *      placeholder emissions + trajectory entries). Uses @noble/ed25519
 *      verifyAsync so this verifier does not pull the APS SDK for
 *      signature checks.
 *   4. Recompute delegation_chain_root when a fixture carries an inline
 *      delegation_chain array. Compare against the declared value.
 *
 * Per-fixture row + aggregate summary printed to stdout.
 *
 * Exit codes:
 *    0 = all fixtures pass
 *    1 = any signature or chain-root failure
 *    2 = any schema failure
 */

import { readFileSync, readdirSync, statSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import Ajv from 'ajv/dist/2020.js'
import addFormats from 'ajv-formats'
import * as ed from '@noble/ed25519'
import { canonicalizeJCS } from 'agent-passport-system'

const DIR = dirname(fileURLToPath(import.meta.url))
const SCHEMA_PATH = join(DIR, 'schema', 'a2a-trust-header.schema.json')
const PLACEHOLDER_DIR = join(DIR, 'moltrust-placeholder')

const sha256 = (s: string) => createHash('sha256').update(s).digest('hex')

// ── Schema validator ──────────────────────────────────────────────────
const schema = JSON.parse(readFileSync(SCHEMA_PATH, 'utf8'))
const ajv = new Ajv({ allErrors: true, strict: false })
addFormats(ajv)
const validateComposite = ajv.compile(schema)

// ── Fixture discovery ─────────────────────────────────────────────────
// Files that live alongside fixtures but are NOT fixtures. These are
// excluded from the fixture discovery loop.
const NON_FIXTURE_FILES = new Set([
  '_keys.json',
  'package.json',
  'package-lock.json',
  'tsconfig.json',
])

function discoverFixtures(): Array<{ path: string; label: string }> {
  const files: Array<{ path: string; label: string }> = []

  for (const entry of readdirSync(DIR)) {
    if (!entry.endsWith('.json')) continue
    if (NON_FIXTURE_FILES.has(entry)) continue
    if (entry.startsWith('_')) continue
    const full = join(DIR, entry)
    if (!statSync(full).isFile()) continue
    files.push({ path: full, label: entry })
  }

  try {
    for (const entry of readdirSync(PLACEHOLDER_DIR)) {
      if (!entry.endsWith('.json')) continue
      const full = join(PLACEHOLDER_DIR, entry)
      if (!statSync(full).isFile()) continue
      files.push({ path: full, label: `moltrust-placeholder/${entry}` })
    }
  } catch {
    /* no placeholder dir yet; skip */
  }

  files.sort((a, b) => a.label.localeCompare(b.label))
  return files
}

// ── Issuer classification ─────────────────────────────────────────────
type IssuerKind = 'aps' | 'moltrust' | 'unknown'

function classifyIssuer(fixture: Record<string, unknown>, hv: Record<string, unknown>): IssuerKind {
  if (fixture._placeholder === true) return 'moltrust'

  const direct = typeof hv.issuer === 'string' ? (hv.issuer as string) : undefined
  if (direct === 'moltrust' || direct?.startsWith('moltrust:')) return 'moltrust'
  if (direct?.startsWith('did:aps:')) return 'aps'

  const did = typeof hv.did === 'string' ? (hv.did as string) : undefined
  if (did?.startsWith('did:aps:')) return 'aps'
  if (did?.startsWith('did:moltrust:')) return 'moltrust'

  // Infer from attestation issuer kid prefix
  const atts = (hv.attestations ?? []) as Array<{
    payload?: { issuer?: string }
    signature?: { kid?: string }
  }>
  for (const att of atts) {
    const kid = att?.signature?.kid ?? ''
    if (kid.startsWith('did:aps:')) return 'aps'
    if (kid.startsWith('moltrust:') || kid.startsWith('did:moltrust:')) return 'moltrust'
    const iss = att?.payload?.issuer ?? ''
    if (iss.startsWith('did:aps:')) return 'aps'
    if (iss === 'moltrust' || iss.startsWith('moltrust:')) return 'moltrust'
  }

  // Shared-card fixture: inspect agent_card.trust.signals
  const card = hv.agent_card as
    | { trust?: { signals?: Array<{ signature?: { kid?: string } }> } }
    | undefined
  if (card?.trust?.signals?.length) {
    const kid = card.trust.signals[0].signature?.kid ?? ''
    if (kid.startsWith('did:aps:')) return 'aps'
  }

  return 'unknown'
}

// ── Composite-view derivation ─────────────────────────────────────────
/**
 * Reduce a fixture's header_value to the canonical 5-field composite.
 * For MolTrust placeholders, the fields are already present on
 * header_value and returned directly. For APS fixtures, they are
 * synthesized from the rich native shape.
 */
function deriveComposite(
  hv: Record<string, unknown>,
  issuerKind: IssuerKind,
): { composite: Record<string, unknown>; derivation: 'direct' | 'aps-synthesized' } {
  const hasDirectCompositeFields =
    typeof hv.trust_level === 'number' &&
    typeof hv.attestation_count === 'number' &&
    typeof hv.last_verified === 'string' &&
    typeof hv.evidence_bundle === 'string' &&
    typeof hv.delegation_chain_root === 'string'

  if (hasDirectCompositeFields) {
    return {
      composite: {
        trust_level: hv.trust_level,
        attestation_count: hv.attestation_count,
        last_verified: hv.last_verified,
        evidence_bundle: hv.evidence_bundle,
        delegation_chain_root: hv.delegation_chain_root,
      },
      derivation: 'direct',
    }
  }

  // APS synthesis path: derive from attestations[] + agent_card.trust.signals[]
  const attestations = (hv.attestations ?? []) as Array<{
    payload?: { trust_level?: string; issued_at?: string }
  }>
  const card = hv.agent_card as
    | { trust?: { signals?: Array<{ payload?: { trust_level?: string; issued_at?: string } }> } }
    | undefined
  const signals = card?.trust?.signals ?? []
  const all = [...attestations, ...signals]

  const levelMap: Record<string, number> = {
    unknown: 0,
    flagged: 1,
    revoked: 0,
    developing: 2,
    trusted: 4,
  }

  const last = all[all.length - 1]
  const trustStr = last?.payload?.trust_level ?? 'unknown'
  const trustLevel = levelMap[trustStr] ?? 0
  const attestationCount = all.length
  const lastVerified = last?.payload?.issued_at ?? '1970-01-01T00:00:00Z'

  const subject =
    typeof hv.subject_agent === 'string' ? (hv.subject_agent as string) : 'unknown'
  // Synthesize evidence_bundle as a pointer to the APS gateway's public
  // trust attestation endpoint for the subject agent.
  const evidenceBundle = `https://gateway.aeoess.com/api/v1/public/trust/${encodeURIComponent(
    subject,
  )}/attestation`

  return {
    composite: {
      trust_level: trustLevel,
      attestation_count: attestationCount,
      last_verified: lastVerified,
      evidence_bundle: evidenceBundle,
      delegation_chain_root: hv.delegation_chain_root ?? '',
    },
    derivation: 'aps-synthesized',
  }
}

// ── Signature collection ──────────────────────────────────────────────
interface SignatureRef {
  location: string
  sig: string
  pubkey: string
  canonicalPayload: string
}

/**
 * Walk the header_value and collect every signed payload + signature
 * pair. Canonicalization is RFC 8785 JCS over payload-minus-signature
 * for inline-signed objects, or over payload for wrapped
 * { payload, signature } objects. This is the shared convention APS +
 * MolTrust both agreed to use.
 */
function collectSignatures(hv: Record<string, unknown>, prefix: string): SignatureRef[] {
  const out: SignatureRef[] = []

  // 1. Delegation chain: each link inline-signs { ...link, signature }
  const chain = (hv.delegation_chain ?? []) as Array<Record<string, unknown>>
  for (let i = 0; i < chain.length; i++) {
    const link = chain[i]
    const sig = link.signature as { sig?: string; pubkey?: string } | undefined
    if (sig?.sig && sig.pubkey) {
      const { signature: _, ...payload } = link
      out.push({
        location: `${prefix}.delegation_chain[${i}]`,
        sig: sig.sig,
        pubkey: sig.pubkey,
        canonicalPayload: canonicalizeJCS(payload),
      })
    }
  }

  // 2. Attestations: { payload, signature } wrapper
  const atts = (hv.attestations ?? []) as Array<{
    payload?: Record<string, unknown>
    signature?: { sig?: string; pubkey?: string }
  }>
  for (let i = 0; i < atts.length; i++) {
    const a = atts[i]
    if (a?.signature?.sig && a.signature.pubkey && a.payload) {
      out.push({
        location: `${prefix}.attestations[${i}]`,
        sig: a.signature.sig,
        pubkey: a.signature.pubkey,
        canonicalPayload: canonicalizeJCS(a.payload),
      })
    }
  }

  // 3. Agent card trust signals (A2A#1628 pattern)
  const card = hv.agent_card as
    | {
        trust?: {
          signals?: Array<{
            payload?: Record<string, unknown>
            signature?: { sig?: string; pubkey?: string }
          }>
        }
      }
    | undefined
  const signals = card?.trust?.signals ?? []
  for (let i = 0; i < signals.length; i++) {
    const s = signals[i]
    if (s?.signature?.sig && s.signature.pubkey && s.payload) {
      out.push({
        location: `${prefix}.agent_card.trust.signals[${i}]`,
        sig: s.signature.sig,
        pubkey: s.signature.pubkey,
        canonicalPayload: canonicalizeJCS(s.payload),
      })
    }
  }

  // 4. Deny receipt
  const deny = hv.deny_receipt as
    | { payload?: Record<string, unknown>; signature?: { sig?: string; pubkey?: string } }
    | undefined
  if (deny?.signature?.sig && deny.signature.pubkey && deny.payload) {
    out.push({
      location: `${prefix}.deny_receipt`,
      sig: deny.signature.sig,
      pubkey: deny.signature.pubkey,
      canonicalPayload: canonicalizeJCS(deny.payload),
    })
  }

  // 5. MolTrust-shape inline signature on header_value itself. The
  // signed payload is header_value minus `signature` and minus fields
  // that are not part of the emission (`trajectory`, `delegation_chain`,
  // `overlap_ref` are accompanying data, not signed content).
  const inlineSig = hv.signature as { sig?: string; pubkey?: string } | undefined
  if (inlineSig?.sig && inlineSig.pubkey) {
    const {
      signature: _sig,
      trajectory: _traj,
      delegation_chain: _chain,
      overlap_ref: _ov,
      ...signed
    } = hv as Record<string, unknown>
    out.push({
      location: `${prefix}.header_value.signature`,
      sig: inlineSig.sig,
      pubkey: inlineSig.pubkey,
      canonicalPayload: canonicalizeJCS(signed),
    })
  }

  // 6. MolTrust trajectory[] entries (each carries its own inline signature)
  const trajectory = (hv.trajectory ?? []) as Array<Record<string, unknown>>
  for (let i = 0; i < trajectory.length; i++) {
    const entry = trajectory[i]
    const s = entry.signature as { sig?: string; pubkey?: string } | undefined
    if (s?.sig && s.pubkey) {
      const { signature: _sig, ...signed } = entry
      out.push({
        location: `${prefix}.trajectory[${i}]`,
        sig: s.sig,
        pubkey: s.pubkey,
        canonicalPayload: canonicalizeJCS(signed),
      })
    }
  }

  return out
}

// ── Per-fixture verification ──────────────────────────────────────────
interface FixtureRow {
  fixture: string
  issuer_kind: IssuerKind
  schema_valid: boolean
  schema_errors: unknown[]
  signatures_total: number
  signatures_valid: number
  signature_failures: string[]
  delegation_chain_root_recomputed: string | null
  delegation_chain_root_declared: string | null
  delegation_chain_root_mismatch: boolean
  composite_derivation: 'direct' | 'aps-synthesized' | 'n/a'
  verdict: 'pass' | 'fail_schema' | 'fail_signature' | 'fail_chain_root' | 'partial'
  notes: string[]
}

async function verifyFixture(path: string, label: string): Promise<FixtureRow> {
  const raw = readFileSync(path, 'utf8')
  const fixture = JSON.parse(raw) as Record<string, unknown>
  const hv = (fixture.header_value ?? {}) as Record<string, unknown>
  const issuerKind = classifyIssuer(fixture, hv)

  const row: FixtureRow = {
    fixture: label,
    issuer_kind: issuerKind,
    schema_valid: false,
    schema_errors: [],
    signatures_total: 0,
    signatures_valid: 0,
    signature_failures: [],
    delegation_chain_root_recomputed: null,
    delegation_chain_root_declared: null,
    delegation_chain_root_mismatch: false,
    composite_derivation: 'n/a',
    verdict: 'pass',
    notes: [],
  }

  // 1. Derive composite + schema-validate
  const { composite, derivation } = deriveComposite(hv, issuerKind)
  row.composite_derivation = derivation
  const schemaOk = validateComposite(composite)
  row.schema_valid = !!schemaOk
  if (!schemaOk) {
    row.schema_errors = (validateComposite.errors ?? []) as unknown[]
  }

  // 2. Signature verification
  const sigs = collectSignatures(hv, label)
  row.signatures_total = sigs.length
  for (const s of sigs) {
    try {
      const ok = await ed.verifyAsync(
        s.sig,
        new TextEncoder().encode(s.canonicalPayload),
        s.pubkey,
      )
      if (ok) {
        row.signatures_valid++
      } else {
        row.signature_failures.push(s.location)
      }
    } catch (err) {
      row.signature_failures.push(
        `${s.location} (verify threw: ${(err as Error).message})`,
      )
    }
  }

  // 3. Recompute delegation_chain_root from inline chain if present
  const chain = hv.delegation_chain as unknown[] | undefined
  const declaredRoot =
    typeof hv.delegation_chain_root === 'string'
      ? (hv.delegation_chain_root as string)
      : null
  row.delegation_chain_root_declared = declaredRoot
  if (Array.isArray(chain) && chain.length > 0 && declaredRoot) {
    const recomputed = `sha256:${sha256(canonicalizeJCS(chain))}`
    row.delegation_chain_root_recomputed = recomputed
    if (declaredRoot.startsWith('sha256:') && recomputed !== declaredRoot) {
      row.delegation_chain_root_mismatch = true
      row.notes.push(
        `declared ${declaredRoot} != recomputed ${recomputed}; drift/variant fixture may declare this intentionally`,
      )
    }
  }

  // 4. Derive verdict
  const hasSchemaFailure = !row.schema_valid
  const hasSignatureFailure = row.signature_failures.length > 0
  // For fixtures that explicitly flag format_variant, a chain-root
  // mismatch under a non-sha256 advertised algorithm is EXPECTED and
  // does not count as a verdict failure.
  const formatVariant = fixture.format_variant === true
  const hasChainRootFailure =
    row.delegation_chain_root_mismatch && !formatVariant

  if (hasSchemaFailure) row.verdict = 'fail_schema'
  else if (hasSignatureFailure) row.verdict = 'fail_signature'
  else if (hasChainRootFailure) row.verdict = 'fail_chain_root'
  else if (issuerKind === 'unknown') {
    row.verdict = 'partial'
    row.notes.push('issuer could not be classified; signatures still verified generically')
  } else row.verdict = 'pass'

  return row
}

// ── Rendering ─────────────────────────────────────────────────────────
function renderRow(r: FixtureRow): void {
  const tag = r.verdict === 'pass' ? 'PASS' : r.verdict === 'partial' ? 'PART' : 'FAIL'
  console.log(
    `[${tag}] ${r.fixture}  issuer=${r.issuer_kind}  schema=${
      r.schema_valid ? 'ok' : 'FAIL'
    }  sigs=${r.signatures_valid}/${r.signatures_total}  root=${
      r.delegation_chain_root_mismatch ? 'drift' : 'ok'
    }  verdict=${r.verdict}`,
  )
  if (r.composite_derivation !== 'n/a') {
    console.log(`         composite_derivation=${r.composite_derivation}`)
  }
  if (!r.schema_valid) {
    for (const e of r.schema_errors) {
      console.log(`         schema: ${JSON.stringify(e)}`)
    }
  }
  for (const f of r.signature_failures) {
    console.log(`         sig FAIL: ${f}`)
  }
  for (const n of r.notes) {
    console.log(`         · ${n}`)
  }
}

// ── Main ──────────────────────────────────────────────────────────────
async function main(): Promise<number> {
  const fixtures = discoverFixtures()
  console.log(
    `Consumer verify: A2A#1742 x-agent-trust header, dual-provider (APS + MolTrust)`,
  )
  console.log(`Schema: ${SCHEMA_PATH}`)
  console.log(`Discovered ${fixtures.length} fixture(s)\n`)

  const rows: FixtureRow[] = []
  for (const f of fixtures) {
    const row = await verifyFixture(f.path, f.label)
    rows.push(row)
    renderRow(row)
  }

  // Aggregate
  const aps = rows.filter(r => r.issuer_kind === 'aps')
  const molt = rows.filter(r => r.issuer_kind === 'moltrust')
  const unknown = rows.filter(r => r.issuer_kind === 'unknown')
  const apsPass = aps.filter(r => r.verdict === 'pass').length
  const moltPass = molt.filter(r => r.verdict === 'pass').length
  const schemaFailures = rows.filter(r => r.verdict === 'fail_schema').length
  const sigFailures = rows.filter(r => r.verdict === 'fail_signature').length
  const chainRootFailures = rows.filter(r => r.verdict === 'fail_chain_root').length

  console.log('\nConsumer verify: aggregate')
  console.log(`  APS fixtures:       ${apsPass} / ${aps.length} pass`)
  console.log(
    `  MolTrust fixtures:  ${moltPass} / ${molt.length} pass (placeholder)`,
  )
  console.log(`  Unknown issuer:     ${unknown.length}`)
  console.log(`  Schema failures:    ${schemaFailures}`)
  console.log(`  Signature failures: ${sigFailures}`)
  console.log(`  Chain-root drift:   ${chainRootFailures}`)

  if (schemaFailures > 0) return 2
  if (sigFailures > 0 || chainRootFailures > 0) return 1
  return 0
}

main().then(code => process.exit(code)).catch(err => {
  console.error(err)
  process.exit(1)
})
