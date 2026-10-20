#!/usr/bin/env node
// Verifier-side vectors: fixed receipts and key sets, and what a verifier must report about them.
//
//   node verifier-vectors/run.mjs
//
//   VERIFY_PKG  the verifier run through npx (default: 0.10.26, the latest release, published with npm provenance).
//               0.10.26 was the first to check a receipt against a supplied predecessor (--previous), to read --jwks
//               with --replay-chain, and to combine checks as -04 Section 5.3 does; 0.10.25 the first to refuse a
//               payload-only link in a sequence whatever the receipt before it cites, and to report each chain a
//               sequence holds; 0.10.22 the first to refuse a malformed or other-algorithm chain link on a receipt
//               checked alone, Section 6.7; and 0.10.21 the first to implement -04 Section 5.5 and refuse a signature
//               member in the signing input, Section 6.6.
//   VERIFY_CMD  instead of npx, a command prefix, e.g. "node /path/to/verify-cli/cli.js" (local testing)
//   REVOCATION_CHECKED=1  score revocation/ against expected_if_revocation_checked, for a verifier that reads revoked_at
//
// Seven parts:
//   1. key-window/                    this repository's key validity window vectors (Section 5.5)
//   2. farley-receipt-signature       giskard09/argentum-core's vectors (Apache-2.0), fetched at a pinned commit
//   3. conformance/check_embedded_key.sh   a receipt's own key must never be trusted (Section 9.5)
//   4. revocation/                    a key revoked before issued_at: the gap, since the draft defines no revocation
//   5. timeliness/                    one issued_at, alone and against an external chain commitment (Section 9.7)
//   6. signing-input/                 a signature member in the object canonicalized, null included (Section 6.6)
//   7. chain-link/                    the link alone, against a supplied predecessor, in a sequence (6.7, 6.7.1, 5.3)
//
// Exit: 0 every case matched, 1 a case did not, 77 the pinned verifier cannot be installed here.

import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const ROOT = path.dirname(HERE)
const PKG = process.env.VERIFY_PKG || '@veritasacta/verify@0.10.26'
const CMD = process.env.VERIFY_CMD ? process.env.VERIFY_CMD.split(' ').filter(Boolean) : ['npx', '--yes', PKG]
const ARGENTUM = {
  repo: 'giskard09/argentum-core',
  commit: '541ce84b4f970c1dd3d9e53f2a4562dbbc354e46',
  dir: 'examples/conformance/farley-receipt-signature',
}

function run(args, cwd) {
  const p = spawnSync(CMD[0], [...CMD.slice(1), ...args], { cwd, encoding: 'utf8' })
  let out = null
  try { out = JSON.parse(p.stdout) } catch { /* reported below */ }
  return { rc: p.status, out, stderr: p.stderr || '' }
}

const probe = spawnSync(CMD[0], [...CMD.slice(1), '--version'], { encoding: 'utf8' })
if (probe.status !== 0) {
  const why = (probe.stderr || '').split('\n').find((l) => l.trim()) || `exit ${probe.status}`
  console.log(`skip: ${CMD.join(' ')} cannot run here (${why.trim()})`)
  process.exit(77)
}
console.log(`verifier: ${process.env.VERIFY_CMD || PKG} (${probe.stdout.trim()})`)

let failed = 0
let passed = 0
const ok = (msg) => { passed += 1; console.log(`  ok    ${msg}`) }
const bad = (msg) => { failed += 1; console.log(`  FAIL  ${msg}`) }
const verdictOf = (out) => (out && out.valid === true ? 'ACCEPT' : 'REJECT')

// 1. Key validity windows.
console.log('\n=== key-window (Section 5.5) ===')
const gen = spawnSync(process.execPath, [path.join(HERE, 'key-window', 'scripts', 'generate.mjs'), '--check'], { encoding: 'utf8' })
if (gen.status !== 0) bad(`key-window vectors are stale: ${gen.stderr.trim()}`)
const kw = JSON.parse(fs.readFileSync(path.join(HERE, 'key-window', 'index.json'), 'utf8'))
for (const c of kw.cases) {
  const { out } = run([c.file, '--jwks', c.jwks, '--mode', 'receipt', '--json'], path.join(HERE, 'key-window'))
  const label = `${c.file} with ${c.jwks}`
  if (!out) { bad(`${label}: no JSON from the verifier`); continue }
  const verdict = verdictOf(out)
  const status = out.keyStatus && out.keyStatus.result
  if (verdict !== c.expected) bad(`${label}: ${verdict}, expected ${c.expected}`)
  else if (c.code && out.error !== c.code) bad(`${label}: code ${out.error}, expected ${c.code}`)
  else if (status !== c.key_status) bad(`${label}: key status ${status || 'not reported'}, expected ${c.key_status}`)
  else ok(`${label}: ${verdict}${c.code ? ` (${c.code})` : ''}, key ${status}`)
}

// 2. argentum-core's farley-receipt-signature vectors, at a pinned commit. They are fetched rather than copied, so
//    their authors' index.json stays the source of truth. A runner without network access skips this part.
console.log(`\n=== farley-receipt-signature (${ARGENTUM.repo} @ ${ARGENTUM.commit.slice(0, 7)}) ===`)
const base = `https://raw.githubusercontent.com/${ARGENTUM.repo}/${ARGENTUM.commit}/${ARGENTUM.dir}`
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'farley-vectors-'))
async function fetchTo(name) {
  const r = await fetch(`${base}/${name}`)
  if (!r.ok) throw new Error(`${name}: HTTP ${r.status}`)
  fs.writeFileSync(path.join(tmp, name), Buffer.from(await r.arrayBuffer()))
}
try {
  await fetchTo('index.json')
  await fetchTo('jwks.json')
  const idx = JSON.parse(fs.readFileSync(path.join(tmp, 'index.json'), 'utf8'))
  for (const v of idx.vectors) {
    await fetchTo(v.file)
    const { out } = run([v.file, '--jwks', './jwks.json', '--mode', 'receipt', '--json'], tmp)
    if (!out) { bad(`${v.file}: no JSON from the verifier`); continue }
    // The pinned verifier implements Section 5.5, so every vector is held to its strict expected verdict, SHOULD
    // vectors included; expected_if_not_honoured is for verifiers that predate it.
    const verdict = verdictOf(out)
    if (verdict === v.expected) ok(`${v.file}: ${verdict}${v.code ? ` (${out.error})` : ''}`)
    else bad(`${v.file}: ${verdict}, expected ${v.expected}${v.code ? ` (${v.code})` : ''}`)
  }
} catch (e) {
  console.log(`  skip  could not fetch the vectors: ${e.message}`)
}

// 3. A receipt's own key must never be trusted (ScopeBlind/agent-governance-testvectors#24).
console.log('\n=== embedded keys (Section 9.5) ===')
if (process.env.VERIFY_CMD) {
  console.log('  skip  check_embedded_key.sh runs the verifier through npx; run it directly for a local build')
} else {
  const ek = spawnSync('bash', [path.join(ROOT, 'conformance', 'check_embedded_key.sh')], {
    encoding: 'utf8', env: { ...process.env, VERIFY_PKG: PKG },
  })
  process.stdout.write(ek.stdout.split('\n').map((l) => (l ? `  ${l}` : l)).join('\n'))
  if (ek.status === 0) passed += 1
  else { failed += 1; console.log(`  FAIL  check_embedded_key.sh exited ${ek.status}`) }
}

// 4. Revocation. The draft defines none, so under -04 the receipt signed after revoked_at is accepted and its key is
//    reported inside its window. A verifier that reads revoked_at declares it and is scored against the other column.
const REVOKED = process.env.REVOCATION_CHECKED === '1'
console.log(`\n=== revocation (not defined by -03 or -04; scored ${REVOKED ? 'as revocation checked' : 'under -04'}) ===`)
const rg = spawnSync(process.execPath, [path.join(HERE, 'revocation', 'scripts', 'generate.mjs'), '--check'], { encoding: 'utf8' })
if (rg.status !== 0) bad(`revocation vectors are stale: ${rg.stderr.trim()}`)
const rv = JSON.parse(fs.readFileSync(path.join(HERE, 'revocation', 'index.json'), 'utf8'))
for (const c of rv.cases) {
  const { out } = run([c.file, '--jwks', c.jwks, '--mode', 'receipt', '--json'], path.join(HERE, 'revocation'))
  const label = `${c.file} with ${c.jwks}`
  if (!out) { bad(`${label}: no JSON from the verifier`); continue }
  const verdict = verdictOf(out)
  const expected = REVOKED ? c.expected_if_revocation_checked : c.expected
  const code = REVOKED ? c.code_if_revocation_checked : c.code
  const status = out.keyStatus && out.keyStatus.result
  if (verdict !== expected) bad(`${label}: ${verdict}, expected ${expected}`)
  else if (code && out.error !== code) bad(`${label}: code ${out.error}, expected ${code}`)
  else if (!REVOKED && status !== c.key_status) bad(`${label}: key status ${status || 'not reported'}, expected ${c.key_status}`)
  else ok(`${label}: ${verdict}${code ? ` (${code})` : ''}${REVOKED ? '' : `, key ${status}`}`)
}

// 5. Timeliness. The verifier checks each receipt of the chain; scripts/check.mjs checks the Section 6.7 link and
//    evaluates the proposed commitment rule, which no revision of the draft defines yet.
console.log('\n=== timeliness (Section 9.7; the commitment rule is proposed, not in the draft) ===')
const tg = spawnSync(process.execPath, [path.join(HERE, 'timeliness', 'scripts', 'generate.mjs'), '--check'], { encoding: 'utf8' })
if (tg.status !== 0) bad(`timeliness vectors are stale: ${tg.stderr.trim()}`)
for (const file of ['genesis.json', 'receipt.json']) {
  const { out } = run([file, '--jwks', 'jwks.json', '--mode', 'receipt', '--json'], path.join(HERE, 'timeliness'))
  if (!out) { bad(`${file}: no JSON from the verifier`); continue }
  const verdict = verdictOf(out)
  const status = out.keyStatus && out.keyStatus.result
  if (verdict !== 'ACCEPT') bad(`${file}: ${verdict}, expected ACCEPT`)
  else if (status !== 'inside') bad(`${file}: key status ${status || 'not reported'}, expected inside`)
  else ok(`${file}: ACCEPT, key inside`)
}
const tc = spawnSync(process.execPath, [path.join(HERE, 'timeliness', 'scripts', 'check.mjs')], { encoding: 'utf8' })
process.stdout.write(tc.stdout.split('\n').filter((l) => l.startsWith('  ')).map((l) => `${l}\n`).join(''))
if (tc.status === 0) passed += 1
else { failed += 1; console.log(`  FAIL  timeliness/scripts/check.mjs exited ${tc.status}`) }

// 6. Signing input. Each rejected receipt is signed over JCS(payload) with the member inside, so its signature verifies;
//    Section 6.6 forbids the member itself, null and the empty string included.
console.log('\n=== signing input (Section 6.6) ===')
const sg = spawnSync(process.execPath, [path.join(HERE, 'signing-input', 'scripts', 'generate.mjs'), '--check'], { encoding: 'utf8' })
if (sg.status !== 0) bad(`signing-input vectors are stale: ${sg.stderr.trim()}`)
const si = JSON.parse(fs.readFileSync(path.join(HERE, 'signing-input', 'index.json'), 'utf8'))
for (const c of si.cases) {
  const { rc, out } = run([c.file, '--jwks', c.jwks, '--mode', 'receipt', '--json'], path.join(HERE, 'signing-input'))
  if (!out) { bad(`${c.file}: no JSON from the verifier`); continue }
  const verdict = verdictOf(out)
  if (verdict !== c.expected) bad(`${c.file}: ${verdict}, expected ${c.expected}`)
  else if (c.code && out.error !== c.code) bad(`${c.file}: code ${out.error}, expected ${c.code}`)
  else if (c.code && rc !== 1) bad(`${c.file}: exit ${rc}, expected 1 (invalid, not undecidable)`)
  else ok(`${c.file}: ${verdict}${c.code ? ` (${c.code}, exit 1)` : ''}`)
}

// 7. Chain links. Every receipt is signed over JCS(payload) with its link inside, so its signature verifies. A case is a
//    receipt checked alone, a receipt checked against the predecessor the caller supplies (--previous, which asserts
//    the succession), or a log read as a sequence (--replay-chain, which does not). Section 6.7 fixes the link's form,
//    Section 6.7.1 how it is read, and Section 5.3 how the checks combine: a malformed link, or one that does not follow
//    a supplied predecessor, is invalid (exit 1); one naming another hash algorithm is undecidable (exit 2), unless
//    another check ran and failed.
console.log('\n=== chain links (Sections 6.7 and 6.7.1, and the combination rule of Section 5.3) ===')
const cg = spawnSync(process.execPath, [path.join(HERE, 'chain-link', 'scripts', 'generate.mjs'), '--check'], { encoding: 'utf8' })
if (cg.status !== 0) bad(`chain-link vectors are stale: ${cg.stderr.trim()}`)
const cl = JSON.parse(fs.readFileSync(path.join(HERE, 'chain-link', 'index.json'), 'utf8'))
for (const c of cl.cases) {
  const keyArgs = c.jwks ? ['--jwks', c.jwks] : []
  const args = c.check === 'sequence'
    ? ['--replay-chain', c.file, ...keyArgs, '--json']
    : [c.file, ...(c.check === 'supplied-predecessor' ? ['--previous', c.previous] : []), ...keyArgs, '--mode', 'receipt', '--json']
  const { rc, out } = run(args, path.join(HERE, 'chain-link'))
  const label = `${c.file}${c.previous ? ` after ${c.previous}` : ''}${c.jwks === null ? ' with no key' : c.jwks !== 'jwks.json' ? ` with ${c.jwks}` : ''}`
  if (!out) { bad(`${label}: no JSON from the verifier (exit ${rc})`); continue }
  const verdict = verdictOf(out)
  // A sequence is reported line by line, and each case turns on one line of it.
  const subject = c.check === 'sequence' ? (Array.isArray(out.receipts) && out.receipts[c.line - 1]) || {} : out
  const where = c.check === 'sequence' ? ` on line ${c.line}` : ''
  if (verdict !== c.expected) bad(`${label}: ${verdict}, expected ${c.expected}`)
  else if (c.code && subject.error !== c.code) bad(`${label}: code ${subject.error}${where}, expected ${c.code}`)
  else if (rc !== c.exit) bad(`${label}: exit ${rc}, expected ${c.exit} (${c.outcome})`)
  else if (c.check === 'supplied-predecessor' && !out.previous) bad(`${label}: the result does not report the link compared with ${c.previous}`)
  else if (c.check === 'sequence' && out.chains !== c.chains) bad(`${label}: ${out.chains === undefined ? 'no count of' : out.chains} chains reported, expected ${c.chains}`)
  else if (c.check === 'sequence' && out.chainBreaks !== c.chain_breaks) bad(`${label}: ${out.chainBreaks} chain breaks, expected ${c.chain_breaks}`)
  else if (c.warn && !subject.warning) bad(`${label}: no warning that the issuer emitted a null link${where}`)
  else ok(`${label}: ${verdict}, ${c.outcome}${c.code ? ` (${c.code}, exit ${rc})` : ''}${c.check === 'sequence' ? `, ${c.chains} chain${c.chains === 1 ? '' : 's'}` : ''}${c.warn ? ', warned' : ''}`)
}

console.log(`\n${passed} passed, ${failed} failed`)
process.exit(failed ? 1 : 0)
