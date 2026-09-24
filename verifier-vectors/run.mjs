#!/usr/bin/env node
// Verifier-side vectors: fixed receipts and key sets, and what a verifier must report about them.
//
//   node verifier-vectors/run.mjs
//
//   VERIFY_PKG  the verifier run through npx (default: the first release implementing -04 Section 5.5)
//   VERIFY_CMD  instead of npx, a command prefix, e.g. "node /path/to/verify-cli/cli.js" (local testing)
//
// Three parts:
//   1. key-window/                    this repository's key validity window vectors (Section 5.5)
//   2. farley-receipt-signature       giskard09/argentum-core's vectors (Apache-2.0), fetched at a pinned commit
//   3. conformance/check_embedded_key.sh   a receipt's own key must never be trusted (Section 9.5)
//
// Exit: 0 every case matched, 1 a case did not, 77 the pinned verifier cannot be installed here.

import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const ROOT = path.dirname(HERE)
const PKG = process.env.VERIFY_PKG || '@veritasacta/verify@0.10.20'
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

console.log(`\n${passed} passed, ${failed} failed`)
process.exit(failed ? 1 : 0)
