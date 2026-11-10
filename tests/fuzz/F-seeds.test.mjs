// The nightly fuzzer's targets (fuzz/targets/, SPEC §12) on every seed of their corpus, without the fuzzer: each seed
// runs without a finding, so a target that breaks, or a seed it no longer reads, fails here on every pull request
// rather than at night. The seeds must reach what each target is there to check.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readdirSync, readFileSync } from 'node:fs'
import { encoding, assertion } from '../impl.mjs'
import { CTX, make, RECORD } from '../assertion/helpers.mjs'

const SEEDS = new URL('../../fuzz/seeds/', import.meta.url)
const TARGETS = ['decode', 'client-data', 'verify']
const seeds = (name) => readdirSync(new URL(`${name}/`, SEEDS)).map((f) => readFileSync(new URL(`${name}/${f}`, SEEDS)))

test('every target is seeded, and every seed runs without a finding', async () => {
  assert.deepEqual(readdirSync(SEEDS).sort(), [...TARGETS].sort())
  for (const name of TARGETS) {
    const { fuzz } = await import(`../../fuzz/targets/${name}.mjs`)
    const all = seeds(name)
    assert.ok(all.length >= 5, `${name}: ${all.length} seeds`)
    for (const s of all) fuzz(s)
  }
})

test('the seeds reach acceptance and refusal in each target', async () => {
  const decoded = seeds('decode').map((s) => { try { encoding.decode(s.toString('utf8')); return true } catch { return false } })
  assert.ok(decoded.includes(true) && decoded.includes(false), 'decode')
  const checked = seeds('client-data').map((s) => assertion.checkRootAssertion(make({ covers: [RECORD], cdjBytes: s }), CTX).ok)
  assert.ok(checked.includes(true) && checked.includes(false), 'client-data')
  const { splice, RECORDS } = await import('../../fuzz/targets/verify.mjs')
  const spliced = seeds('verify').map(splice)
  assert.deepEqual([...new Set(spliced.map((s) => s.name))].sort(), Object.keys(RECORDS).sort(), 'verify: every record')
  assert.ok(spliced.some((s) => s.text === RECORDS[s.name]) && spliced.some((s) => s.text !== RECORDS[s.name]), 'verify: changed and unchanged')
})

test('the nightly job fuzzes exactly the targets there are', () => {
  const workflow = readFileSync(new URL('../../.github/workflows/fuzz.yml', import.meta.url), 'utf8')
  const listed = workflow.match(/\n {10}for t in ([a-z -]+); do\n/)?.[1].split(' ')
  const files = readdirSync(new URL('../../fuzz/targets/', import.meta.url)).map((f) => f.replace(/\.mjs$/, ''))
  assert.deepEqual(listed?.sort(), [...TARGETS].sort())
  assert.deepEqual(files.sort(), [...TARGETS].sort())
})
