// Every property test takes its run count from runs() (tests/runs.mjs), so FC_RUNS and FC_SCALE reach all of them:
// the nightly fuzz run scales every count, and mutation testing and the twins lower every count.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync } from 'node:fs'
import { runs } from '../runs.mjs'

const TESTS = new URL('../', import.meta.url)

function withEnv (env, f) {
  const saved = { FC_RUNS: process.env.FC_RUNS, FC_SCALE: process.env.FC_SCALE }
  for (const [k, v] of Object.entries(env)) if (v === undefined) delete process.env[k]; else process.env[k] = v
  try { return f() } finally { for (const [k, v] of Object.entries(saved)) if (v === undefined) delete process.env[k]; else process.env[k] = v }
}

test('runs(): the file\'s count, scaled by FC_SCALE, overridden by FC_RUNS', () => {
  assert.equal(withEnv({ FC_RUNS: undefined, FC_SCALE: undefined }, () => runs(300)), 300)
  assert.equal(withEnv({ FC_RUNS: undefined, FC_SCALE: '40' }, () => runs(300)), 12000)
  assert.equal(withEnv({ FC_RUNS: '60', FC_SCALE: '40' }, () => runs(300)), 60)
  for (const env of [{ FC_RUNS: '0' }, { FC_RUNS: '-1' }, { FC_RUNS: '1.5' }, { FC_RUNS: 'x' }, { FC_RUNS: '' },
    { FC_RUNS: undefined, FC_SCALE: '0' }, { FC_RUNS: undefined, FC_SCALE: 'x' }, { FC_RUNS: undefined, FC_SCALE: '2.5' }]) {
    assert.throws(() => withEnv(env, () => runs(300)), RangeError, JSON.stringify(env))
  }
})

// Files that may sample at a fixed count, and why. A sample measured for anti-vacuity must stay at the count it was
// measured at, whatever FC_RUNS a mutation run or a twin sets.
const FIXED = new Map([
  ['membership/R8-walks.test.mjs', 'the walk generator, run through the model alone, must reach every kind of state'],
  ['verifier/F-time-model.test.mjs', 'the call and trace generators, decided by the model alone, must reach every reason'],
])

// What is wrong with one test file's run counts, as short strings; none means every count comes from runs().
const faults = (text, name = '') => [
  ...(text.includes('process.env.FC_RUNS') ? ['reads FC_RUNS'] : []),
  ...((FIXED.has(name) ? /numRuns: (?!runs\(|RUNS\b|1 \}|USUAL \}|TRACES \})/ : /numRuns: (?!runs\(|RUNS\b|1 \})/).test(text) ? ['sets numRuns'] : []),
]

test('the run-count guard names each planted fault', () => {
  assert.deepEqual(faults("const RUNS = Number(process.env.FC_RUNS ?? 300)"), ['reads FC_RUNS'])
  assert.deepEqual(faults("fc.assert(p, { numRuns: 500 })"), ['sets numRuns'])
  assert.deepEqual(faults("fc.assert(p, { numRuns: Number(process.env.FC_RUNS ?? 9) })"), ['reads FC_RUNS', 'sets numRuns'])
  assert.deepEqual(faults("fc.assert(p, { numRuns: runs(500) }); fc.assert(q, { numRuns: RUNS }); fc.sample(a, { numRuns: 1 })"), [])
  assert.deepEqual(faults("// FC_RUNS lowers it"), [])
  assert.deepEqual(faults("fc.sample(a, { seed: PINNED, numRuns: USUAL })"), ['sets numRuns'])
  assert.deepEqual(faults("fc.sample(a, { seed: PINNED, numRuns: USUAL })", 'membership/R8-walks.test.mjs'), [])
  assert.deepEqual(faults("fc.assert(p, { numRuns: 500 })", 'membership/R8-walks.test.mjs'), ['sets numRuns'])
})

test('no property test reads FC_RUNS itself, and every count comes from runs()', () => {
  const offenders = []
  for (const dir of readdirSync(TESTS, { withFileTypes: true })) {
    if (!dir.isDirectory() || dir.name === 'meta' || dir.name === 'guards') continue
    for (const name of readdirSync(new URL(`${dir.name}/`, TESTS))) {
      if (!name.endsWith('.mjs')) continue
      for (const f of faults(readFileSync(new URL(`${dir.name}/${name}`, TESTS), 'utf8'), `${dir.name}/${name}`)) offenders.push(`${dir.name}/${name} ${f}`)
    }
  }
  assert.deepEqual(offenders, [])
})
