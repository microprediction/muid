// tests/mutation-plan.mjs: a pull request runs the quick mutation configs whose inputs it changes, and no other; a
// push runs every quick config; the nightly run every config.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { writeFileSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { JOBS, EVERY_RUN, NIGHTLY, plan, select, inputs, reach, references, touches } from '../mutation-plan.mjs'

const ROOT = fileURLToPath(new URL('../../', import.meta.url))
const ALL = JOBS.map((j) => j.join(' '))
const configs = (jobs) => jobs.flatMap((j) => j.split(' ')).sort()
const only = (...cs) => [...cs].sort()

test('the nightly run takes every job; a push the quick job whole; a pull request the quick configs it affects', () => {
  assert.deepEqual(plan(null, { nightly: true }), ALL)
  assert.deepEqual(plan(['README.md'], { nightly: true }), ALL)
  assert.deepEqual(plan(null), [EVERY_RUN.join(' ')])
  assert.deepEqual(plan(['README.md']), [])
  assert.deepEqual(plan(['src/bytes.js']), [EVERY_RUN.join(' ')])
  assert.deepEqual(plan(['id/page.js']), ['stryker.id-records.config.json stryker.id-store.config.json'])
  assert.deepEqual(plan(['stryker.id-page.config.json']), [])
  assert.deepEqual(JOBS, [...NIGHTLY, EVERY_RUN])
})

test('selection: with no list of changes, every job', () => {
  assert.deepEqual(select(null), ALL)
})

test('selection: a change that no config reads selects nothing', () => {
  assert.deepEqual(select([]), [])
  assert.deepEqual(select(['README.md', 'SPEC.md', 'research/delegation.md', 'tests/guards/core-bans.test.mjs', '.github/workflows/scan.yml']), [])
})

test('selection: a change to package files, the workflow or the plan selects every job', () => {
  for (const f of ['package.json', 'package-lock.json', '.github/workflows/test.yml', 'tests/mutation-plan.mjs']) assert.deepEqual(select([f]), ALL, f)
})

test('selection: a core module is read by every suite but the storage adapter\'s, so a change to one selects every other config', () => {
  // The adapter's tests are served src/ with the page but import nothing of the core (tests/impl.mjs).
  const others = ALL.map((j) => j.split(' ').filter((c) => c !== 'stryker.id-store.config.json').join(' '))
  assert.deepEqual(select(['tests/impl.mjs']), others)
  assert.deepEqual(select(['src/bytes.js']), ALL, 'served to the adapter\'s tests with the page')
})

test('selection: a change to the id page selects the configs whose tests load it, and only those', () => {
  const ids = ['stryker.id-page.config.json', 'stryker.id-records.config.json']
  const store = 'stryker.id-store.config.json'
  // The demo's tests load id/ too (tests/id/impl.mjs), but not the page tests or their server. The storage adapter's
  // tests are served id/ by the page tests' server, and read none of the page's tests.
  for (const f of ['id/page.js', 'id/store.js', 'id/index.html', 'id/page.css', 'id/new.js']) assert.deepEqual(configs(select([f])), only(...ids, store, 'stryker.demo.config.json'), f)
  assert.deepEqual(configs(select(['tests/id/P2-page.test.mjs'])), only(...ids))
  assert.deepEqual(configs(select(['tests/id/serve.mjs'])), only(...ids, store))
  assert.deepEqual(configs(select(['tests/store/ST1-store.test.mjs'])), [store])
  assert.deepEqual(configs(select(['stryker.id-page.config.json'])), ['stryker.id-page.config.json'])
})

test('what a suite reaches from another directory counts: helpers, fixtures, models and vectors', () => {
  assert.ok(inputs('stryker.id-page.config.json').includes('tests/witness/fixtures.mjs'))
  assert.ok(inputs('stryker.id-page.config.json').includes('witness/service.js'))
  assert.ok(inputs('stryker.membership.config.json').includes('model/recovery.mjs'))
  assert.ok(inputs('stryker.config.json').some((f) => f.startsWith('tests/vectors/jcs/input/')))
  assert.ok(configs(select(['tests/vectors/c2sp-note/anything'])).includes('stryker.note.config.json'))
  assert.ok(!configs(select(['tests/vectors/c2sp-note/anything'])).includes('stryker.id-page.config.json'))
  // A deleted file a suite still names is a change to that suite's inputs.
  assert.ok(configs(select(['tests/witness/fixtures.mjs'])).includes('stryker.id-page.config.json'))
})

test('references: quoted and template paths, directories, and a template cut at its first substitution', () => {
  const at = join(ROOT, 'tests/x/f.mjs')
  const text = "import a from '../impl.mjs'\nnew URL('../../id/', u)\nreadFileSync(new URL(`../vectors/jcs/input/${n}.json`, u))\nimport 'node:fs'\nimport b from './h.mjs'\nconst s = '../../'\nnew URL(`./v${n}`, u)\n"
  assert.deepEqual(references(at, text), [join(ROOT, 'tests/impl.mjs'), join(ROOT, 'id/'), join(ROOT, 'tests/vectors/jcs/input/'), join(ROOT, 'tests/x/h.mjs'), ROOT, join(ROOT, 'tests/x/')])
})

test('a file that names the repository itself reaches everything, so every job runs for any change', () => {
  // This guard names the repository root ('../../') to find the configs.
  assert.deepEqual(reach(['tests/guards/mutation-coverage.test.mjs']), ['*'])
  assert.deepEqual(reach(['tests/x/missing.mjs']), ['tests/x/missing.mjs'])
  assert.equal(touches('*', ['README.md']), true)
  assert.equal(touches('id/', ['id/new.js']), true)
  assert.equal(touches('id/', ['idx/page.js']), false)
  assert.equal(touches('id/page.js', ['id/page.js.orig']), false)
})

test('the command prints the jobs: the quick job, the quick configs the listed changes affect, or every job', () => {
  const dir = mkdtempSync(join(tmpdir(), 'muid-plan-'))
  try {
    const run = (...args) => JSON.parse(execFileSync(process.execPath, [join(ROOT, 'tests/mutation-plan.mjs'), ...args], { encoding: 'utf8' }))
    assert.deepEqual(run(), [EVERY_RUN.join(' ')])
    assert.deepEqual(run('--nightly'), ALL)
    writeFileSync(join(dir, 'changed.txt'), 'README.md\nid/page.js\n')
    assert.deepEqual(run(join(dir, 'changed.txt')), ['stryker.id-records.config.json stryker.id-store.config.json'])
    writeFileSync(join(dir, 'changed.txt'), 'README.md\n')
    assert.deepEqual(run(join(dir, 'changed.txt')), [])
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
