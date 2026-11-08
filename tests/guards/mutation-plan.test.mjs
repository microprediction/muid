// tests/mutation-plan.mjs: a pull request runs every mutation config whose inputs it changes, and no other; every
// other event runs them all.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { writeFileSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { JOBS, plan, inputs, reach, references, touches } from '../mutation-plan.mjs'

const ROOT = fileURLToPath(new URL('../../', import.meta.url))
const ALL = JOBS.map((j) => j.join(' '))
const configs = (jobs) => jobs.flatMap((j) => j.split(' ')).sort()
const only = (...cs) => [...cs].sort()

test('with no list of changes, every job runs', () => {
  assert.deepEqual(plan(null), ALL)
})

test('a change that no config reads runs no mutation job', () => {
  assert.deepEqual(plan([]), [])
  assert.deepEqual(plan(['README.md', 'SPEC.md', 'research/delegation.md', 'tests/guards/core-bans.test.mjs', '.github/workflows/scan.yml']), [])
})

test('a change to package files, the workflow or the plan runs every job', () => {
  for (const f of ['package.json', 'package-lock.json', '.github/workflows/test.yml', 'tests/mutation-plan.mjs']) assert.deepEqual(plan([f]), ALL, f)
})

test('a core module is read by every suite (through tests/impl.mjs), so a change to one runs every job', () => {
  assert.deepEqual(plan(['src/bytes.js']), ALL)
  assert.deepEqual(plan(['tests/impl.mjs']), ALL)
})

test('a change to the id page runs the configs whose tests load it, and only those', () => {
  const ids = ['stryker.id-page.config.json', 'stryker.id-records.config.json']
  // The demo's tests load id/ too (tests/id/impl.mjs), but not the page tests or their server.
  for (const f of ['id/page.js', 'id/index.html', 'id/page.css', 'id/new.js']) assert.deepEqual(configs(plan([f])), only(...ids, 'stryker.demo.config.json'), f)
  for (const f of ['tests/id/P2-page.test.mjs', 'tests/id/serve.mjs']) assert.deepEqual(configs(plan([f])), only(...ids), f)
  assert.deepEqual(configs(plan(['stryker.id-page.config.json'])), ['stryker.id-page.config.json'])
})

test('what a suite reaches from another directory counts: helpers, fixtures, models and vectors', () => {
  assert.ok(inputs('stryker.id-page.config.json').includes('tests/witness/fixtures.mjs'))
  assert.ok(inputs('stryker.id-page.config.json').includes('witness/service.js'))
  assert.ok(inputs('stryker.membership.config.json').includes('model/recovery.mjs'))
  assert.ok(inputs('stryker.config.json').some((f) => f.startsWith('tests/vectors/jcs/input/')))
  assert.ok(configs(plan(['tests/vectors/c2sp-note/anything'])).includes('stryker.note.config.json'))
  assert.ok(!configs(plan(['tests/vectors/c2sp-note/anything'])).includes('stryker.id-page.config.json'))
  // A deleted file a suite still names is a change to that suite's inputs.
  assert.ok(configs(plan(['tests/witness/fixtures.mjs'])).includes('stryker.id-page.config.json'))
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

test('the command prints the jobs: all of them, or those the listed changes affect', () => {
  const dir = mkdtempSync(join(tmpdir(), 'muid-plan-'))
  try {
    const run = (...args) => JSON.parse(execFileSync(process.execPath, [join(ROOT, 'tests/mutation-plan.mjs'), ...args], { encoding: 'utf8' }))
    assert.deepEqual(run(), ALL)
    writeFileSync(join(dir, 'changed.txt'), 'README.md\nid/page.js\n')
    assert.deepEqual(configs(run(join(dir, 'changed.txt'))), only('stryker.id-page.config.json', 'stryker.id-records.config.json', 'stryker.demo.config.json'))
    writeFileSync(join(dir, 'changed.txt'), 'README.md\n')
    assert.deepEqual(run(join(dir, 'changed.txt')), [])
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
