// Every core module, and every module of the relying-party adapter, the worker's side, the witness, the id page and the demo, is mutation-tested in CI: it has a Stryker config of its own, and that config is in exactly one of
// the CI mutation jobs (tests/mutation-plan.mjs), alone or in a group, every member run. A new module cannot skip the gate unnoticed.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync, mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { Instrumenter } from '@stryker-mutator/instrumenter'
import { JOBS, mutated as fileOf } from '../mutation-plan.mjs'

const ROOT = new URL('../../', import.meta.url)
// Include files in subdirectories too: otherwise a new module can evade every mutation config and this guard.
function modulesIn (dir, root = ROOT) {
  function walk (relative) {
    return readdirSync(new URL(`${relative}/`, root), { withFileTypes: true }).flatMap((entry) => {
      const path = `${relative}/${entry.name}`
      return entry.isDirectory() ? walk(path) : (entry.name.endsWith('.js') ? [path] : [])
    })
  }
  return walk(dir)
}
const modules = ['src', 'adapter', 'worker', 'witness', 'id', 'demo'].flatMap((d) => modulesIn(d)).sort()
const configs = readdirSync(ROOT).filter((f) => /^stryker(\.[a-z0-9-]+)?\.config\.json$/.test(f))
const read = (c) => JSON.parse(readFileSync(new URL(c, ROOT), 'utf8'))
const workflow = readFileSync(new URL('.github/workflows/test.yml', ROOT), 'utf8')

test('the module inventory includes nested files that would otherwise evade mutation coverage', () => {
  const dir = mkdtempSync(join(tmpdir(), 'muid-mutation-inventory-'))
  try {
    mkdirSync(join(dir, 'src', 'nested'), { recursive: true })
    writeFileSync(join(dir, 'src', 'flat.js'), 'export const flat = true\n')
    writeFileSync(join(dir, 'src', 'nested', 'deep.js'), 'export const deep = true\n')
    writeFileSync(join(dir, 'src', 'nested', 'ignored.txt'), '')
    const found = modulesIn('src', pathToFileURL(`${dir}/`)).sort()
    assert.deepEqual(found, ['src/flat.js', 'src/nested/deep.js'])
    assert.notDeepEqual(found, ['src/flat.js'], 'a nested module with no Stryker config must not disappear')
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

// A module is mutated whole by one config, or in parts by several, each a range of its lines (`file:first-last`):
// the ranges start at line 1, each begins where the last ended, and the last runs past any length the file could have.
const OPEN_END = 99999
test('every module under src/, adapter/, worker/, witness/, id/ and demo/ is mutated by exactly one Stryker config, or by configs whose line ranges are the whole of it', () => {
  assert.ok(modules.length >= 5)
  const entries = configs.flatMap((c) => read(c).mutate)
  const whole = entries.filter((e) => fileOf(e) === e)
  const parts = entries.filter((e) => fileOf(e) !== e)
  const inParts = [...new Set(parts.map(fileOf))]
  assert.deepEqual([...whole, ...inParts].sort(), modules)
  for (const f of inParts) {
    const ranges = parts.filter((e) => fileOf(e) === f).map((e) => e.slice(f.length + 1).split('-').map(Number)).sort((a, b) => a[0] - b[0])
    assert.ok(ranges.length >= 2, f)
    assert.equal(ranges[0][0], 1, `${f}: from line 1`)
    for (let i = 1; i < ranges.length; i++) assert.equal(ranges[i][0], ranges[i - 1][1] + 1, `${f}: no line left out or taken twice`)
    assert.equal(ranges.at(-1)[1], OPEN_END, `${f}: to the end`)
    assert.ok(readFileSync(new URL(f, ROOT), 'utf8').split('\n').length < OPEN_END, f)
  }
})

// Stryker mutates a node only if one range holds all of it, so a node across a boundary is mutated by no part.
// Every mutant Stryker makes of a module in parts, by Stryker's own instrumenter, is held by one part; but one
// holding a whole part (the body of a function a part lies inside) can be held by none, and is left.
const holds = ([first, last], { start, end }) => first <= start.line + 1 && end.line + 1 <= last
const quiet = { isDebugEnabled: () => false, isTraceEnabled: () => false, debug () {}, trace () {}, info () {}, warn () {}, error () {} }
async function mutantsOf (file) {
  const content = readFileSync(new URL(file, ROOT), 'utf8')
  const { mutants } = await new Instrumenter(quiet).instrument([{ name: file, content, mutate: true }], { plugins: null, excludedMutations: [], ignorers: [], noHeader: true })
  return mutants
}
const unheld = (mutants, ranges) => mutants.filter((m) => !ranges.some((r) => holds(r, m.location)) &&
  !ranges.some(([first, last]) => m.location.start.line + 1 < first && last < m.location.end.line + 1))
// A part is a CI job, which must end within its 150 minutes. Measured in the nightly run, a mutant of the page took
// up to 40 seconds and one of the witness about 9: so at most 210 and 500 a part.
const MOST = { 'id/page.js': 210, 'witness/witness.js': 500 }
test('every mutant of a module in parts is mutated by one part, but one holding a whole part; and no part is too long to run', async () => {
  const parts = configs.flatMap((c) => read(c).mutate).filter((e) => fileOf(e) !== e)
  const files = [...new Set(parts.map(fileOf))]
  assert.deepEqual(files.sort(), Object.keys(MOST).sort())
  for (const f of files) {
    const mutants = await mutantsOf(f)
    const ranges = parts.filter((e) => fileOf(e) === f).map((e) => e.slice(f.length + 1).split('-').map(Number))
    const left = unheld(mutants, ranges).map((m) => `${m.mutatorName} at lines ${m.location.start.line + 1}-${m.location.end.line + 1}`)
    assert.deepEqual(left, [], `${f}: in no part`)
    for (const r of ranges) {
      const n = mutants.filter((m) => !m.ignoreReason && holds(r, m.location)).length
      assert.ok(n <= MOST[f], `${f}:${r.join('-')}: ${n} mutants, more than ${MOST[f]}: divide it`)
    }
  }
  // The negative control: a boundary inside a block leaves that block's mutant in no part.
  const lines = readFileSync(new URL('id/page.js', ROOT), 'utf8').split('\n')
  const inside = 1 + lines.findIndex((l) => /^async function stillHeld /.test(l))
  assert.ok(inside > 1)
  assert.notDeepEqual(unheld(await mutantsOf('id/page.js'), [[1, inside + 1], [inside + 2, OPEN_END]]), [])
})

test('every Stryker config is in exactly one CI mutation job, with the break threshold', () => {
  assert.deepEqual(JOBS.flat().sort(), [...configs].sort(), 'each config in one job exactly once')
  for (const c of configs) assert.ok(read(c).thresholds.break >= 95, `${c}: break threshold ${read(c).thresholds.break}`)
  const mutation = workflow.slice(workflow.indexOf('\n  mutation:\n'))
  assert.match(mutation, /\n {4}needs: plan\n/)
  assert.match(mutation, /config: \$\{\{ fromJSON\(needs\.plan\.outputs\.jobs\) \}\}\n/)
  // Every config of a group runs, whatever an earlier one did, and any one failing fails the job.
  assert.match(mutation, /for c in \$\{\{ matrix\.config \}\}; do npx --no-install stryker run "\$c" \|\| status=1; done\n\s+exit \$status\n/)
})

test('the plan job takes every config nightly and on demand, the quick ones on a push, and on a pull request those it affects', () => {
  const plan = workflow.slice(workflow.indexOf('\n  plan:\n'), workflow.indexOf('\n  mutation:\n'))
  assert.match(plan, /fetch-depth: 2 /)
  assert.match(plan, /case "\$GITHUB_EVENT_NAME" in\n\s+pull_request\)\n\s+git diff --name-only --no-renames HEAD\^1 HEAD > "\$RUNNER_TEMP\/changed\.txt"\n\s+jobs=\$\(node tests\/mutation-plan\.mjs "\$RUNNER_TEMP\/changed\.txt"\) ;;\n\s+schedule \| workflow_dispatch\) jobs=\$\(node tests\/mutation-plan\.mjs --nightly\) ;;\n\s+\*\) jobs=\$\(node tests\/mutation-plan\.mjs\) ;;\n\s+esac\n/)
  assert.match(workflow, /\n {2}schedule:\n {4}- cron: /)
  assert.match(workflow, /\n {2}workflow_dispatch:\n/)
})

test('a config that names its test files one by one names every test file of its directory', () => {
  for (const c of configs) {
    const files = read(c).tap.testFiles
    if (files.some((f) => f.includes('*'))) continue
    const dirs = [...new Set(files.map((f) => f.slice(0, f.lastIndexOf('/') + 1)))]
    const all = dirs.flatMap((d) => readdirSync(new URL(d, ROOT)).filter((f) => f.endsWith('.test.mjs')).map((f) => d + f))
    // The demo's end-to-end scenarios (D1) run the Go log, which the mutation jobs do not install.
    // The id records are killed by the Node tests alone, every mutant of them; the page in Chrome (P2), minutes a
    // run, is left to the page's own config.
    const left = c === 'stryker.id-records.config.json' ? ['tests/id/P2-page.test.mjs'] : []
    const expected = all.filter((f) => f !== 'tests/demo/D1-scenarios.test.mjs' && !left.includes(f))
    assert.deepEqual([...files].sort(), expected.sort(), c)
  }
})
