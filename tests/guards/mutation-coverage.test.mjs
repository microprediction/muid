// Every core module, and every module of the relying-party adapter, the witness, the id page and the demo, is mutation-tested in CI: it has a Stryker config of its own, and that config is in exactly one of
// the CI mutation jobs (tests/mutation-plan.mjs), alone or in a group, every member run. A new module cannot skip the gate unnoticed.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync } from 'node:fs'
import { JOBS } from '../mutation-plan.mjs'

const ROOT = new URL('../../', import.meta.url)
const modules = ['src', 'adapter', 'witness', 'id', 'demo'].flatMap((d) => readdirSync(new URL(`${d}/`, ROOT)).filter((f) => f.endsWith('.js')).map((f) => `${d}/${f}`)).sort()
const configs = readdirSync(ROOT).filter((f) => /^stryker(\.[a-z0-9-]+)?\.config\.json$/.test(f))
const read = (c) => JSON.parse(readFileSync(new URL(c, ROOT), 'utf8'))
const workflow = readFileSync(new URL('.github/workflows/test.yml', ROOT), 'utf8')

test('every module under src/, adapter/, witness/, id/ and demo/ is mutated by exactly one Stryker config', () => {
  assert.ok(modules.length >= 5)
  const mutated = configs.flatMap((c) => read(c).mutate)
  assert.deepEqual([...mutated].sort(), modules)
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

test('the plan job takes every config except on a pull request, which it diffs against the base it merges into', () => {
  const plan = workflow.slice(workflow.indexOf('\n  plan:\n'), workflow.indexOf('\n  mutation:\n'))
  assert.match(plan, /fetch-depth: 2 /)
  assert.match(plan, /if \[ "\$GITHUB_EVENT_NAME" = pull_request \]; then\n\s+git diff --name-only --no-renames HEAD\^1 HEAD > "\$RUNNER_TEMP\/changed\.txt"\n\s+jobs=\$\(node tests\/mutation-plan\.mjs "\$RUNNER_TEMP\/changed\.txt"\)\n\s+else\n\s+jobs=\$\(node tests\/mutation-plan\.mjs\)\n/)
  assert.match(workflow, /\n {2}schedule:\n {4}- cron: /)
})

test('a config that names its test files one by one names every test file of its directory', () => {
  for (const c of configs) {
    const files = read(c).tap.testFiles
    if (files.some((f) => f.includes('*'))) continue
    const dirs = [...new Set(files.map((f) => f.slice(0, f.lastIndexOf('/') + 1)))]
    const all = dirs.flatMap((d) => readdirSync(new URL(d, ROOT)).filter((f) => f.endsWith('.test.mjs')).map((f) => d + f))
    // The demo's end-to-end scenarios (D1) run the Go log, which the mutation jobs do not install.
    const expected = all.filter((f) => f !== 'tests/demo/D1-scenarios.test.mjs')
    assert.deepEqual([...files].sort(), expected.sort(), c)
  }
})
