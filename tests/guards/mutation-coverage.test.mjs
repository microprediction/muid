// Every core module, and every module of the relying-party adapter, the witness, the id page and the demo, is mutation-tested in CI: it has a Stryker config of its own, and that config is in the
// workflow's mutation matrix exactly once (alone or in a group, every member run). A new module cannot skip the gate unnoticed.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync } from 'node:fs'

const ROOT = new URL('../../', import.meta.url)
const modules = ['src', 'adapter', 'witness', 'id', 'demo'].flatMap((d) => readdirSync(new URL(`${d}/`, ROOT)).filter((f) => f.endsWith('.js')).map((f) => `${d}/${f}`)).sort()
const configs = readdirSync(ROOT).filter((f) => /^stryker(\.[a-z0-9]+)?\.config\.json$/.test(f))
const workflow = readFileSync(new URL('.github/workflows/test.yml', ROOT), 'utf8')

test('every module under src/, adapter/, witness/, id/ and demo/ is mutated by exactly one Stryker config', () => {
  assert.ok(modules.length >= 5)
  const mutated = configs.flatMap((c) => JSON.parse(readFileSync(new URL(c, ROOT), 'utf8')).mutate)
  assert.deepEqual([...mutated].sort(), modules)
})

test('every Stryker config runs in the CI mutation matrix, with the break threshold', () => {
  const mutation = workflow.slice(workflow.indexOf('\n  mutation:\n'))
  const listed = [...mutation.matchAll(/stryker(?:\.[a-z0-9]+)?\.config\.json/g)].map((m) => m[0]).sort()
  assert.deepEqual(listed, [...configs].sort(), 'each config in the mutation matrix exactly once')
  for (const c of configs) {
    const { thresholds } = JSON.parse(readFileSync(new URL(c, ROOT), 'utf8'))
    assert.ok(thresholds.break >= 95, `${c}: break threshold ${thresholds.break}`)
  }
  // Every config of a group runs, whatever an earlier one did, and any one failing fails the job.
  assert.match(mutation, /for c in \$\{\{ matrix\.config \}\}; do npx --no-install stryker run "\$c" \|\| status=1; done\n\s+exit \$status\n/)
})
