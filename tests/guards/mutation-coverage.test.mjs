// Every core module is mutation-tested in CI: it has a Stryker config of its own, and that config is in the
// workflow's mutation matrix. A new module cannot skip the gate unnoticed.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync } from 'node:fs'

const ROOT = new URL('../../', import.meta.url)
const modules = readdirSync(new URL('src/', ROOT)).filter((f) => f.endsWith('.js')).map((f) => `src/${f}`).sort()
const configs = readdirSync(ROOT).filter((f) => /^stryker(\.[a-z0-9]+)?\.config\.json$/.test(f))
const workflow = readFileSync(new URL('.github/workflows/test.yml', ROOT), 'utf8')

test('every module under src/ is mutated by exactly one Stryker config', () => {
  assert.ok(modules.length >= 5)
  const mutated = configs.flatMap((c) => JSON.parse(readFileSync(new URL(c, ROOT), 'utf8')).mutate)
  assert.deepEqual([...mutated].sort(), modules)
})

test('every Stryker config runs in the CI mutation matrix, with the break threshold', () => {
  for (const c of configs) {
    assert.match(workflow, new RegExp(`^\\s+- ${c.replace(/\./g, '\\.')}$`, 'm'), `${c} is in the matrix`)
    const { thresholds } = JSON.parse(readFileSync(new URL(c, ROOT), 'utf8'))
    assert.ok(thresholds.break >= 95, `${c}: break threshold ${thresholds.break}`)
  }
  assert.match(workflow, /stryker run \$\{\{ matrix\.config \}\}/)
})
