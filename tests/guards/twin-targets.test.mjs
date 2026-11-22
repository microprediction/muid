// The id page's twins and the witness's run only nightly (tests/meta), so a change to code one of them targets would
// go unnoticed until then, failing every nightly run. Each harness is run here as far as making its twins, which
// checks that every target occurs exactly once, and runs none of them.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const ROOT = fileURLToPath(new URL('../../', import.meta.url))
const { NODE_TEST_CONTEXT, ...env } = process.env

for (const harness of ['tests/meta/id-twins.test.mjs', 'tests/meta/witness-twins.test.mjs']) {
  test(`every twin of ${harness} finds its targets, each exactly once`, () => {
    const r = spawnSync(process.execPath, ['--test', '--test-reporter=tap', harness], { cwd: ROOT, env: { ...env, MUID_TWIN_TARGETS_ONLY: '1' }, encoding: 'utf8' })
    assert.equal(r.status, 0, r.stdout + r.stderr)
    assert.match(r.stdout, /^# pass 1$/m)
  })
}
