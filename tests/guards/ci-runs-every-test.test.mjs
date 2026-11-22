// Every test file runs in CI: the test job's glob takes all but tests/meta/, and each tests/meta/ file is in exactly one
// of the twins matrices, the every-run one or the nightly one (alone or in a group run one after another). A new suite
// or harness cannot be left out unnoticed.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync, globSync, mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const ROOT = new URL('../../', import.meta.url).pathname
// Search every depth, unlike the CI suite glob, so an unrun nested test fails this guard.
const ALL_TEST_GLOB = 'tests/**/*.test.mjs'
const workflow = readFileSync(new URL('../../.github/workflows/test.yml', import.meta.url), 'utf8')
// The text of one job: from its key to the next job's.
const job = (name) => workflow.slice(workflow.indexOf(`\n  ${name}:\n`)).split(/\n  (?=[a-z][\w-]*:\n)/)[1]

test('the test job runs every suite outside tests/meta/, and the twins job every harness in it', () => {
  assert.match(workflow, /"tests\/!\(meta\)\/\*\.test\.mjs"/)
  const all = globSync(ALL_TEST_GLOB, { cwd: ROOT }).sort()
  const main = globSync('tests/!(meta)/*.test.mjs', { cwd: ROOT })
  const meta = readdirSync(ROOT + 'tests/meta').filter((f) => f.endsWith('.test.mjs'))
  assert.equal(main.length + meta.length, all.length)
  const twins = [job('twins'), job('twins-nightly')]
  const listed = twins.flatMap((j) => [...j.matchAll(/tests\/meta\/([\w-]+\.test\.mjs)/g)].map((m) => m[1])).sort()
  assert.deepEqual(listed, [...meta].sort(), 'each harness in one twins matrix exactly once')
  for (const j of twins) assert.match(j, /node --test --test-concurrency=1 \$\{\{ matrix\.suite \}\}/)
  assert.doesNotMatch(job('twins'), /\n {4}if:/, 'the every-run twins run on every event')
  assert.match(job('twins-nightly'), /\n {4}if: github\.event_name == 'schedule' \|\| github\.event_name == 'workflow_dispatch'\n/)
  assert.ok(meta.length >= 11)
})

// Regression for scenario 146: the inventory, unlike the CI runner, must include files
// both directly under tests/ and more than one directory beneath it.
test('test inventory sees root-level and deeply nested suites', () => {
  const dir = mkdtempSync(join(tmpdir(), 'muid-test-inventory-'))
  try {
    mkdirSync(join(dir, 'tests/guards/deeper'), { recursive: true })
    for (const name of ['tests/direct.test.mjs', 'tests/guards/top.test.mjs', 'tests/guards/deeper/hidden.test.mjs']) {
      writeFileSync(join(dir, name), '')
    }
    assert.deepEqual(globSync(ALL_TEST_GLOB, { cwd: dir }).sort(), [
      'tests/direct.test.mjs',
      'tests/guards/deeper/hidden.test.mjs',
      'tests/guards/top.test.mjs',
    ].sort())
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
