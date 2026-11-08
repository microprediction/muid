// Every test file runs in CI: the test job's glob takes all but tests/meta/, and each tests/meta/ file is in the twins
// matrix exactly once (alone or in a group run one after another). A new suite or harness cannot be left out unnoticed.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync, globSync } from 'node:fs'

const ROOT = new URL('../../', import.meta.url).pathname
const workflow = readFileSync(new URL('../../.github/workflows/test.yml', import.meta.url), 'utf8')
// The text of one job: from its key to the next job's.
const job = (name) => workflow.slice(workflow.indexOf(`\n  ${name}:\n`)).split(/\n  (?=[a-z][\w-]*:\n)/)[1]

test('the test job runs every suite outside tests/meta/, and the twins job every harness in it', () => {
  assert.match(workflow, /"tests\/!\(meta\)\/\*\.test\.mjs"/)
  const all = globSync('tests/*/*.test.mjs', { cwd: ROOT }).sort()
  const main = globSync('tests/!(meta)/*.test.mjs', { cwd: ROOT })
  const meta = readdirSync(ROOT + 'tests/meta').filter((f) => f.endsWith('.test.mjs'))
  assert.equal(main.length + meta.length, all.length)
  const twins = job('twins')
  const listed = [...twins.matchAll(/tests\/meta\/([\w-]+\.test\.mjs)/g)].map((m) => m[1]).sort()
  assert.deepEqual(listed, [...meta].sort(), 'each harness in the twins matrix exactly once')
  assert.match(twins, /node --test --test-concurrency=1 \$\{\{ matrix\.suite \}\}/)
  assert.ok(meta.length >= 11)
})
