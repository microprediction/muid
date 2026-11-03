// Every test file runs in CI: the test job's glob takes all but tests/meta/, and each tests/meta/ file is in the twins
// matrix. A new suite or harness cannot be left out unnoticed.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync, globSync } from 'node:fs'

const ROOT = new URL('../../', import.meta.url).pathname
const workflow = readFileSync(new URL('../../.github/workflows/test.yml', import.meta.url), 'utf8')

test('the test job runs every suite outside tests/meta/, and the twins job every harness in it', () => {
  assert.match(workflow, /"tests\/!\(meta\)\/\*\.test\.mjs"/)
  const all = globSync('tests/*/*.test.mjs', { cwd: ROOT }).sort()
  const main = globSync('tests/!(meta)/*.test.mjs', { cwd: ROOT })
  const meta = readdirSync(ROOT + 'tests/meta').filter((f) => f.endsWith('.test.mjs'))
  assert.equal(main.length + meta.length, all.length)
  for (const f of meta) assert.match(workflow, new RegExp(`^\\s+- ${f.replace(/\./g, '\\.')}$`, 'm'), `${f} is in the twins matrix`)
  assert.match(workflow, /node --test "tests\/meta\/\$\{\{ matrix\.suite \}\}"/)
  assert.ok(meta.length >= 11)
})
