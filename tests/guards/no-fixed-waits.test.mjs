// R3: a check that something did not happen waits for something observable (idle, an answer counted, a message
// heard), not for a time a slow machine may outrun. Playwright's waitForTimeout is such a time, so no test uses it.
// (A poll of a condition, as idle and until do, waits on the condition, with the test's timeout as its only limit.)
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'

const ROOT = new URL('..', import.meta.url).pathname
const SELF = relative(ROOT, new URL(import.meta.url).pathname)
const BANNED = /\bwaitForTimeout\b/

function files (dir) {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name)
    if (statSync(p).isDirectory()) return files(p)
    return /\.(m?js)$/.test(name) ? [p] : []
  })
}

test('no test waits for a fixed time', () => {
  const offenders = files(ROOT)
    .filter((p) => relative(ROOT, p) !== SELF)
    .filter((p) => BANNED.test(readFileSync(p, 'utf8')))
  assert.deepEqual(offenders.map((p) => relative(ROOT, p)), [])
})

test('the pattern catches what it is meant to catch', () => {
  for (const s of ['await page.waitForTimeout(500)', 'p.waitForTimeout (1)', 'page["waitForTimeout"](9)']) assert.equal(BANNED.test(s), true, s)
  for (const s of ['await page.waitForFunction(() => true)', 'waitForTimeouts', 'await idle(page)']) assert.equal(BANNED.test(s), false, s)
})
