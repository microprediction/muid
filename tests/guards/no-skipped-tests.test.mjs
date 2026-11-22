// SPEC §12: a skipped, todo or exclusive ("only") test fails the build.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'

const ROOT = new URL('..', import.meta.url).pathname
const SELF = relative(ROOT, new URL(import.meta.url).pathname)

function files (dir) {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name)
    if (statSync(p).isDirectory()) return name === 'vectors' ? [] : files(p)
    return /\.(m?js)$/.test(name) ? [p] : []
  })
}

// A condition such as skip: process.env.CI can silently skip a failing test in CI.
// Allow only an explicit false option; an expression beginning with false may still be truthy.
const BANNED = [
  /\b(?:test|it|describe|suite)\s*\.\s*(?:skip|todo|only)\b/,
  /[{,]\s*(?:skip|todo|only)\s*:\s*(?!false(?=\s*[,}]))\S/, // an option key, not the word in a test's name
  /\b(?:t|ctx)\s*\.\s*(?:skip|todo)\s*\(/,
]
const banned = (source) => BANNED.some((re) => re.test(source))

// Only this one Chrome DevTools-dependent test is deliberately skipped in the Firefox/WebKit
// jobs (and executed in the Chrome job). The exact expression and its location are pinned.
const CHROME_SKIP = String.raw`skip: ENGINE !== 'chrome' && 'storage is cleared through Chrome\'s DevTools protocol'`
const STORE_TEST = 'store/ST1-store.test.mjs'

function forbidden (name, source) {
  if (name === STORE_TEST) {
    const parts = source.split(CHROME_SKIP)
    if (parts.length !== 2) return true // the permitted exception was removed, duplicated or changed
    source = parts.join('skip: false')
  }
  return banned(source)
}

test('no test is skipped, todo or exclusive', () => {
  const offenders = files(ROOT)
    .filter((p) => relative(ROOT, p) !== SELF)
    .filter((p) => forbidden(relative(ROOT, p), readFileSync(p, 'utf8')))
  assert.deepEqual(offenders.map((p) => relative(ROOT, p)), [])
})

test('the pattern catches what it is meant to catch', () => {
  for (const s of [
    'test.skip(', 'it.only(', 'describe.todo(', "{ skip: 'why' }", '{ todo: true }',
    'test . skip (', "test('x', { skip: process.env.CI === 'true' }, () => {})",
    "test('x', { todo: Boolean(process.env.CI) }, () => {})",
    'test("x", { skip: false || process.env.CI }, () => {})',
    "t.skip('not ready')", "ctx.todo('later')",
  ]) {
    assert.ok(banned(s), s)
  }
  for (const s of ['skipped', 'const only = 1', 'todoList', '{ skip: false }', '{ todo: false }', '{ only: false }',
    "test('a salt belongs to a membership record only: a contest is no record', () => {})"]) {
    assert.ok(!banned(s), s)
  }
})

test('the only permitted conditional skip is the pinned Chrome-specific one', () => {
  assert.equal(forbidden(STORE_TEST, `test('x', { ${CHROME_SKIP} }, () => {})`), false)
  assert.equal(forbidden('id/P2-page.test.mjs', `test('x', { ${CHROME_SKIP} }, () => {})`), true)
  assert.equal(forbidden(STORE_TEST, `test('x', { ${CHROME_SKIP}, skip: process.env.CI }, () => {})`), true)
  assert.equal(forbidden(STORE_TEST, "test('x', { skip: false }, () => {})"), true)
})
