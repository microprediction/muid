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
  /\b(?:skip|todo|only)\s*:\s*(?!false(?=\s*[,}]))\S/,
  /\b(?:t|ctx)\s*\.\s*(?:skip|todo)\s*\(/,
]
const banned = (source) => BANNED.some((re) => re.test(source))

test('no test is skipped, todo or exclusive', () => {
  const offenders = files(ROOT)
    .filter((p) => relative(ROOT, p) !== SELF)
    .filter((p) => banned(readFileSync(p, 'utf8')))
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
  for (const s of ['skipped', 'const only = 1', 'todoList', '{ skip: false }', '{ todo: false }', '{ only: false }']) {
    assert.ok(!banned(s), s)
  }
})
