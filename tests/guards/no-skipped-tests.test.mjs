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

const BANNED = /\b(?:test|it|describe|suite)\s*\.\s*(?:skip|todo|only)\b|\b(?:skip|todo|only)\s*:\s*(?:true|['"`])/

test('no test is skipped, todo or exclusive', () => {
  const offenders = files(ROOT)
    .filter((p) => relative(ROOT, p) !== SELF)
    .filter((p) => BANNED.test(readFileSync(p, 'utf8')))
  assert.deepEqual(offenders.map((p) => relative(ROOT, p)), [])
})

test('the pattern catches what it is meant to catch', () => {
  for (const s of ['test.skip(', 'it.only(', 'describe.todo(', "{ skip: 'why' }", '{ todo: true }', 'test . skip (']) {
    assert.ok(BANNED.test(s), s)
  }
  for (const s of ['skipped', 'const only = 1', 'todoList', '{ skip: false }']) {
    assert.ok(!BANNED.test(s), s)
  }
})
