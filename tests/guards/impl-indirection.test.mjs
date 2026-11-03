// TESTING.md §5: tests reach the implementation only through tests/impl.mjs, so a broken twin swapped in there
// replaces it everywhere. A direct import of src/ would silently bypass the twin.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'

const ROOT = new URL('..', import.meta.url).pathname

function files (dir) {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name)
    if (statSync(p).isDirectory()) return name === 'vectors' || name === 'twins' ? [] : files(p)
    return /\.(m?js)$/.test(name) ? [p] : []
  })
}

test('no test file imports src/ directly', () => {
  const all = files(ROOT)
  assert.ok(all.length >= 15, `found ${all.length} test files`)
  const offenders = all
    .filter((p) => relative(ROOT, p) !== 'impl.mjs')
    .filter((p) => /(?:from|import)\s*\(?\s*['"][^'"]*\/src\//.test(readFileSync(p, 'utf8')))
  assert.deepEqual(offenders.map((p) => relative(ROOT, p)), [])
})
