// Every vector set under tests/vectors/ is pinned: a SOURCE.md whose SHA-256 block lists exactly the files present,
// each with its hash. A file added, edited or left unlisted fails here.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { join, relative } from 'node:path'

const ROOT = new URL('../vectors/', import.meta.url).pathname

function listFiles (dir) {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name)
    return statSync(p).isDirectory() ? listFiles(p) : [p]
  })
}

const sets = readdirSync(ROOT).filter((name) => statSync(join(ROOT, name)).isDirectory()).sort()

test('the vector sets are the expected ones', () => {
  assert.deepEqual(sets, ['cavp-sha256', 'ed25519-speccheck', 'jcs', 'rfc8032', 'webauthn-l3', 'wycheproof'])
})

for (const set of sets) {
  test(`${set}: every file is listed in SOURCE.md with a matching SHA-256`, () => {
    const dir = join(ROOT, set)
    assert.ok(existsSync(join(dir, 'SOURCE.md')), 'SOURCE.md exists')
    const blocks = readFileSync(join(dir, 'SOURCE.md'), 'utf8').split('```')
    const block = blocks[blocks.length - 2]
    const recorded = new Map(block.trim().split('\n').map((line) => line.trim().split(/\s+/).reverse()))
    const present = listFiles(dir).map((p) => relative(dir, p)).filter((p) => p !== 'SOURCE.md').sort()
    assert.deepEqual(present, [...recorded.keys()].sort())
    for (const [path, hash] of recorded) {
      assert.match(hash, /^[0-9a-f]{64}$/)
      assert.equal(createHash('sha256').update(readFileSync(join(dir, path))).digest('hex'), hash, path)
    }
  })
}
