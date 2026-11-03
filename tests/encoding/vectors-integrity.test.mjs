// The committed RFC 8785 vectors are byte-for-byte the files recorded in SOURCE.md, and nothing else is in the set.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { join, relative } from 'node:path'

const DIR = new URL('../vectors/jcs/', import.meta.url).pathname

function listFiles (dir) {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name)
    return statSync(p).isDirectory() ? listFiles(p) : [p]
  })
}

test('every vector file matches the SHA-256 recorded in SOURCE.md, and no file is unlisted', () => {
  const source = readFileSync(join(DIR, 'SOURCE.md'), 'utf8')
  const block = source.split('```')[1]
  const recorded = new Map(
    block.trim().split('\n').map((line) => {
      const [hash, path] = line.trim().split(/\s+/)
      return [path, hash]
    }),
  )
  assert.equal(recorded.size, 19, 'SOURCE.md lists 19 files')

  const present = listFiles(DIR).map((p) => relative(DIR, p)).filter((p) => p !== 'SOURCE.md').sort()
  assert.deepEqual(present, [...recorded.keys()].sort(), 'files on disk are exactly the listed files')

  for (const [path, hash] of recorded) {
    const actual = createHash('sha256').update(readFileSync(join(DIR, path))).digest('hex')
    assert.equal(actual, hash, `hash of ${path}`)
  }
})
