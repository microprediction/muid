// The committed CAVP vectors are byte-for-byte the files recorded in SOURCE.md, and nothing else is in the set.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync } from 'node:fs'
import { createHash } from 'node:crypto'

const DIR = new URL('../vectors/cavp-sha256/', import.meta.url)

test('every vector file matches its recorded SHA-256, and no file is unlisted', () => {
  const block = readFileSync(new URL('SOURCE.md', DIR), 'utf8').split('```')[1]
  const recorded = new Map(block.trim().split('\n').map((line) => line.trim().split(/\s+/).reverse()))
  assert.equal(recorded.size, 2)
  assert.deepEqual(readdirSync(DIR).filter((f) => f !== 'SOURCE.md').sort(), [...recorded.keys()].sort())
  for (const [file, hash] of recorded) {
    assert.equal(createHash('sha256').update(readFileSync(new URL(file, DIR))).digest('hex'), hash, file)
  }
})
