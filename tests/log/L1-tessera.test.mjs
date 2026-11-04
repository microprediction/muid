// The witness's log is Tessera's own POSIX server: entries appended through witness/log.js are in the checkpoints it
// signs, which the core's verifyCheckpoint accepts under the log's key, and an inclusion proof built from its tiles
// verifies under the core's verifyInclusion for every entry, across a tile boundary and a level-1 tile.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { note, merkle } from '../impl.mjs'
import { tesseraLog } from '../witness/impl.mjs'
import { startLog } from './tessera.mjs'

const enc = new TextEncoder()

async function checkpointAt (log, ctx, size) {
  for (let i = 0; i < 300; i++) {
    const c = note.verifyCheckpoint(await log.checkpoint(), ctx)
    assert.equal(c.ok, true, JSON.stringify(c))
    if (c.size >= size) return c
    await new Promise((resolve) => setTimeout(resolve, 100))
  }
  throw new Error(`no checkpoint of size ${size}`)
}

test('entries appended to Tessera are proved in its checkpoints, from its tiles', { timeout: 300_000 }, async () => {
  const l = await startLog()
  try {
    const log = tesseraLog({ url: l.url })
    const ctx = { origin: l.origin, log: l.vkey, cosigners: [], quorum: 0, now: Math.floor(Date.now() / 1000), skew: 60 }
    const first = await checkpointAt(log, ctx, 0)
    assert.equal(first.size, 0)
    // 300 entries: a full level-0 tile, a partial one, and one hash in a level-1 tile.
    const texts = Array.from({ length: 300 }, (_, i) => `entry ${i}`)
    const indices = await Promise.all(texts.map((t) => log.append(t)))
    assert.deepEqual([...indices].sort((a, b) => a - b), texts.map((_, i) => i))
    const c = await checkpointAt(log, ctx, 300)
    assert.equal(c.size, 300)
    for (let i = 0; i < texts.length; i++) {
      const proof = await log.inclusionProof(indices[i], c.size)
      const ok = merkle.verifyInclusion({ leafHash: merkle.leafHash(enc.encode(texts[i])), index: indices[i], size: c.size,
        root: Buffer.from(c.root, 'hex'), proof })
      assert.equal(ok, true, `entry ${i} at ${indices[i]}`)
    }
    // A later checkpoint proves the same entries; a proof for another entry's hash does not verify.
    const more = await Promise.all(Array.from({ length: 21 }, (_, i) => log.append(`more ${i}`)))
    assert.equal(more.length, 21)
    const d = await checkpointAt(log, ctx, 321)
    const proof = await log.inclusionProof(indices[7], d.size)
    const at = (t) => merkle.verifyInclusion({ leafHash: merkle.leafHash(enc.encode(t)), index: indices[7], size: d.size, root: Buffer.from(d.root, 'hex'), proof })
    assert.equal(at(texts[7]), true)
    assert.equal(at(texts[8]), false)
  } finally {
    l.stop()
  }
})
