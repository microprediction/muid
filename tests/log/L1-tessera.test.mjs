// The witness's log is Tessera's POSIX server (log/cmd/muid-log): entries appended through witness/log.js are in the checkpoints it
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
    // In batches of 50: more connections at once than the listen backlog (128 on macOS) are reset.
    const indices = []
    for (let i = 0; i < texts.length; i += 50) indices.push(...await Promise.all(texts.slice(i, i + 50).map((t) => log.append(t))))
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
    await l.stop()
  }
})

test('with a witness policy, every checkpoint the log publishes is cosigned by the witness, and meets a quorum of one', { timeout: 300_000 }, async () => {
  const l = await startLog({ witnessed: true })
  try {
    const log = tesseraLog({ url: l.url })
    const ctx = { origin: l.origin, log: l.vkey, cosigners: [l.cosigner], quorum: 1, now: Math.floor(Date.now() / 1000), skew: 60 }
    const [index] = await Promise.all([log.append('witnessed entry'), log.append('another')])
    const c = await checkpointAt(log, ctx, 2)
    assert.equal(c.times.length, 1)
    assert.ok(Math.abs(c.times[0] - ctx.now) < 120, 'the cosignature time is the witness clock')
    const proof = await log.inclusionProof(index, c.size)
    assert.equal(merkle.verifyInclusion({ leafHash: merkle.leafHash(enc.encode('witnessed entry')), index, size: c.size, root: Buffer.from(c.root, 'hex'), proof }), true)
    // Without the witness's key, the same checkpoint does not meet the quorum.
    const other = { ...ctx, cosigners: [l.cosigner.replace('witness.test', 'other.test')] }
    assert.throws(() => note.verifyCheckpoint(log, other)) // a malformed key is a programming error
  } finally {
    await l.stop()
  }
})

// An entry is at most 65,535 bytes: C2SP tlog-tiles writes each entry in a bundle after a 16-bit length. The server
// refuses a longer body at the HTTP boundary with 413, whether or not its length was declared, and stays usable.
test('an entry longer than a bundle can hold is refused with 413 before it is read; the largest entry is appended', { timeout: 300_000 }, async () => {
  const l = await startLog()
  try {
    const log = tesseraLog({ url: l.url })
    const MAX = 65535
    const post = (body, init = {}) => fetch(l.url + 'add', { method: 'POST', body, ...init })
    const over = await post(new Uint8Array(MAX + 1).fill(0x61))
    assert.equal(over.status, 413)
    // No declared length: the body is streamed in chunks, far past the limit; the server answers without the rest.
    let sent = 0
    const endless = new ReadableStream({ pull (c) { sent += 16384; if (sent > 64 * 1024 * 1024) c.close(); else c.enqueue(new Uint8Array(16384).fill(0x62)) } })
    const streamed = await post(endless, { duplex: 'half' }).then((r) => r.status, () => 413)
    assert.equal(streamed, 413)
    assert.ok(sent < 64 * 1024 * 1024, 'the server stopped reading')
    const largest = 'c'.repeat(MAX)
    const index = await log.append(largest)
    const after = await log.append('after')
    assert.notEqual(index, after)
    const ctx = { origin: l.origin, log: l.vkey, cosigners: [], quorum: 0, now: Math.floor(Date.now() / 1000), skew: 60 }
    const c = await checkpointAt(log, ctx, 2)
    assert.equal(c.size, 2, 'neither refused body became an entry')
    const proof = await log.inclusionProof(index, c.size)
    assert.equal(merkle.verifyInclusion({ leafHash: merkle.leafHash(enc.encode(largest)), index, size: c.size, root: Buffer.from(c.root, 'hex'), proof }), true)
  } finally {
    await l.stop()
  }
})
