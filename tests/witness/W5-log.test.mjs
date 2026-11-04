// witness/log.js against a log laid out from the C2SP tlog-tiles wording by this test (tests/log/ runs it against
// Tessera itself): proofs equal RFC 9162's PATH for every entry of trees of many sizes, partial tiles and their
// fallback, and every failure of the server refused.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { tesseraLog, tileIndex } from './impl.mjs'

const sha = (...parts) => new Uint8Array(createHash('sha256').update(Buffer.concat(parts.map((p) => Buffer.from(p)))).digest())
const LEAF = (d) => sha([0x00], d)
const NODE = (l, r) => sha([0x01], l, r)
const split = (n) => { let k = 1; while (k * 2 < n) k *= 2; return k }
const mth = (h) => (h.length === 1 ? h[0] : NODE(mth(h.slice(0, split(h.length))), mth(h.slice(split(h.length)))))
const path = (m, h) => {
  if (h.length === 1) return []
  const k = split(h.length)
  return m < k ? [...path(m, h.slice(0, k)), mth(h.slice(k))] : [...path(m - k, h.slice(k)), mth(h.slice(0, k))]
}

// The tiles of a tree of `leaves` leaf hashes: at level L, the hashes of the complete subtrees of 256^L leaves, 256
// to a tile, the last tile partial. With `full` the partial tiles are written at their full path too.
function tilesOf (leaves, { partial = true, full = false } = {}) {
  const files = new Map()
  let row = leaves
  for (let L = 0; row.length > 0; L++) {
    for (let N = 0; N * 256 < row.length; N++) {
      const hashes = row.slice(N * 256, N * 256 + 256)
      const bytes = Buffer.concat(hashes.map((h) => Buffer.from(h)))
      const p = `tile/${L}/${tileIndex(N)}`
      if (hashes.length === 256 || full) files.set(p, bytes)
      if (hashes.length < 256 && partial) files.set(`${p}.p/${hashes.length}`, bytes)
    }
    const up = []
    for (let j = 0; (j + 1) * 256 <= row.length; j++) up.push(mth(row.slice(j * 256, j * 256 + 256)))
    row = up
  }
  return files
}

function server (files, { status = new Map(), seen = [] } = {}) {
  return async (url, init) => {
    const p = new URL(url).pathname.slice(1)
    seen.push(p)
    if (status.has(p)) return new Response('', { status: status.get(p) })
    if (init?.method === 'POST') return new Response('', { status: 404 })
    return files.has(p) ? new Response(files.get(p)) : new Response('', { status: 404 })
  }
}
const leavesOf = (n) => Array.from({ length: n }, (_, i) => LEAF(Buffer.from(`e${i}`)))
const hex = (list) => list.map((h) => Buffer.from(h).toString('hex'))

test('tile indices as C2SP writes them', () => {
  for (const [n, s] of [[0, '000'], [7, '007'], [999, '999'], [1000, 'x001/000'], [1234067, 'x001/x234/067'], [256 ** 3, 'x016/x777/216']]) {
    assert.equal(tileIndex(n), s, String(n))
  }
})

test('proofs equal RFC 9162 PATH for every entry, over trees of many sizes, crossing tiles and levels', async () => {
  for (const n of [1, 2, 3, 5, 8, 255, 256, 257, 300, 511, 512, 513, 1000]) {
    const leaves = leavesOf(n)
    const log = tesseraLog({ url: 'https://log.example/', fetch: server(tilesOf(leaves)) })
    for (let m = 0; m < n; m += n > 300 ? 37 : 1) assert.deepEqual(hex(await log.inclusionProof(m, n)), hex(path(m, leaves)), `${m} of ${n}`)
    assert.deepEqual(hex(await log.inclusionProof(n - 1, n)), hex(path(n - 1, leaves)), `last of ${n}`)
  }
})

test('a level-2 tile: subtrees of 65,536 entries', { timeout: 120_000 }, async () => {
  const n = 65_536 + 300
  const leaves = leavesOf(n)
  const log = tesseraLog({ url: 'https://log.example', fetch: server(tilesOf(leaves)) })
  for (const m of [0, 255, 256, 65_535, 65_536, n - 1]) assert.deepEqual(hex(await log.inclusionProof(m, n)), hex(path(m, leaves)), String(m))
})

test('a proof for an older, smaller tree reads the partial tiles of that width', async () => {
  const leaves = leavesOf(300)
  const files = new Map([...tilesOf(leaves.slice(0, 260)), ...tilesOf(leaves)])
  const log = tesseraLog({ url: 'https://log.example/', fetch: server(files) })
  assert.deepEqual(hex(await log.inclusionProof(3, 260)), hex(path(3, leaves.slice(0, 260))))
})

test("a partial tile no longer served is read from its full tile, its row's first entries", async () => {
  const leaves = leavesOf(600)
  const files = tilesOf(leaves) // tile 0/002 is partial (88); serve only a full tile 0/002 written later
  const later = tilesOf(leavesOf(768), { partial: false })
  files.delete('tile/0/002.p/88')
  files.set('tile/0/002', later.get('tile/0/002'))
  const seen = []
  const log = tesseraLog({ url: 'https://log.example/', fetch: server(files, { seen }) })
  assert.deepEqual(hex(await log.inclusionProof(599, 600)), hex(path(599, leaves)))
  assert.ok(seen.includes('tile/0/002.p/88') && seen.includes('tile/0/002'))
})

test('each tile is read once for a proof', async () => {
  const leaves = leavesOf(300)
  const seen = []
  const log = tesseraLog({ url: 'https://log.example/', fetch: server(tilesOf(leaves), { seen }) })
  await log.inclusionProof(0, 300)
  assert.deepEqual([...seen].sort(), ['tile/0/000', 'tile/0/001.p/44'], 'a full tile at its full path, a partial one at its own')
})

test('a missing or short tile, or a failing server, is an error; so is an index outside the tree', async () => {
  const leaves = leavesOf(300)
  const missing = tilesOf(leaves)
  missing.delete('tile/0/001.p/44')
  await assert.rejects(tesseraLog({ url: 'https://l.example/', fetch: server(missing) }).inclusionProof(299, 300), /log tile missing: tile\/0\/001/)
  const short = tilesOf(leaves)
  short.set('tile/0/001.p/44', short.get('tile/0/001.p/44').subarray(0, 43 * 32))
  await assert.rejects(tesseraLog({ url: 'https://l.example/', fetch: server(short) }).inclusionProof(299, 300), /log tile short/)
  const failing = server(tilesOf(leaves), { status: new Map([['tile/0/000', 500]]) })
  await assert.rejects(tesseraLog({ url: 'https://l.example/', fetch: failing }).inclusionProof(0, 300), /log read failed: 500 tile\/0\/000/)
  const log = tesseraLog({ url: 'https://l.example/', fetch: server(tilesOf(leaves)) })
  for (const [m, n] of [[300, 300], [-1, 300], [0, 0], [1.5, 300], [0, 2 ** 53]]) await assert.rejects(log.inclusionProof(m, n), { name: 'RangeError', message: 'index must be below size' }, `${m} ${n}`)
})

test('append posts the entry and returns the index the log gives; anything else is an error', async () => {
  let got
  const reply = (status, body) => async (url, init) => { got = { url, method: init?.method, body: init?.body }; return new Response(body, { status }) }
  assert.equal(await tesseraLog({ url: 'https://l.example', fetch: reply(200, '42') }).append('text'), 42)
  assert.deepEqual(got, { url: 'https://l.example/add', method: 'POST', body: 'text' })
  for (const n of [0, 7, 123, 9_007_199]) assert.equal(await tesseraLog({ url: 'https://l.example/', fetch: reply(200, String(n)) }).append('t'), n)
  for (const [status, body] of [[500, '1'], [200, ''], [200, '01'], [200, '1x'], [200, 'x1'], [200, '-1'], [201, 'x']]) {
    await assert.rejects(tesseraLog({ url: 'https://l.example/', fetch: reply(status, body) }).append('t'), /log append failed/, `${status} ${body}`)
  }
})

test('checkpoint: the text the log serves; none is an error', async () => {
  const text = 'log.example/muid\n0\n47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=\n\n— log.example/muid abc=\n'
  const files = new Map([['checkpoint', Buffer.from(text)]])
  assert.equal(await tesseraLog({ url: 'https://l.example/', fetch: server(files) }).checkpoint(), text)
  await assert.rejects(tesseraLog({ url: 'https://l.example/', fetch: server(new Map()) }).checkpoint(), /log has no checkpoint/)
})
