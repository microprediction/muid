// A client of a C2SP tlog-tiles log (Tessera's POSIX server, log/go.mod): append an entry, read the checkpoint, and
// build an RFC 9162 inclusion proof from the log's hash tiles, so a proof can be served for any entry against any
// checkpoint. Tiles are read as C2SP tlog-tiles lays them out: height 8, the hashes of one tree level per tile row,
// partial tiles at `.p/<width>`. The proof is checked by the core's verifyInclusion against a verified checkpoint;
// nothing here is trusted.
import { sha256 } from '@noble/hashes/sha2.js'

const TILE = 256
const NODE = (l, r) => {
  const b = new Uint8Array(65)
  b[0] = 1
  b.set(l, 1)
  b.set(r, 33)
  return sha256(b)
}

// The largest power of two strictly below n (n > 1).
function below (n) {
  let k = 1
  while (k * 2 < n) k *= 2
  return k
}

// A tile index as C2SP tlog-tiles writes it: groups of three digits, all but the last prefixed with x.
export function tileIndex (n) {
  const groups = []
  do {
    groups.unshift(String(n % 1000).padStart(3, '0'))
    n = Math.floor(n / 1000)
  } while (n > 0)
  return groups.map((g, i) => (i < groups.length - 1 ? 'x' + g : g)).join('/')
}

export function tesseraLog ({ url, fetch = globalThis.fetch }) {
  const base = url.endsWith('/') ? url : url + '/'

  async function get (path) {
    const res = await fetch(base + path)
    if (res.status === 404) return undefined
    if (!res.ok) throw new Error(`log read failed: ${res.status} ${path}`)
    return new Uint8Array(await res.arrayBuffer())
  }

  // Appends one entry; resolves to its index once the log has sequenced it.
  async function append (text) {
    const res = await fetch(base + 'add', { method: 'POST', body: text })
    const body = await res.text()
    if (!res.ok || !/^(?:0|[1-9][0-9]*)$/.test(body)) throw new Error(`log append failed: ${res.status}`)
    return Number(body)
  }

  async function checkpoint () {
    const b = await get('checkpoint')
    if (b === undefined) throw new Error('log has no checkpoint')
    return new TextDecoder().decode(b)
  }

  // The inclusion proof (RFC 9162 §2.1.3.1, PATH) of entry `index` in the tree of `size` entries, as 32-byte hashes.
  async function inclusionProof (index, size) {
    if (!Number.isSafeInteger(index) || !Number.isSafeInteger(size) || index < 0 || index >= size) {
      throw new RangeError('index must be below size')
    }
    const tiles = new Map()

    // The row of hashes at tree level 8L held by tile N, for a tree of `size` entries: a full tile, or the partial
    // one of the width this size gives (a full tile serves too, once written).
    async function tile (L, N) {
      const key = `${L}/${N}`
      if (!tiles.has(key)) {
        const row = Math.floor(size / TILE ** L)
        const width = Math.min(TILE, row - N * TILE)
        const path = `tile/${L}/${tileIndex(N)}`
        let b = width === TILE ? await get(path) : (await get(`${path}.p/${width}`)) ?? (await get(path))
        if (b === undefined) throw new Error(`log tile missing: ${path}`)
        if (b.length < width * 32) throw new Error(`log tile short: ${path}`)
        b = b.subarray(0, width * 32)
        tiles.set(key, b)
      }
      return tiles.get(key)
    }

    // The hash of the complete subtree of 2^h entries starting at entry i * 2^h.
    async function node (h, i) {
      const L = Math.floor(h / 8)
      const r = h - 8 * L
      const first = i * 2 ** r // in the row at level 8L
      const t = await tile(L, Math.floor(first / TILE))
      let level = []
      for (let j = 0; j < 2 ** r; j++) {
        const at = (first % TILE + j) * 32
        level.push(t.subarray(at, at + 32))
      }
      while (level.length > 1) {
        const up = []
        for (let j = 0; j < level.length; j += 2) up.push(NODE(level[j], level[j + 1]))
        level = up
      }
      return level[0]
    }

    // MTH of entries [a, b): a complete subtree read from a tile, or split as RFC 9162 splits it.
    async function mth (a, b) {
      const n = b - a
      if (Number.isInteger(Math.log2(n))) return node(Math.log2(n), a / n) // exact for powers of two
      const k = below(n)
      return NODE(await mth(a, a + k), await mth(a + k, b))
    }

    async function path (m, a, b) {
      if (b - a === 1) return []
      const k = below(b - a)
      return m < a + k ? [...await path(m, a, a + k), await mth(a + k, b)] : [...await path(m, a + k, b), await mth(a, a + k)]
    }

    return path(index, 0, size)
  }

  return Object.freeze({ append, checkpoint, inclusionProof })
}
