// An in-memory transparency log for the demo's unit tests: entries, RFC 9162 trees and proofs, and C2SP checkpoints
// signed by a log key and cosigned by one witness key at a chosen time (tests/note/helpers.mjs builds the lines).
import { createHash } from 'node:crypto'
import { keyPair, logLine, cosignLine, b64 } from '../note/helpers.mjs'

const sha = (...parts) => new Uint8Array(createHash('sha256').update(Buffer.concat(parts.map((p) => Buffer.from(p)))).digest())
const LEAF = (d) => sha([0x00], d)
const NODE = (l, r) => sha([0x01], l, r)
const split = (n) => { let k = 1; while (k * 2 < n) k *= 2; return k }
const mth = (h) => (h.length === 0 ? sha() : h.length === 1 ? h[0] : NODE(mth(h.slice(0, split(h.length))), mth(h.slice(split(h.length)))))
const path = (m, h) => {
  if (h.length === 1) return []
  const k = split(h.length)
  return m < k ? [...path(m, h.slice(0, k)), mth(h.slice(k))] : [...path(m - k, h.slice(k)), mth(h.slice(0, k))]
}

export const ORIGIN = 'log.test/demo'
export const LOG = keyPair(ORIGIN, 1, 3)
export const COSIGNER = keyPair('witness.test/demo', 4, 5)
export const CONFIG = Object.freeze({ origin: ORIGIN, log: LOG.vkey, cosigners: [COSIGNER.vkey], quorum: 1 })

// { append, checkpoint, inclusionProof, entries, published }: `cosignTime()` gives each checkpoint's cosignature
// time; `publish` false holds checkpoints back at their last size, as a log waiting on its witnesses; `failAppend`
// makes appends fail, before (or with `lostAnswer`, after) the entry is taken; `failProof` makes proofs fail.
export function fakeLog ({ cosignTime, failAppend = false } = {}) {
  const entries = []
  let published = 0
  const state = { publish: true, failAppend, lostAnswer: false, failProof: false }
  return {
    state,
    entries: () => [...entries],
    async append (text) {
      if (state.failAppend && !state.lostAnswer) throw new Error('log down')
      entries.push(text)
      if (state.publish) published = entries.length
      if (state.failAppend) throw new Error('answer lost')
      return entries.length - 1
    },
    async checkpoint () {
      const leaves = entries.slice(0, published).map((t) => LEAF(Buffer.from(t, 'utf8')))
      const text = `${ORIGIN}\n${published}\n${b64(mth(leaves))}\n`
      return text + '\n' + logLine(LOG, text) + cosignLine(COSIGNER, text, cosignTime())
    },
    async inclusionProof (index, size) {
      if (state.failProof) throw new Error('tiles unavailable')
      return path(index, entries.slice(0, size).map((t) => LEAF(Buffer.from(t, 'utf8'))))
    },
  }
}
