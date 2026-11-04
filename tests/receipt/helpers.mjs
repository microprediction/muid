// Receipts, a log holding them, and its cosigned checkpoint, built independently of src/receipt.js: the tree by RFC
// 9162's recursions, the checkpoint by the C2SP formats (tests/note/helpers.mjs).
import { createHash } from 'node:crypto'
import { ed25519 } from '@noble/curves/ed25519.js'
import { envelope } from '../impl.mjs'
import { keyPair, logLine, cosignLine } from '../note/helpers.mjs'

const hex = (b) => Buffer.from(b).toString('hex')
const sha = (...parts) => createHash('sha256').update(Buffer.concat(parts.map((p) => Buffer.from(p)))).digest()
const LEAF = (entry) => sha([0x00], Buffer.from(entry, 'utf8'))
const NODE = (l, r) => sha([0x01], l, r)
const split = (n) => { let k = 1; while (k * 2 < n) k *= 2; return k }
const mth = (h) => (h.length === 1 ? h[0] : NODE(mth(h.slice(0, split(h.length))), mth(h.slice(split(h.length)))))
const path = (m, h) => {
  if (h.length <= 1) return []
  const k = split(h.length)
  return m < k ? [...path(m, h.slice(0, k)), mth(h.slice(k))] : [...path(m - k, h.slice(k)), mth(h.slice(0, k))]
}

export const NOW = 1_800_000_000
export const SERVICE = 'https://forecasts.example'
export const SERVICE_SECRET = Uint8Array.from({ length: 32 }, (_, i) => 40 + i)
export const SERVICE_KEY = hex(ed25519.getPublicKey(SERVICE_SECRET))
export const id = (c) => c.repeat(64)
export const BODY = Object.freeze({ service: SERVICE, identity: id('1'), delegation: id('2'), claim: id('3'), at: NOW - 100 })

export function receiptText (body = BODY, { secret = SERVICE_SECRET, sig } = {}) {
  const { payload } = envelope.seal('receipt', body)
  const signature = hex(ed25519.sign(envelope.signedBytes(payload), secret))
  return envelope.wrap(payload, sig ?? { service: hex(ed25519.getPublicKey(secret)), signature })
}

export const ORIGIN = 'log.example/receipts'
export const LOG = keyPair(ORIGIN, 1, 11)
export const COSIGNERS = [keyPair('witness.example/a', 4, 12), keyPair('witness.example/b', 4, 13), keyPair('witness.example/c', 4, 14)]

// A log of the given entries; for entry i, the checkpoint (log-signed, cosigned at `times`) and its inclusion proof.
export function logged (entries, i, times = [NOW - 50, NOW - 40, NOW - 30]) {
  const hashes = entries.map(LEAF)
  const root = mth(hashes)
  const text = `${ORIGIN}\n${entries.length}\n${root.toString('base64')}\n`
  const checkpoint = text + '\n' + logLine(LOG, text) + COSIGNERS.map((k, j) => (times[j] === undefined ? '' : cosignLine(k, text, times[j]))).join('')
  return { checkpoint, proof: path(i, hashes).map((h) => new Uint8Array(h)), index: i }
}

export const CTX = Object.freeze({
  services: [{ origin: SERVICE, key: SERVICE_KEY, nbf: 0, exp: NOW + 1000 }],
  log: { origin: ORIGIN, log: LOG.vkey, cosigners: COSIGNERS.map((k) => k.vkey), quorum: 2 },
  now: NOW,
  skew: 60,
})
