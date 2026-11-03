import assert from 'node:assert/strict'
import { createPublicKey, verify as nodeVerify } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { ed25519 } from '../impl.mjs'

export const { checkEd25519 } = ed25519

// SPEC §2 K5, in order.
export const REASONS = Object.freeze(['key-encoding', 'key-point', 'key-small-order', 'key-mixed-order', 'sig-encoding',
  'sig-r-point', 'sig-r-small-order', 'sig-r-mixed-order', 'sig-s-range', 'sig-invalid'])

export const hex = (b) => Buffer.from(b).toString('hex')
export const bytes = (h) => new Uint8Array(Buffer.from(h, 'hex'))

export function accepts (sig, msg, key, label) {
  const r = checkEd25519(sig, msg, key)
  assert.deepEqual({ ...r }, { ok: true }, label)
}

export function rejects (sig, msg, key, reason, label) {
  assert.ok(REASONS.includes(reason), `${label}: test bug, unknown reason ${reason}`)
  const r = checkEd25519(sig, msg, key)
  assert.deepEqual({ ...r }, { ok: false, reason }, label)
}

// Node's own Ed25519 (OpenSSL), independent of noble: the differential oracle.
const SPKI = Buffer.from('302a300506032b6570032100', 'hex')
export function nodeAccepts (sigHex, msg, keyHex) {
  try {
    const key = createPublicKey({ key: Buffer.concat([SPKI, Buffer.from(keyHex, 'hex')]), format: 'der', type: 'spki' })
    return nodeVerify(null, msg, key, Buffer.from(sigHex, 'hex'))
  } catch {
    return false
  }
}

export const vector = (path) => JSON.parse(readFileSync(new URL(`../vectors/${path}`, import.meta.url), 'utf8'))

// The eight points of small order, as published (e.g. in the libsodium blocklist and "Taming the many EdDSAs"):
// identity, the point of order 2, two of order 4, four of order 8. All canonical encodings.
export const SMALL_ORDER = Object.freeze([
  '0100000000000000000000000000000000000000000000000000000000000000',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  '0000000000000000000000000000000000000000000000000000000000000000',
  '0000000000000000000000000000000000000000000000000000000000000080',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
])
