import assert from 'node:assert/strict'
import { createPublicKey, verify as nodeVerify } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { p256 } from '../impl.mjs'

export const { checkP256 } = p256
export const REASONS = Object.freeze(['key-encoding', 'key-point', 'sig-encoding', 'sig-invalid'])
export const bytes = (h) => new Uint8Array(Buffer.from(h, 'hex'))
export const hex = (b) => Buffer.from(b).toString('hex')
export const vectors = () => JSON.parse(readFileSync(new URL('../vectors/wycheproof/ecdsa_secp256r1_sha256_test.json', import.meta.url), 'utf8'))
// The order of the P-256 group.
export const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n

export function result (sig, msg, key) {
  return { ...checkP256(sig, msg, key) }
}

export function rejects (sig, msg, key, reason, label) {
  assert.ok(REASONS.includes(reason), `${label}: test bug`)
  assert.deepEqual(result(sig, msg, key), { ok: false, reason }, label)
}

// Node's ECDSA (OpenSSL), independent of noble.
export function nodeAccepts (sig, msg, keyHex) {
  try {
    const x = Buffer.from(keyHex.slice(2, 66), 'hex').toString('base64url')
    const y = Buffer.from(keyHex.slice(66), 'hex').toString('base64url')
    const key = createPublicKey({ key: { kty: 'EC', crv: 'P-256', x, y }, format: 'jwk' })
    return nodeVerify('sha256', msg, { key, dsaEncoding: 'der' }, sig)
  } catch {
    return false
  }
}

// DER of (r, s) built by hand, minimal: used to make high-S variants of honest signatures.
export function der (r, s) {
  const int = (n) => {
    let h = n.toString(16)
    if (h.length % 2) h = '0' + h
    if (parseInt(h.slice(0, 2), 16) >= 0x80) h = '00' + h
    return '02' + (h.length / 2).toString(16).padStart(2, '0') + h
  }
  const body = int(r) + int(s)
  return bytes('30' + (body.length / 2).toString(16).padStart(2, '0') + body)
}

export function parseDer (sig) {
  const h = hex(sig)
  const rl = parseInt(h.slice(6, 8), 16)
  const r = BigInt('0x' + h.slice(8, 8 + rl * 2))
  const s = BigInt('0x' + h.slice(8 + rl * 2 + 4))
  return { r, s }
}
