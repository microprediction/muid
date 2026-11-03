import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { p256 } from '@noble/curves/nist.js'
import { assertion } from '../impl.mjs'

export const { checkRootAssertion } = assertion

// SPEC §6 W6, in order (the last four are K6's).
export const REASONS = Object.freeze(['assertion-shape', 'covers', 'assertion-encoding', 'client-data', 'challenge',
  'origin', 'auth-data-length', 'rp-id', 'user-presence', 'user-verification', 'auth-data-flags', 'key-encoding',
  'key-point', 'sig-encoding', 'sig-invalid'])

export const sha256 = (x) => createHash('sha256').update(x).digest()
export const b64u = (b) => Buffer.from(b).toString('base64url')
export const hex = (b) => Buffer.from(b).toString('hex')

// W1, computed independently of the implementation.
export const challengeFor = (covers, prefix = 'muid/v1/assert\n') => b64u(sha256(prefix + covers.map((id) => id + '\n').join('')))

export const RP_ID = 'id.example'
export const ORIGIN = 'https://id.example'
export const SECRET = Uint8Array.from(sha256('muid test passkey'))
export const KEY = '04' + hex(p256.getPublicKey(SECRET, false).subarray(1))
export const RECORD = 'a'.repeat(64)
export const CTX = Object.freeze({ record: RECORD, rpId: RP_ID, origin: ORIGIN, key: KEY })

export const FLAGS = Object.freeze({ UP: 0x01, RFU1: 0x02, UV: 0x04, BE: 0x08, BS: 0x10, RFU2: 0x20, AT: 0x40, ED: 0x80 })

export function authData ({ rpId = RP_ID, flags = 0x1d, count = 0, extra = new Uint8Array(0) } = {}) {
  const c = Buffer.alloc(4); c.writeUInt32BE(count)
  return Buffer.concat([sha256(rpId), Buffer.from([flags]), c, extra])
}

export function clientData ({ type = 'webauthn.get', challenge, origin = ORIGIN, crossOrigin = 'false', tail = '' }) {
  return `{"type":"${type}","challenge":"${challenge}","origin":"${origin}","crossOrigin":${crossOrigin}${tail}}`
}

export function signOver (ad, cdj, secret = SECRET) {
  const msg = Buffer.concat([Buffer.from(ad), sha256(typeof cdj === 'string' ? Buffer.from(cdj, 'utf8') : cdj)])
  return Buffer.from(p256.sign(msg, secret, { format: 'der', prehash: true, lowS: false }))
}

// A valid assertion over `covers`, with any part overridden.
export function make ({ covers = [RECORD], ad = authData(), cdj, cdjBytes, secret = SECRET } = {}) {
  const json = cdj ?? clientData({ challenge: challengeFor(covers) })
  const bytes = cdjBytes ?? Buffer.from(json, 'utf8')
  return {
    covers,
    authenticator_data: b64u(ad),
    client_data_json: b64u(bytes),
    signature: b64u(signOver(ad, bytes, secret)),
  }
}

export function result (sig, ctx = CTX) {
  return { ...checkRootAssertion(sig, ctx) }
}

export function rejects (sig, reason, label, ctx = CTX) {
  assert.ok(REASONS.includes(reason), `${label}: test bug, ${reason}`)
  assert.deepEqual(result(sig, ctx), { ok: false, reason }, label)
}
