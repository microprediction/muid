import assert from 'node:assert/strict'
import { ed25519 } from '@noble/curves/ed25519.js'
import { envelope, delegation } from '../impl.mjs'
import { make, authData, KEY as ROOT_KEY, RP_ID, ORIGIN } from '../assertion/helpers.mjs'

export const { checkDelegation } = delegation
export const REASONS = Object.freeze(['envelope-encoding', 'envelope-shape', 'payload-size', 'payload-encoding',
  'payload-shape', 'version', 'type', 'delegation-shape', 'scopes', 'aud', 'subject-key', 'lifetime', 'not-yet', 'expired',
  'root',
  'assertion-shape', 'covers', 'assertion-encoding', 'client-data', 'challenge', 'origin', 'auth-data-length', 'rp-id',
  'user-presence', 'user-verification', 'auth-data-flags', 'key-encoding', 'key-point', 'sig-encoding', 'sig-invalid',
  'subject-consent'])

export const hex = (b) => Buffer.from(b).toString('hex')
export const SUBJECT_SECRET = Uint8Array.from({ length: 32 }, (_, i) => 200 - i)
export const SUBJECT = hex(ed25519.getPublicKey(SUBJECT_SECRET))
export const NBF = 1_800_000_000
export const CTX = Object.freeze({ rootKey: ROOT_KEY, rpId: RP_ID, origin: ORIGIN, now: NBF + 10, skew: 60, maxLifetime: 2_592_000 })

export const BODY = Object.freeze({
  identity: '1'.repeat(64),
  membership: '2'.repeat(64),
  root: '44404d2d618dcf0680853eb9c05c20fe78d3958f7be85a0d8faa8a238200caae', // the test passkey's root id (tests/root)
  subject: SUBJECT,
  aud: 'https://app.example',
  scopes: ['post', 'read'],
  nbf: NBF,
  exp: NBF + 86_400,
})

export const ACCEPT_PREFIX = 'muid/v1/accept\n'
export const consent = (id, { secret = SUBJECT_SECRET, prefix = ACCEPT_PREFIX, asHex = false } = {}) =>
  hex(ed25519.sign(Buffer.concat([Buffer.from(prefix), asHex ? Buffer.from(id) : Buffer.from(id, 'hex')]), secret))

// A delegation's envelope text, made with the real seal and wrap, with any part overridden.
export function build ({ body = BODY, covers, rootSig, subject, sigOverride, rootSecret } = {}) {
  const { payload, id } = envelope.seal('delegation', body)
  const root = rootSig ?? make({ covers: covers ?? [id], ...(rootSecret ? { secret: rootSecret } : {}) })
  const sig = sigOverride ?? { root, subject: subject ?? consent(id) }
  return envelope.wrap(payload, sig)
}

// Accepts are compared as { ok: true } here; the id and body they carry are tested on their own.
export const result = (record, ctx = CTX) => {
  const r = checkDelegation(record, ctx)
  return r.ok ? { ok: true } : { ...r }
}

export function rejects (record, reason, label, ctx = CTX) {
  assert.ok(REASONS.includes(reason), `${label}: test bug, ${reason}`)
  assert.deepEqual(result(record, ctx), { ok: false, reason }, label)
}

export { authData }
