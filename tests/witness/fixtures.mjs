// Shared records for the witness tests: the model's roots as passkeys (tests/membership/translate.mjs), and a witness
// holding the same Ed25519 key as the translated records, so the texts it signs equal the translation's.
import { ed25519 } from '@noble/curves/ed25519.js'
import { envelope, membership } from '../impl.mjs'
import { witness } from './impl.mjs'
import { rootText, rootId, rootSigned, identityFor, secretOf, WITNESS, WITNESS_SECRET, CTX_BASE, BASE } from '../membership/translate.mjs'
import { make } from '../assertion/helpers.mjs'

const hex = (b) => Buffer.from(b).toString('hex')
export { rootText, rootId, rootSigned, identityFor, BASE, CTX_BASE, WITNESS }
export const WINDOW = 3600
export const sign = (bytes) => hex(ed25519.sign(bytes, WITNESS_SECRET))
export const CONFIG = Object.freeze({ rpId: CTX_BASE.rpId, origin: CTX_BASE.origin, witnessKeys: CTX_BASE.witnessKeys, key: WITNESS, sign,
  contestWindow: WINDOW })
export const w = witness(CONFIG)
export const IDENTITY = identityFor('a')
export const CTX = Object.freeze({ ...CTX_BASE, identity: IDENTITY })
export const state = (held) => membership.membershipState(held, CTX)

// A membership record body: epoch, roots (letters), prev (a record id).
export const mBody = (epoch, letters, prev) => ({ identity: IDENTITY, prev, epoch, roots: letters.map(rootId).sort() })
export const mId = (body) => envelope.seal('membership', body).id
export const signed = (type, body, letter) => rootSigned(type, body, letter)
// A root-signed record whose `sig.root` claims one root while another's key signed it.
export function forged (type, body, claimed, actual) {
  const { payload, id } = envelope.seal(type, body)
  return envelope.wrap(payload, { root: rootId(claimed), assertion: make({ covers: [id], secret: secretOf(actual) }) })
}

// Admits each [type, text], asserting every one is accepted; returns the held records.
export function admitAll (held, items) {
  for (const [type, text] of items) {
    const r = w.admit(held, type, text)
    if (!r.ok) throw new Error(`refused ${type}: ${r.reason}`)
    held = r.held
  }
  return held
}

export const start = () => admitAll(w.empty(IDENTITY), [['root', rootText('a')]])
// Epoch 2 = {a, b}: a's signature, b's root record, b's signature.
export const M2 = mBody(2, ['a', 'b'], IDENTITY)
export const withM2 = () => admitAll(start(), [['membership', signed('membership', M2, 'a')], ['root', rootText('b')],
  ['membership', signed('membership', M2, 'b')]])
export const open = (text, type) => envelope.open(text, type)
