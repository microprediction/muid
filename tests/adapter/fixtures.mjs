// Records for the adapter tests: one identity, one delegation, heads at chosen times, and claims (as in
// tests/verifier/C1-claims.test.mjs).
import { ed25519 } from '@noble/curves/ed25519.js'
import { verifier as verifierModule, envelope, root as rootModule } from '../impl.mjs'
import { make, KEY, RP_ID, ORIGIN } from '../assertion/helpers.mjs'

const hex = (b) => Buffer.from(b).toString('hex')
export const NOW = 1_800_000_100
const W = Uint8Array.from({ length: 32 }, (_, i) => 140 + i)
const WITNESS = hex(ed25519.getPublicKey(W))
const APP = Uint8Array.from({ length: 32 }, (_, i) => 60 + i)
const AUD = 'https://app.example'
export const URL_ = 'https://app.example/forecasts'
export const CONFIG = Object.freeze({ rpId: RP_ID, origin: ORIGIN, audience: AUD, witnessKeys: [{ key: WITNESS, nbf: 0, exp: 1_900_000_000 }],
  skew: 60, maxLifetime: 2_592_000, maxStaleness: 86_400, maxClaimAge: 300 })
export const verifier = () => verifierModule.verifier(CONFIG)

export const root = envelope.wrap(envelope.seal('root', { pub: KEY, rp_id: RP_ID }).payload)
const ROOT = rootModule.checkRoot(root, { rpId: RP_ID }).id
export const IDENTITY = rootModule.identityOf(ROOT)
const del = envelope.seal('delegation', { agent: 'worker', identity: IDENTITY, membership: IDENTITY, root: ROOT, subject: hex(ed25519.getPublicKey(APP)), aud: AUD,
  scopes: ['forecast'], nbf: NOW - 10, exp: NOW + 86_000 })
export const delegation = envelope.wrap(del.payload, { root: make({ covers: [del.id] }),
  subject: hex(ed25519.sign(Buffer.concat([Buffer.from('muid/v1/accept\n'), Buffer.from(del.id, 'hex')]), APP)) })

export function head (at, { revoked = [], secret = W, epoch = 1, memberships = [IDENTITY] } = {}) {
  const h = envelope.seal('head', { identity: IDENTITY, epoch, memberships, authority: [ROOT], revoked, at })
  return envelope.wrap(h.payload, { signature: hex(ed25519.sign(envelope.signedBytes(h.payload), secret)), witness: hex(ed25519.getPublicKey(secret)) })
}
export const DELEGATION_ID = del.id
// A second delegation from the same root, to another app's key: an honest request alongside the first.
const APP2 = Uint8Array.from({ length: 32 }, (_, i) => 100 + i)
const del2 = envelope.seal('delegation', { agent: 'worker', identity: IDENTITY, membership: IDENTITY, root: ROOT, subject: hex(ed25519.getPublicKey(APP2)), aud: AUD,
  scopes: ['forecast'], nbf: NOW - 10, exp: NOW + 86_000 })
export const delegation2 = envelope.wrap(del2.payload, { root: make({ covers: [del2.id] }),
  subject: hex(ed25519.sign(Buffer.concat([Buffer.from('muid/v1/accept\n'), Buffer.from(del2.id, 'hex')]), APP2)) })
// R10: the witness's logged record of a delegation, signed at NOW - 10, when it took effect.
export function loggedFor (id, secret = W) {
  const l = envelope.seal('logged', { identity: IDENTITY, delegation: id, at: NOW - 10 })
  return envelope.wrap(l.payload, { signature: hex(ed25519.sign(envelope.signedBytes(l.payload), secret)), witness: hex(ed25519.getPublicKey(secret)) })
}
export const logged2 = loggedFor(del2.id)
// A second witness key, for rotation: a configuration that pins only it.
export const W2 = Uint8Array.from({ length: 32 }, (_, i) => 200 + i)
export const verifierWithKey = (secret) => verifierModule.verifier({ ...CONFIG, witnessKeys: [{ key: hex(ed25519.getPublicKey(secret)), nbf: 0, exp: 1_900_000_000 }] })

export function claim (at = NOW - 5, text = 'a forecast', extra = {}) {
  const { payload, id } = envelope.seal('claim', { delegation: del.id, scope: 'forecast', htm: 'POST', htu: URL_, at, data: { text }, ...extra })
  return { text: envelope.wrap(payload, { signature: hex(ed25519.sign(envelope.signedBytes(payload), APP)) }), id }
}

// `secret` signs the logged record: the witness key the verifier pins.
export const records = (c = claim(), h = head(NOW - 100), secret = W) => ({ claim: c.text, delegation, root, head: h, logged: loggedFor(del.id, secret) })
export const CALL = Object.freeze({ now: NOW, scope: 'forecast', method: 'POST', url: URL_, revoked: [] })
