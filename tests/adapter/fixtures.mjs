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
export const REQUEST = 'POST https://app.example/forecasts sha256:0f00'
export const CONFIG = Object.freeze({ rpId: RP_ID, origin: ORIGIN, audience: AUD, witnessKeys: [{ key: WITNESS, nbf: 0, exp: 1_900_000_000 }],
  skew: 60, maxLifetime: 2_592_000, maxStaleness: 86_400, maxClaimAge: 300 })
export const verifier = () => verifierModule.verifier(CONFIG)

export const root = envelope.wrap(envelope.seal('root', { pub: KEY, rp_id: RP_ID }).payload)
const ROOT = rootModule.checkRoot(root, { rpId: RP_ID }).id
export const IDENTITY = rootModule.identityOf(ROOT)
const del = envelope.seal('delegation', { identity: IDENTITY, membership: IDENTITY, root: ROOT, subject: hex(ed25519.getPublicKey(APP)), aud: AUD,
  scopes: ['forecast'], nbf: NOW - 10, exp: NOW + 86_000 })
export const delegation = envelope.wrap(del.payload, { root: make({ covers: [del.id] }),
  subject: hex(ed25519.sign(Buffer.concat([Buffer.from('muid/v1/accept\n'), Buffer.from(del.id, 'hex')]), APP)) })

export function head (at) {
  const h = envelope.seal('head', { identity: IDENTITY, epoch: 1, memberships: [IDENTITY], authority: [ROOT], revoked: [], at })
  return envelope.wrap(h.payload, { signature: hex(ed25519.sign(envelope.signedBytes(h.payload), W)), witness: WITNESS })
}

export function claim (at = NOW - 5, text = 'a forecast') {
  const { payload, id } = envelope.seal('claim', { delegation: del.id, scope: 'forecast', request: REQUEST, at, data: { text } })
  return { text: envelope.wrap(payload, { signature: hex(ed25519.sign(envelope.signedBytes(payload), APP)) }), id }
}

export const records = (c = claim(), h = head(NOW - 100)) => ({ claim: c.text, delegation, root, head: h })
export const CALL = Object.freeze({ now: NOW, scope: 'forecast', request: REQUEST, revoked: [] })
