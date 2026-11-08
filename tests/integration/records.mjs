// The records one claim rests on (the claim, its delegation, the root record, the head and the logged record), all
// valid at NOW, for the integration sweeps.
import { ed25519 } from '@noble/curves/ed25519.js'
import { verifier as verifierModule, envelope, root as rootModule } from '../impl.mjs'
import { make, KEY, RP_ID, ORIGIN } from '../assertion/helpers.mjs'

const hex = (b) => Buffer.from(b).toString('hex')
export const NOW = 1_800_000_100
const W = Uint8Array.from({ length: 32 }, (_, i) => 7 + i)
const WITNESS = hex(ed25519.getPublicKey(W))
const APP = Uint8Array.from({ length: 32 }, (_, i) => 77 + i)
const AUD = 'https://app.example'
const URL_ = 'https://app.example/posts'
export const v = verifierModule.verifier({ rpId: RP_ID, origin: ORIGIN, audience: AUD,
  witnessKeys: [{ key: WITNESS, nbf: 0, exp: 1_900_000_000 }], skew: 60, maxLifetime: 2_592_000, maxStaleness: 86_400,
  maxClaimAge: 300 })

const root = envelope.wrap(envelope.seal('root', { pub: KEY, rp_id: RP_ID }).payload)
const ROOT = rootModule.checkRoot(root, { rpId: RP_ID }).id
const IDENTITY = rootModule.identityOf(ROOT)
const del = envelope.seal('delegation', { identity: IDENTITY, membership: IDENTITY, root: ROOT,
  subject: hex(ed25519.getPublicKey(APP)), aud: AUD, scopes: ['post'], nbf: NOW - 10, exp: NOW + 86_000 })
const delegation = envelope.wrap(del.payload, { root: make({ covers: [del.id] }),
  subject: hex(ed25519.sign(Buffer.concat([Buffer.from('muid/v1/accept\n'), Buffer.from(del.id, 'hex')]), APP)) })
const h = envelope.seal('head', { identity: IDENTITY, epoch: 1, memberships: [IDENTITY], authority: [ROOT], revoked: [], at: NOW - 100 })
const head = envelope.wrap(h.payload, { signature: hex(ed25519.sign(envelope.signedBytes(h.payload), W)), witness: WITNESS })
const c = envelope.seal('claim', { delegation: del.id, scope: 'post', htm: 'POST', htu: URL_, at: NOW - 5, data: { n: 1 } })
const claim = envelope.wrap(c.payload, { signature: hex(ed25519.sign(envelope.signedBytes(c.payload), APP)) })

const l = envelope.seal('logged', { identity: IDENTITY, delegation: del.id, at: NOW - 10 })
const logged = envelope.wrap(l.payload, { signature: hex(ed25519.sign(envelope.signedBytes(l.payload), W)), witness: WITNESS })
export const RECORDS = Object.freeze({ claim, delegation, root, head, logged })
export const CALL = Object.freeze({ now: NOW, scope: 'post', method: 'POST', url: URL_, revoked: [] })
