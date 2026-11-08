// F6: verifyHead(head, call) applies F5's head checks alone — form, witness signature and window (R9), freshness,
// minHeadAt, and consistency with the last head accepted — so a relying party can remember any head that verifies,
// whatever else a request carries (as a TUF client keeps any metadata that verifies). Its refusals are exactly the
// ones verifyDelegation gives for the same head.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { ed25519 } from '@noble/curves/ed25519.js'
import { verifier as verifierModule, envelope, root as rootModule } from '../impl.mjs'
import { make, KEY, RP_ID, ORIGIN } from '../assertion/helpers.mjs'

const hex = (b) => Buffer.from(b).toString('hex')
const NOW = 1_800_000_100
const W = Uint8Array.from({ length: 32 }, (_, i) => 140 + i)
const WITNESS = hex(ed25519.getPublicKey(W))
const APP = Uint8Array.from({ length: 32 }, (_, i) => 60 + i)
const AUD = 'https://app.example'
const v = verifierModule.verifier({ rpId: RP_ID, origin: ORIGIN, audience: AUD, witnessKeys: [{ key: WITNESS, nbf: 0, exp: 1_900_000_000 }],
  skew: 60, maxLifetime: 2_592_000, maxStaleness: 86_400, maxClaimAge: 300 })
const root = envelope.wrap(envelope.seal('root', { pub: KEY, rp_id: RP_ID }).payload)
const ROOT = rootModule.checkRoot(root, { rpId: RP_ID }).id
const IDENTITY = rootModule.identityOf(ROOT)
const del = envelope.seal('delegation', { identity: IDENTITY, membership: IDENTITY, root: ROOT, subject: hex(ed25519.getPublicKey(APP)), aud: AUD,
  scopes: ['post'], nbf: NOW - 10, exp: NOW + 86_000 })
const delegation = envelope.wrap(del.payload, { root: make({ covers: [del.id] }),
  subject: hex(ed25519.sign(Buffer.concat([Buffer.from('muid/v1/accept\n'), Buffer.from(del.id, 'hex')]), APP)) })
function head (at, over = {}) {
  const h = envelope.seal('head', { identity: IDENTITY, epoch: 1, memberships: [IDENTITY], authority: [ROOT], revoked: [], at, ...over })
  return envelope.wrap(h.payload, { signature: hex(ed25519.sign(envelope.signedBytes(h.payload), W)), witness: WITNESS })
}
const lg = envelope.seal('logged', { identity: IDENTITY, delegation: del.id, at: NOW - 10 })
const logged = envelope.wrap(lg.payload, { signature: hex(ed25519.sign(envelope.signedBytes(lg.payload), W)), witness: WITNESS })
const CALL = Object.freeze({ now: NOW, scope: 'post', revoked: [] })
const plain = (r) => ({ ...r })

test('a head that verifies gives its identity and time, whatever else a request would carry', () => {
  assert.deepEqual(plain(v.verifyHead(head(NOW - 100), CALL)), { ok: true, identity: IDENTITY, at: NOW - 100 })
  const revoking = head(NOW - 50, { revoked: [del.id] })
  assert.deepEqual(plain(v.verifyHead(revoking, CALL)), { ok: true, identity: IDENTITY, at: NOW - 50 }, 'one that revokes the delegation')
  assert.deepEqual(plain(v.verifyDelegation({ delegation, root, logged, head: revoking }, CALL)), { ok: false, reason: 'revoked' })
})

test("its refusals are verifyDelegation's for the same head and call", () => {
  const other = '9'.repeat(64)
  for (const [name, h, call] of [
    ['not a head', 'x', CALL], ['stale', head(NOW - 86_401), CALL], ['from the future', head(NOW + 61), CALL],
    ['under minHeadAt', head(NOW - 100), { ...CALL, minHeadAt: NOW - 99 }], ['older than the last', head(NOW - 100), { ...CALL, lastHead: head(NOW - 50) }],
    ['another identity than the last', head(NOW - 100, { identity: other, memberships: [other] }), { ...CALL, lastHead: head(NOW - 150) }],
    ['equivocation', head(NOW - 100, { epoch: 2, memberships: ['5'.repeat(64)] }), { ...CALL, lastHead: head(NOW - 150, { epoch: 3, memberships: ['6'.repeat(64)] }) }],
  ]) {
    const a = plain(v.verifyHead(h, call))
    assert.equal(a.ok, false, name)
    assert.deepEqual(a, plain(v.verifyDelegation({ delegation, root, logged, head: h }, call)), name)
  }
})

test('a malformed call is a programming error, as for verifyDelegation', () => {
  for (const call of [null, { ...CALL, now: -1 }, { ...CALL, scope: 'x y' }, { ...CALL, lastHead: 'x' }]) {
    assert.throws(() => v.verifyHead(head(NOW - 100), call), TypeError)
  }
})
