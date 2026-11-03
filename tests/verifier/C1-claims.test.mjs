// C1: ephemeral claims, signed by the delegation's subject key, verified with their delegation and a fresh head.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { ed25519 } from '@noble/curves/ed25519.js'
import { verifier as verifierModule, envelope, root as rootModule } from '../impl.mjs'
import { make, KEY, RP_ID, ORIGIN } from '../assertion/helpers.mjs'

const { verifier } = verifierModule
const hex = (b) => Buffer.from(b).toString('hex')
const NOW = 1_800_000_100
const W = Uint8Array.from({ length: 32 }, (_, i) => 140 + i)
const WITNESS = hex(ed25519.getPublicKey(W))
const APP = Uint8Array.from({ length: 32 }, (_, i) => 60 + i)
const AUD = 'https://app.example'
const CONFIG = Object.freeze({ rpId: RP_ID, origin: ORIGIN, audience: AUD, witnessKeys: [{ key: WITNESS, nbf: 0, exp: 1_900_000_000 }],
  skew: 60, maxLifetime: 2_592_000, maxStaleness: 86_400, maxClaimAge: 300 })
const v = verifier(CONFIG)

const root = envelope.wrap(envelope.seal('root', { pub: KEY, rp_id: RP_ID }).payload)
const ROOT = rootModule.checkRoot(root, { rpId: RP_ID }).id
const IDENTITY = rootModule.identityOf(ROOT)
const body = { identity: IDENTITY, membership: IDENTITY, root: ROOT, subject: hex(ed25519.getPublicKey(APP)), aud: AUD,
  scopes: ['post', 'read'], nbf: NOW - 10, exp: NOW + 86_000 }
const del = envelope.seal('delegation', body)
const delegation = envelope.wrap(del.payload, { root: make({ covers: [del.id] }),
  subject: hex(ed25519.sign(Buffer.concat([Buffer.from('muid/v1/accept\n'), Buffer.from(del.id, 'hex')]), APP)) })
const h = envelope.seal('head', { identity: IDENTITY, memberships: [IDENTITY], authority: [ROOT], revoked: [], at: NOW - 100 })
const head = envelope.wrap(h.payload, { signature: hex(ed25519.sign(envelope.signedBytes(h.payload), W)), witness: WITNESS })

function claim (over = {}, { secret = APP, sig } = {}) {
  const b = { delegation: del.id, scope: 'post', at: NOW - 5, data: { text: 'hello' }, ...over }
  for (const k of Object.keys(b)) if (b[k] === '__drop__') delete b[k]
  const { payload, id } = envelope.seal('claim', b)
  return { text: envelope.wrap(payload, sig ?? { signature: hex(ed25519.sign(envelope.signedBytes(payload), secret)) }), id }
}
const C = claim()
const call = (records = {}, ctx = {}) => {
  const r = v.verifyClaim({ claim: C.text, delegation, root, head, ...records }, { now: NOW, revoked: [], ...ctx })
  return r.ok ? { ok: true } : { ...r }
}
const refused = (reason) => ({ ok: false, reason })

test('a claim under a valid delegation is accepted, with its id, body and the delegation', () => {
  const r = v.verifyClaim({ claim: C.text, delegation, root, head }, { now: NOW, revoked: [] })
  assert.equal(r.ok, true, JSON.stringify(r))
  assert.equal(r.id, C.id)
  assert.equal(r.body.data.text, 'hello')
  assert.equal(r.delegation.id, del.id)
  assert.deepEqual(Object.keys(r), ['ok', 'id', 'body', 'delegation'])
  assert.ok(Object.isFrozen(r))
})

test('claim-shape: keys, forms, sig', () => {
  for (const [name, over] of [['extra key', { x: 1 }], ['no data', { data: '__drop__' }], ['data an array', { data: [1] }],
    ['delegation not an id', { delegation: 'x' }], ['scope not a scope', { scope: 'Post' }], ['at negative', { at: -1 }], ['at a string', { at: '1' }]]) {
    assert.deepEqual(call({ claim: claim(over).text }), refused('claim-shape'), name)
  }
  for (const sig of [{}, { signature: 'ab' }, { signature: '0'.repeat(128), x: 1 }, { signature: 'A'.repeat(128) }]) {
    assert.deepEqual(call({ claim: claim({}, { sig }).text }), refused('claim-shape'), JSON.stringify(sig).slice(0, 30))
  }
  assert.deepEqual(call({ claim: 'x' }), refused('envelope-encoding'))
  assert.deepEqual(call({ claim: delegation }), refused('type'))
})

test("the delegation is verified in full, with the claim's scope", () => {
  assert.deepEqual(call({ claim: claim({ scope: 'admin' }).text }), refused('scope'))
  assert.deepEqual(call({ claim: claim({ scope: 'read' }).text }), { ok: true })
  assert.deepEqual(call({ head: 'x' }), refused('head'))
  assert.deepEqual(call({}, { revoked: [del.id] }), refused('revoked'))
  assert.deepEqual(call({}, { minHeadAt: NOW }), refused('stale'))
})

test('claim-delegation: a claim names the delegation it is made under', () => {
  assert.deepEqual(call({ claim: claim({ delegation: 'f'.repeat(64) }).text }), refused('claim-delegation'))
})

test('claim-time: no older than maxClaimAge, no later than skew', () => {
  assert.deepEqual(call({ claim: claim({ at: NOW - 300 }).text }), { ok: true })
  assert.deepEqual(call({ claim: claim({ at: NOW - 301 }).text }), refused('claim-time'))
  assert.deepEqual(call({ claim: claim({ at: NOW + 60 }).text }), { ok: true })
  assert.deepEqual(call({ claim: claim({ at: NOW + 61 }).text }), refused('claim-time'))
})

test('the signature: by the subject key, over the signed bytes', () => {
  assert.deepEqual(call({ claim: claim({}, { secret: W }).text }), refused('sig-invalid'))
  const { payload } = envelope.seal('claim', { delegation: del.id, scope: 'post', at: NOW - 5, data: {} })
  const overPayload = hex(ed25519.sign(new TextEncoder().encode(payload), APP))
  assert.deepEqual(call({ claim: envelope.wrap(payload, { signature: overPayload }) }), refused('sig-invalid'))
})

test('programming errors and totality', () => {
  assert.throws(() => verifier({ ...CONFIG, maxClaimAge: -1 }), { name: 'TypeError' })
  assert.throws(() => v.verifyClaim({ claim: C.text, delegation, root, head }, { now: NOW }), { name: 'TypeError' })
  for (const x of [undefined, null, 1, {}, []]) assert.equal(v.verifyClaim({ claim: x, delegation, root, head }, { now: NOW, revoked: [] }).ok, false)
  const hostile = new Proxy({}, { get () { throw new Error('trap') } })
  assert.equal(v.verifyClaim(hostile, { now: NOW, revoked: [] }).ok, false)
})
