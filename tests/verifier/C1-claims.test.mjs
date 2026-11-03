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
// The relying party's canonical form of the request: method, URL and body hash, and a nonce if it issues them.
const REQUEST = 'POST https://app.example/posts sha256:0f00'
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
  const b = { delegation: del.id, scope: 'post', request: REQUEST, at: NOW - 5, data: { text: 'hello' }, ...over }
  for (const k of Object.keys(b)) if (b[k] === '__drop__') delete b[k]
  const { payload, id } = envelope.seal('claim', b)
  return { text: envelope.wrap(payload, sig ?? { signature: hex(ed25519.sign(envelope.signedBytes(payload), secret)) }), id }
}
const C = claim()
const CALL = Object.freeze({ now: NOW, scope: 'post', request: REQUEST, revoked: [] })
const call = (records = {}, ctx = {}) => {
  const r = v.verifyClaim({ claim: C.text, delegation, root, head, ...records }, { ...CALL, ...ctx })
  return r.ok ? { ok: true } : { ...r }
}
const refused = (reason) => ({ ok: false, reason })

test('a claim under a valid delegation is accepted, with its id, body and the delegation', () => {
  const r = v.verifyClaim({ claim: C.text, delegation, root, head }, CALL)
  assert.equal(r.ok, true, JSON.stringify(r))
  assert.equal(r.id, C.id)
  assert.equal(r.body.data.text, 'hello')
  assert.equal(r.delegation.id, del.id)
  assert.equal(r.until, NOW - 5 + 300, 'keep the claim id until at + maxClaimAge')
  assert.deepEqual(Object.keys(r), ['ok', 'id', 'body', 'delegation', 'until'])
  assert.ok(Object.isFrozen(r))
})

test('claim-shape: keys, forms, sig', () => {
  for (const [name, over] of [['extra key', { x: 1 }], ['no data', { data: '__drop__' }], ['data an array', { data: [1] }],
    ['delegation not an id', { delegation: 'x' }], ['scope not a scope', { scope: 'Post' }], ['scope an array', { scope: ['post'] }],
    ['data a string', { data: 'x' }], ['data a number', { data: 1 }], ['no request', { request: '__drop__' }], ['request a number', { request: 1 }], ['at negative', { at: -1 }], ['at a string', { at: '1' }]]) {
    assert.deepEqual(call({ claim: claim(over).text }), refused('claim-shape'), name)
  }
  const good = JSON.parse(C.text).sig.signature
  for (const sig of [{}, { signature: 'ab' }, { signature: good, x: 1 }, { a: good, signature: good }, { signature: 'A'.repeat(128) },
    { signature: good + '0' }, { signature: 'x' + good }, { signature: [good] }, { other: good }]) {
    assert.deepEqual(call({ claim: claim({}, { sig }).text }), refused('claim-shape'), JSON.stringify(sig).slice(0, 30))
  }
  assert.deepEqual(call({ claim: 'x' }), refused('envelope-encoding'))
  assert.deepEqual(call({ claim: delegation }), refused('type'))
})

test('claim-scope and claim-request: the scope and request the relying party needs, exactly', () => {
  assert.deepEqual(call({ claim: claim({ scope: 'read' }).text }), refused('claim-scope'), 'a claim for read where post is needed')
  assert.deepEqual(call({ claim: claim({ scope: 'read' }).text }, { scope: 'read' }), { ok: true })
  assert.deepEqual(call({ claim: claim({ request: 'GET https://app.example/posts' }).text }), refused('claim-request'))
  assert.deepEqual(call({}, { request: REQUEST + ' ' }), refused('claim-request'))
})

test('revocations by subject key in the call apply to claims and delegations', () => {
  const subject = hex(ed25519.getPublicKey(APP))
  assert.deepEqual(call({}, { revoked: [subject] }), refused('revoked'))
  const r = v.verifyDelegation({ delegation, root, head }, { now: NOW, scope: 'post', revoked: [subject] })
  assert.deepEqual({ ...r }, refused('revoked'))
})

test("claim-time: inside the delegation's window too", () => {
  assert.deepEqual(call({ claim: claim({ at: body.nbf - 61 }).text }, { now: body.nbf + 100 }), refused('claim-time'), 'before nbf - skew')
  assert.deepEqual(call({ claim: claim({ at: body.nbf - 60 }).text }, { now: body.nbf + 100 }), { ok: true })
  assert.deepEqual(call({ claim: claim({ at: body.exp }).text }, { now: body.exp - 1 }), refused('claim-time'), 'at or after exp')
})

test('the call is read once: a revoked list cannot change between its check and its use', () => {
  let reads = 0
  const list = new Proxy([del.id], { get (t, k) { if (k === '0') return reads++ === 0 ? del.id : 'f'.repeat(64); return Reflect.get(t, k) } })
  assert.deepEqual(call({}, { revoked: list }), refused('revoked'))
})

test("the delegation is verified in full, with the claim's scope", () => {
  assert.deepEqual(call({ claim: claim({ scope: 'admin' }).text }, { scope: 'admin' }), refused('scope'))
  assert.deepEqual(call({ head: 'x' }), refused('head'))
  assert.deepEqual(call({}, { revoked: [del.id] }), refused('revoked'))
  assert.deepEqual(call({}, { minHeadAt: NOW }), refused('stale'))
})

test('claim-delegation: a claim names the delegation it is made under', () => {
  assert.deepEqual(call({ claim: claim({ delegation: 'f'.repeat(64) }).text }), refused('claim-delegation'))
})

test('claim-time: no older than maxClaimAge, no later than skew', () => {
  const now = NOW + 1000 // well inside the delegation's window
  assert.deepEqual(call({ claim: claim({ at: now - 300 }).text }, { now }), { ok: true })
  assert.deepEqual(call({ claim: claim({ at: now - 301 }).text }, { now }), refused('claim-time'))
  assert.deepEqual(call({ claim: claim({ at: now + 60 }).text }, { now }), { ok: true })
  assert.deepEqual(call({ claim: claim({ at: now + 61 }).text }, { now }), refused('claim-time'))
})

test('the signature: by the subject key, over the signed bytes', () => {
  assert.deepEqual(call({ claim: claim({}, { secret: W }).text }), refused('sig-invalid'))
  const { payload } = envelope.seal('claim', { delegation: del.id, scope: 'post', request: REQUEST, at: NOW - 5, data: {} })
  const overPayload = hex(ed25519.sign(new TextEncoder().encode(payload), APP))
  assert.deepEqual(call({ claim: envelope.wrap(payload, { signature: overPayload }) }), refused('sig-invalid'))
})

test('programming errors and totality', () => {
  assert.throws(() => verifier({ ...CONFIG, maxClaimAge: -1 }), { name: 'TypeError' })
  for (const c of [{ now: NOW }, { ...CALL, scope: undefined }, { ...CALL, request: undefined }, { ...CALL, request: 1 }]) {
    assert.throws(() => v.verifyClaim({ claim: C.text, delegation, root, head }, c), { name: 'TypeError' })
  }
  for (const x of [undefined, null, 1, {}, []]) assert.equal(v.verifyClaim({ claim: x, delegation, root, head }, CALL).ok, false)
  const hostile = new Proxy({}, { get () { throw new Error('trap') } })
  assert.deepEqual({ ...v.verifyClaim(hostile, CALL) }, { ok: false, reason: 'envelope-encoding' })
})

test('a foreign error opening the claim (patched built-ins in the hash library) fails closed, never throws', () => {
  const original = Uint8Array.prototype.fill
  Uint8Array.prototype.fill = function () { throw new Error('patched') }
  let out
  try { out = { ...v.verifyClaim({ claim: C.text, delegation, root, head }, CALL) } } catch (e) { out = { threw: String(e) } } finally { Uint8Array.prototype.fill = original }
  assert.deepEqual(out, { ok: false, reason: 'envelope-encoding' })
})
