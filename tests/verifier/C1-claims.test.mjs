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
// The request a claim is for, as a DPoP proof names it (RFC 9449 §4.2): the method and the URL without query and fragment.
const URL_ = 'https://app.example/posts'
const DIGEST = Buffer.alloc(32, 7).toString('base64') // RFC 9530 sha-256 of a body
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
const h = envelope.seal('head', { identity: IDENTITY, epoch: 1, memberships: [IDENTITY], authority: [ROOT], revoked: [], at: NOW - 100 })
const head = envelope.wrap(h.payload, { signature: hex(ed25519.sign(envelope.signedBytes(h.payload), W)), witness: WITNESS })
const lg = envelope.seal('logged', { identity: IDENTITY, delegation: del.id, at: NOW - 10 })
const logged = envelope.wrap(lg.payload, { signature: hex(ed25519.sign(envelope.signedBytes(lg.payload), W)), witness: WITNESS })

function claim (over = {}, { secret = APP, sig } = {}) {
  const b = { delegation: del.id, scope: 'post', htm: 'POST', htu: URL_, at: NOW - 5, data: { text: 'hello' }, ...over }
  for (const k of Object.keys(b)) if (b[k] === '__drop__') delete b[k]
  const { payload, id } = envelope.seal('claim', b)
  return { text: envelope.wrap(payload, sig ?? { signature: hex(ed25519.sign(envelope.signedBytes(payload), secret)) }), id }
}
const C = claim()
const CALL = Object.freeze({ now: NOW, scope: 'post', method: 'POST', url: URL_, revoked: [] })
const call = (records = {}, ctx = {}) => {
  const r = v.verifyClaim({ claim: C.text, delegation, root, head, logged, ...records }, { ...CALL, ...ctx })
  return r.ok ? { ok: true } : { ...r }
}
const refused = (reason) => ({ ok: false, reason })

test('a claim under a valid delegation is accepted, with its id, body and the delegation', () => {
  const r = v.verifyClaim({ claim: C.text, delegation, root, head, logged }, CALL)
  assert.equal(r.ok, true, JSON.stringify(r))
  assert.equal(r.id, C.id)
  assert.equal(r.body.data.text, 'hello')
  assert.equal(r.delegation.id, del.id)
  assert.equal(r.until, NOW - 5 + 301, 'until is the first time the claim is refused: at + maxClaimAge + 1')
  assert.deepEqual(Object.keys(r), ['ok', 'id', 'body', 'delegation', 'until'])
  assert.ok(Object.isFrozen(r))
})

test('claim-shape: keys, forms, sig', () => {
  for (const [name, over] of [['extra key', { x: 1 }], ['no data', { data: '__drop__' }], ['data an array', { data: [1] }],
    ['delegation not an id', { delegation: 'x' }], ['scope not a scope', { scope: 'Post' }], ['scope an array', { scope: ['post'] }],
    ['data a string', { data: 'x' }], ['data a number', { data: 1 }], ['no htm', { htm: '__drop__' }], ['htm lower case', { htm: 'post' }], ['htm empty', { htm: '' }], ['htm after a lower-case letter', { htm: 'xPOST' }], ['htm then a lower-case letter', { htm: 'POSTx' }],
    ['htm of 17 letters', { htm: 'A'.repeat(17) }], ['htu in an array', { htu: [URL_] }], ['htu an object', { htu: {} }], ['htu after a letter', { htu: 'x' + URL_ }], ['no htu', { htu: '__drop__' }], ['htu a number', { htu: 1 }],
    ['htu without a path', { htu: AUD }], ['htu with a query', { htu: URL_ + '?a=1' }], ['htu with a fragment', { htu: URL_ + '#a' }],
    ['htu http', { htu: 'http://app.example/posts' }], ['htu origin not canonical', { htu: 'https://APP.example/posts' }],
    ['htu with a space', { htu: URL_ + ' x' }], ['htu lower-case escape', { htu: URL_ + '%2f' }], ['htu a bare percent', { htu: URL_ + '%' }],
    ['nonce empty', { nonce: '' }], ['nonce with a quote', { nonce: 'a"b' }], ['nonce with a space', { nonce: 'a b' }], ['nonce a number', { nonce: 1 }],
    ['digest short', { content_digest: DIGEST.slice(4) }], ['digest not canonical', { content_digest: DIGEST.slice(0, 42) + 'P=' }], ['digest hex', { content_digest: '07'.repeat(32) }], ['digest after a letter', { content_digest: 'x' + DIGEST }], ['digest then a letter', { content_digest: DIGEST + 'x' }],
    ['at negative', { at: -1 }], ['at a string', { at: '1' }]]) {
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

test('claim-scope: the scope the relying party needs, exactly', () => {
  assert.deepEqual(call({ claim: claim({ scope: 'read' }).text }), refused('claim-scope'), 'a claim for read where post is needed')
  assert.deepEqual(call({ claim: claim({ scope: 'read' }).text }, { scope: 'read' }), { ok: true })
})

test('claim-method and claim-url: the request, as DPoP binds it (htm, htu)', () => {
  assert.deepEqual(call({ claim: claim({ htm: 'GET' }).text }), refused('claim-method'))
  assert.deepEqual(call({}, { method: 'PUT' }), refused('claim-method'))
  assert.deepEqual(call({}, { url: URL_ + '/1' }), refused('claim-url'))
  assert.deepEqual(call({ claim: claim({ htu: URL_ + '/' }).text }), refused('claim-url'))
  // The query and fragment are not part of htu: the relying party may pass the URL it received.
  assert.deepEqual(call({}, { url: URL_ + '?page=2#top' }), { ok: true })
  assert.deepEqual(call({}, { url: URL_ + '#top?x' }), { ok: true })
  assert.deepEqual(call({}, { url: URL_ + 'x?' }), refused('claim-url'))
  // htu's origin is the audience: a claim for another origin's URL is refused even where that origin passes it.
  const other = claim({ htu: 'https://other.example/posts' }).text
  assert.deepEqual(call({ claim: other }), refused('claim-url'))
  assert.deepEqual(call({ claim: other }, { url: 'https://other.example/posts' }), refused('claim-url'))
  // A received URL outside the grammar matches no claim, and is refused rather than thrown: it comes from the client.
  for (const url of ['https://app.example/a b', 'https://app.example', 'http://app.example/posts', '', 'https://app.example/%zz']) {
    assert.deepEqual(call({}, { url }), refused('claim-url'), url)
  }
  for (const path of ['/', "/a-._~!$&'()*+,;=:@/b", '/%2F%C3%A9']) {
    assert.deepEqual(call({ claim: claim({ htu: AUD + path }).text }, { url: AUD + path }), { ok: true }, path)
  }
})

test('claim-nonce: present exactly when the relying party issued one, and equal to it', () => {
  assert.deepEqual(call({ claim: claim({ nonce: 'n-1' }).text }, { nonce: 'n-1' }), { ok: true })
  assert.deepEqual(call({ claim: claim({ nonce: 'n-1' }).text }, { nonce: 'n-2' }), refused('claim-nonce'))
  assert.deepEqual(call({ claim: claim({ nonce: 'n-1' }).text }), refused('claim-nonce'), 'a nonce the relying party did not issue')
  assert.deepEqual(call({}, { nonce: 'n-1' }), refused('claim-nonce'), 'no nonce where one was issued')
  assert.deepEqual(call({ claim: claim({ nonce: '!#[]~' }).text }, { nonce: '!#[]~' }), { ok: true }, "DPoP's NQCHAR")
})

test("claim-digest: present exactly when the relying party requires the body's digest, and equal to it", () => {
  const other = Buffer.alloc(32, 8).toString('base64')
  assert.deepEqual(call({ claim: claim({ content_digest: DIGEST }).text }, { contentDigest: DIGEST }), { ok: true })
  assert.deepEqual(call({ claim: claim({ content_digest: DIGEST }).text }, { contentDigest: other }), refused('claim-digest'))
  assert.deepEqual(call({ claim: claim({ content_digest: DIGEST }).text }), refused('claim-digest'))
  assert.deepEqual(call({}, { contentDigest: DIGEST }), refused('claim-digest'))
})

test('the request is checked in order: method, url, nonce, digest; all before the delegation', () => {
  const bad = claim({ htm: 'GET', htu: URL_ + '/x', nonce: 'a', content_digest: DIGEST }).text
  assert.deepEqual(call({ claim: bad, head: 'x' }), refused('claim-method'))
  assert.deepEqual(call({ claim: bad, head: 'x' }, { method: 'GET' }), refused('claim-url'))
  assert.deepEqual(call({ claim: bad, head: 'x' }, { method: 'GET', url: URL_ + '/x' }), refused('claim-nonce'))
  assert.deepEqual(call({ claim: bad, head: 'x' }, { method: 'GET', url: URL_ + '/x', nonce: 'a' }), refused('claim-digest'))
  assert.deepEqual(call({ claim: bad, head: 'x' }, { method: 'GET', url: URL_ + '/x', nonce: 'a', contentDigest: DIGEST }), refused('head'))
})

test('revocations by subject key in the call apply to claims and delegations', () => {
  const subject = hex(ed25519.getPublicKey(APP))
  assert.deepEqual(call({}, { revoked: [subject] }), refused('revoked'))
  const r = v.verifyDelegation({ delegation, root, head, logged }, { now: NOW, scope: 'post', revoked: [subject] })
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

test('until: the claim verifies before it and is refused from it on, so a store that drops the id at until is enough', () => {
  const { until } = v.verifyClaim({ claim: C.text, delegation, root, head, logged }, CALL)
  assert.deepEqual(call({}, { now: until - 1 }), { ok: true })
  assert.deepEqual(call({}, { now: until }), refused('claim-time'))
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
  const { payload } = envelope.seal('claim', { delegation: del.id, scope: 'post', htm: 'POST', htu: URL_, at: NOW - 5, data: {} })
  const overPayload = hex(ed25519.sign(new TextEncoder().encode(payload), APP))
  assert.deepEqual(call({ claim: envelope.wrap(payload, { signature: overPayload }) }), refused('sig-invalid'))
})

test('programming errors and totality', () => {
  assert.throws(() => verifier({ ...CONFIG, maxClaimAge: -1 }), { name: 'TypeError' })
  for (const c of [{ now: NOW }, { ...CALL, scope: undefined }, { ...CALL, method: undefined }, { ...CALL, method: 'post' }, { ...CALL, method: '' },
    { ...CALL, url: undefined }, { ...CALL, url: 1 }, { ...CALL, nonce: '' }, { ...CALL, nonce: 'a b' }, { ...CALL, nonce: 1 },
    { ...CALL, contentDigest: '07'.repeat(32) }, { ...CALL, contentDigest: null }]) {
    assert.throws(() => v.verifyClaim({ claim: C.text, delegation, root, head, logged }, c), { name: 'TypeError' })
  }
  for (const x of [undefined, null, 1, {}, []]) assert.equal(v.verifyClaim({ claim: x, delegation, root, head, logged }, CALL).ok, false)
  const hostile = new Proxy({}, { get () { throw new Error('trap') } })
  assert.deepEqual({ ...v.verifyClaim(hostile, CALL) }, { ok: false, reason: 'envelope-encoding' })
})

test('a foreign error opening the claim (patched built-ins in the hash library) fails closed, never throws', () => {
  const original = Uint8Array.prototype.fill
  Uint8Array.prototype.fill = function () { throw new Error('patched') }
  let out
  try { out = { ...v.verifyClaim({ claim: C.text, delegation, root, head, logged }, CALL) } } catch (e) { out = { threw: String(e) } } finally { Uint8Array.prototype.fill = original }
  assert.deepEqual(out, { ok: false, reason: 'envelope-encoding' })
})
