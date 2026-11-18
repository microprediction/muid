// muid/worker against the real parts: a hand-off built as the id page builds it, a witness service in memory, and a
// relying party's adapter over the real verifier. What the worker makes is accepted; what it is given wrongly it
// refuses with a reason, before anything is signed or sent.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { ed25519 } from '@noble/curves/ed25519.js'
import { newKey, subjectOf, accept, enrol, claim, request } from './impl.mjs'
import { records as page } from '../id/impl.mjs'
import { witness, witnessService, memoryHoldings, memoryLog } from '../witness/impl.mjs'
import { relyingParty, memoryStore } from '../adapter/impl.mjs'
import { verifier as verifierModule, envelope, root as rootModule, delegation as delegationModule } from '../impl.mjs'
import { make, KEY, RP_ID, ORIGIN } from '../assertion/helpers.mjs'

const hex = (b) => Buffer.from(b).toString('hex')
const plain = (x) => JSON.parse(JSON.stringify(x))
const bodyOf = (text) => plain(envelope.open(text, 'claim').body)
const NOW = 1_800_000_000
const W = Uint8Array.from({ length: 32 }, (_, i) => 140 + i)
const WITNESS_KEYS = [{ key: hex(ed25519.getPublicKey(W)), nbf: 0, exp: 1_900_000_000 }]
const AUD = 'https://node.example'
const URL_ = 'https://node.example/blobs'
const AT = 'https://id.example/witness/'
const ROOT_TEXT = envelope.wrap(envelope.seal('root', { pub: KEY, rp_id: RP_ID }).payload)
const ROOT = rootModule.checkRoot(ROOT_TEXT, { rpId: RP_ID }).id
const IDENTITY = rootModule.identityOf(ROOT)
const SECRET = hex(Uint8Array.from({ length: 32 }, (_, i) => 9 + i))

// A witness service holding the identity's root, reached by a fetch that counts what it is asked.
async function deployment ({ now = NOW } = {}) {
  let at = now
  const w = witness({ rpId: RP_ID, origin: ORIGIN, witnessKeys: WITNESS_KEYS, key: WITNESS_KEYS[0].key, sign: (b) => hex(ed25519.sign(b, W)), contestWindow: 60, skew: 60, maxLifetime: 2_592_000 })
  const svc = witnessService({ witness: w, holdings: memoryHoldings(), log: memoryLog(), clock: () => at, headInterval: 0 })
  const asked = []
  const fetch = async (url, init) => {
    asked.push([init?.method ?? 'GET', url])
    assert.equal(url.startsWith(AT), true, url)
    return svc.handle(new Request('http://witness/' + url.slice(AT.length), init))
  }
  const registered = await (await fetch(AT + 'v1/records', { method: 'POST', body: JSON.stringify({ identity: IDENTITY, type: 'root', text: ROOT_TEXT }) })).json()
  assert.equal(registered.ok, true, registered.reason)
  asked.length = 0
  return { fetch, asked, svc, advance: (s) => { at += s }, now: () => at }
}
// The id page's hand-off for a delegation to `subject`, signed by the identity's passkey.
function handOffFor (subject, { scopes = ['store.blob', 'store.ref'], now = NOW, lifetime = 86_400, aud = AUD } = {}) {
  const d = page.delegation({ agent: 'drive', identity: IDENTITY, membership: IDENTITY, root: ROOT, subject, aud, scopes, now, lifetime })
  return page.handOff(d.payload, make({ covers: [d.id] }))
}
const relying = (clock) => relyingParty({
  verifier: verifierModule.verifier({ rpId: RP_ID, origin: ORIGIN, audience: AUD, witnessKeys: WITNESS_KEYS, skew: 60, maxLifetime: 2_592_000, maxStaleness: 86_400, maxClaimAge: 300 }),
  store: memoryStore(),
  clock
})

test('a new key: 32 random bytes, and the public key the owner gives the id page', () => {
  const k = newKey()
  assert.match(k.secret, /^[0-9a-f]{64}$/)
  assert.equal(k.subject, hex(ed25519.getPublicKey(Buffer.from(k.secret, 'hex'))))
  assert.notEqual(newKey().secret, k.secret)
  const fixed = newKey((bytes) => { assert.equal(bytes.length, 32); return bytes.fill(7) })
  assert.deepEqual(fixed, { secret: '07'.repeat(32), subject: subjectOf('07'.repeat(32)) })
  for (const bad of [undefined, 'x', '07'.repeat(31), '07'.repeat(33), 'AB'.repeat(32), Buffer.alloc(32), { toString: () => '07'.repeat(32) }, ['07'.repeat(32)]]) {
    assert.throws(() => subjectOf(bad), { message: 'a worker secret is 64 lowercase hex digits' })
  }
})

test('accept: the hand-off countersigned is a delegation the core accepts; anything else is refused with a reason', () => {
  const subject = subjectOf(SECRET)
  const h = handOffFor(subject)
  const a = accept(h, SECRET)
  const c = delegationModule.checkDelegation(a.delegation, { rootKey: KEY, rpId: RP_ID, origin: ORIGIN, now: NOW + 10, skew: 60, maxLifetime: 2_592_000 })
  assert.equal(c.ok, true, JSON.stringify(c))
  assert.equal(a.id, c.id)
  assert.deepEqual(a.body, { agent: 'drive', identity: IDENTITY, membership: IDENTITY, root: ROOT, subject, aud: AUD, scopes: ['store.blob', 'store.ref'], nbf: NOW, exp: NOW + 86_400 })
  // For another key: refused, and nothing is signed.
  assert.throws(() => accept(handOffFor(subjectOf('07'.repeat(32))), SECRET), { message: 'that delegation is for another key' })
  const { payload, root } = JSON.parse(h)
  for (const bad of ['', 'x', '{', 'null', '7', '[]', '{}', JSON.stringify({ payload }), JSON.stringify({ payload, root: null }), JSON.stringify({ payload, root: 'x' }),
    JSON.stringify({ payload: 7, root }), JSON.stringify({ payload: 'x', root }), JSON.stringify({ payload: envelope.seal('root', { pub: KEY, rp_id: RP_ID }).payload, root }),
    // A delegation by its type, without what a delegation holds: scopes that are a list, an identity.
    JSON.stringify({ payload: envelope.seal('delegation', { subject, identity: IDENTITY }).payload, root }),
    JSON.stringify({ payload: envelope.seal('delegation', { subject, identity: IDENTITY, scopes: 'store.blob' }).payload, root }),
    JSON.stringify({ payload: envelope.seal('delegation', { subject, scopes: ['store.blob'] }).payload, root }),
    JSON.stringify({ payload: envelope.seal('delegation', { subject, scopes: ['store.blob'], identity: 7 }).payload, root })]) {
    assert.throws(() => accept(bad, SECRET), { message: 'that is not a hand-off from the id page' }, bad)
  }
  assert.throws(() => accept(h, 'x'), { message: 'a worker secret is 64 lowercase hex digits' })
})

test('enrol, then a request: the five records are what a relying party at the audience accepts, once', async () => {
  const d = await deployment()
  const w = await enrol({ handOff: handOffFor(subjectOf(SECRET)), secret: SECRET, witness: AT, fetch: d.fetch })
  assert.deepEqual(d.asked, [['POST', AT + 'v1/delegations'], ['GET', AT + `v1/identities/${IDENTITY}/records`]])
  assert.deepEqual(Object.keys(w), ['identity', 'id', 'agent', 'aud', 'scopes', 'nbf', 'exp', 'subject', 'delegation', 'root', 'logged'])
  assert.deepEqual([w.identity, w.agent, w.aud, w.scopes, w.nbf, w.exp, w.subject, w.root], [IDENTITY, 'drive', AUD, ['store.blob', 'store.ref'], NOW, NOW + 86_400, subjectOf(SECRET), ROOT_TEXT])
  assert.equal(Object.isFrozen(w) && Object.isFrozen(w.scopes), true)
  assert.equal(JSON.stringify(w).includes(SECRET), false, 'what is kept holds no secret')
  assert.equal(envelope.open(w.logged, 'logged').body.delegation, w.id)

  d.advance(100)
  d.asked.length = 0
  const call = { scope: 'store.blob', method: 'PUT', url: URL_, data: { size: 3 }, at: d.now() }
  const records = await request(w, SECRET, call, { witness: AT, fetch: d.fetch })
  assert.deepEqual(d.asked, [['GET', AT + `v1/identities/${IDENTITY}/head`]])
  assert.deepEqual(Object.keys(records), ['claim', 'delegation', 'root', 'head', 'logged'])
  assert.deepEqual([records.delegation, records.root, records.logged], [w.delegation, w.root, w.logged])
  assert.deepEqual(bodyOf(records.claim), { delegation: w.id, scope: 'store.blob', htm: 'PUT', htu: URL_, at: d.now(), data: { size: 3 } })
  const rp = relying(d.now)
  const check = { now: d.now(), scope: 'store.blob', method: 'PUT', url: URL_, revoked: [] }
  let ran = 0
  const first = await rp.acceptClaim(records, check, (r) => { ran++; return r.delegation.body.identity })
  assert.equal(first.ok, true, JSON.stringify(first))
  assert.equal(first.value, IDENTITY, 'the identity that delegated is the one credited')
  assert.deepEqual({ ...(await rp.acceptClaim(records, check, () => ran++)) }, { ok: false, reason: 'replay' })
  assert.equal(ran, 1)
  // What was kept, stored and read back as plain data, works as it did.
  const again = await request(JSON.parse(JSON.stringify(w)), SECRET, { ...call, data: { size: 4 } }, { witness: AT, fetch: d.fetch })
  assert.equal((await rp.acceptClaim(again, check, () => {})).ok, true)
  // A nonce and a body digest, when the service checks them, are in the claim.
  const bound = bodyOf(claim(w, SECRET, { ...call, nonce: 'n-1', contentDigest: 'sha-256=:x:' }))
  assert.deepEqual([bound.nonce, bound.content_digest], ['n-1', 'sha-256=:x:'])
  assert.deepEqual(bodyOf(claim(w, SECRET, { scope: 'store.ref', method: 'GET', url: URL_, at: d.now() })).data, {}, 'no data is empty data')
})

test('a claim is made only by the key enrolled, under a scope it was given, while the delegation is in force', async () => {
  const d = await deployment()
  const w = await enrol({ handOff: handOffFor(subjectOf(SECRET)), secret: SECRET, witness: AT, fetch: d.fetch })
  const call = { scope: 'store.blob', method: 'PUT', url: URL_, at: NOW + 5 }
  assert.throws(() => claim(w, '07'.repeat(32), call), { message: "that enrolment is another key's" })
  assert.throws(() => claim(w, 'x', call), { message: 'a worker secret is 64 lowercase hex digits' })
  assert.throws(() => claim(w, SECRET, { ...call, scope: 'store' }), { message: 'the delegation does not give that scope' })
  const lapsed = { message: 'the delegation is not in force at that time: enrol with a renewed one' }
  for (const at of [NOW - 1, NOW + 86_400, NOW + 0.5, undefined, String(NOW + 5)]) assert.throws(() => claim(w, SECRET, { ...call, at }), lapsed, String(at))
  for (const at of [NOW, NOW + 86_399]) assert.equal(envelope.open(claim(w, SECRET, { ...call, at }), 'claim').body.at, at)
  d.asked.length = 0
  await assert.rejects(request(w, SECRET, { ...call, scope: 'store' }, { witness: AT, fetch: d.fetch }), { message: 'the delegation does not give that scope' })
  assert.deepEqual(d.asked, [], 'the witness is not asked for a head for a claim that is not made')
})

test('the witness: refusing the delegation, not holding the root, giving no head, or not answering, each is said', async () => {
  const d = await deployment()
  const h = handOffFor(subjectOf(SECRET))
  // Expired before it is logged: the witness refuses it, and the worker says why.
  await assert.rejects(enrol({ handOff: handOffFor(subjectOf(SECRET), { now: NOW - 200_000 }), secret: SECRET, witness: AT, fetch: d.fetch }), { message: /^the witness refused the delegation: [a-z-]+$/ })
  const answering = (answers) => async (url, init) => {
    const a = answers[new URL(url).pathname.split('/').pop()]
    return a === undefined ? d.fetch(url, init) : a()
  }
  const json = (status, body) => () => new Response(JSON.stringify(body), { status })
  const tries = [
    [{ delegations: json(422, { ok: false }) }, 'the witness refused the delegation: 422'],
    [{ delegations: json(200, { ok: true }) }, 'the witness refused the delegation: 200'],
    [{ delegations: json(200, { ok: true, logged: 7 }) }, 'the witness refused the delegation: 200'],
    [{ delegations: json(422, { ok: false, reason: 'expired', logged: 'x' }) }, 'the witness refused the delegation: expired'],
    [{ delegations: json(422, { ok: false, reason: 7, logged: 'x' }) }, 'the witness refused the delegation: 422'],
    [{ delegations: json(200, null) }, 'the witness did not answer'],
    [{ delegations: json(200, 7) }, 'the witness did not answer'],
    [{ delegations: () => new Response('<html>', { status: 502 }) }, 'the witness did not answer'],
    [{ delegations: () => { throw new Error('offline') } }, 'the witness did not answer'],
    [{ records: json(200, {}) }, 'the witness does not hold the record of the root that signed the delegation'],
    [{ records: json(200, { roots: 'x' }) }, 'the witness does not hold the record of the root that signed the delegation'],
    [{ records: json(200, { roots: ['x', 7, envelope.wrap(envelope.seal('root', { pub: KEY, rp_id: 'other.example' }).payload)] }) }, 'the witness does not hold the record of the root that signed the delegation'],
    [{ records: json(404, { ok: false, reason: 'unknown-identity' }) }, 'the witness does not hold the record of the root that signed the delegation']
  ]
  for (const [answers, message] of tries) await assert.rejects(enrol({ handOff: h, secret: SECRET, witness: AT, fetch: answering(answers) }), { message }, message)
  // The root is found among others, whatever else the witness lists.
  const found = await enrol({ handOff: h, secret: SECRET, witness: AT, fetch: answering({ records: json(200, { roots: ['x', ROOT_TEXT] }) }) })
  assert.equal(found.root, ROOT_TEXT)
  for (const witnessUrl of [undefined, 7, 'https://id.example/witness']) {
    await assert.rejects(enrol({ handOff: h, secret: SECRET, witness: witnessUrl, fetch: d.fetch }), { message: 'the witness is a URL ending in /' })
  }
  const call = { scope: 'store.blob', method: 'PUT', url: URL_, at: NOW + 5 }
  await assert.rejects(request(found, SECRET, call, { witness: AT, fetch: answering({ head: json(409, { ok: false, reason: 'no-head' }) }) }), { message: 'the witness gave no head: no-head' })
  await assert.rejects(request(found, SECRET, call, { witness: AT, fetch: answering({ head: json(200, {}) }) }), { message: 'the witness gave no head: 200' })
  await assert.rejects(request(found, SECRET, call, { witness: AT, fetch: answering({ head: () => { throw new Error('offline') } }) }), { message: 'the witness did not answer' })
})

test('by default the worker asks with the platform\'s fetch', async () => {
  const d = await deployment()
  const real = globalThis.fetch
  globalThis.fetch = d.fetch
  try {
    const w = await enrol({ handOff: handOffFor(subjectOf(SECRET)), secret: SECRET, witness: AT })
    const records = await request(w, SECRET, { scope: 'store.blob', method: 'PUT', url: URL_, at: NOW + 5 }, { witness: AT })
    assert.equal((await relying(() => NOW + 5).acceptClaim(records, { now: NOW + 5, scope: 'store.blob', method: 'PUT', url: URL_, revoked: [] }, () => {})).ok, true)
  } finally { globalThis.fetch = real }
})
