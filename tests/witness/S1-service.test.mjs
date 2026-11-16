// The witness service: the witness's decisions behind a small HTTP API (fetch-style Request and Response), with a
// store that serialises each identity's changes and a log every signed record is appended to before it is kept.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { ed25519 } from '@noble/curves/ed25519.js'
import { envelope } from '../impl.mjs'
import { make } from '../assertion/helpers.mjs'
import { secretOf, partySigned, commitmentOf } from '../membership/translate.mjs'
import { witnessService, memoryHoldings, memoryLog } from './impl.mjs'
import { w, IDENTITY, BASE, WINDOW, M2, mBody, mId, signed, rootText, rootId } from './fixtures.mjs'

const hex = (b) => Buffer.from(b).toString('hex')
// A delegation from root a to an app's key, valid from BASE - 10 for an hour.
const APP = Uint8Array.from({ length: 32 }, (_, i) => 60 + i)
const del = envelope.seal('delegation', { agent: 'worker', identity: IDENTITY, membership: IDENTITY, root: rootId('a'), subject: hex(ed25519.getPublicKey(APP)),
  aud: 'https://app.example', scopes: ['post'], nbf: BASE - 10, exp: BASE + 3600 })
const DELEGATION = envelope.wrap(del.payload, { root: make({ covers: [del.id], secret: secretOf('a') }),
  subject: hex(ed25519.sign(Buffer.concat([Buffer.from('muid/v1/accept\n'), Buffer.from(del.id, 'hex')]), APP)) })

const URL_ = 'https://witness.example'
function setup ({ log = memoryLog(), holdings = memoryHoldings(), headInterval = 60 } = {}) {
  let now = BASE
  const svc = witnessService({ witness: w, holdings, log, clock: () => now, headInterval })
  const call = async (method, path, body) => {
    const init = { method, headers: { 'content-type': 'application/json' } }
    if (body !== undefined) init.body = typeof body === 'string' ? body : JSON.stringify(body)
    const res = await svc.handle(new Request(URL_ + path, init))
    const text = await res.text()
    return { status: res.status, body: text === '' ? undefined : JSON.parse(text), type: res.headers.get('content-type') }
  }
  const submit = (type, text, identity = IDENTITY) => call('POST', '/v1/records', { identity, type, text })
  return { svc, log, holdings, call, submit, at: (t) => { now = t } }
}
const bodyOf = (text, type) => envelope.open(text, type).body

test('records submitted in turn: the anchor is signed, logged and served; the tick settles it', async () => {
  const s = setup()
  assert.deepEqual((await s.submit('root', rootText('a'))).body, { ok: true, signed: [] })
  assert.equal((await s.submit('membership', signed('membership', M2, 'a'))).status, 200)
  await s.submit('root', rootText('b'))
  const r = await s.submit('membership', signed('membership', M2, 'b'))
  assert.equal(r.status, 200)
  assert.equal(r.type, 'application/json')
  assert.equal(r.body.signed.length, 1)
  assert.deepEqual({ ...bodyOf(r.body.signed[0], 'anchor') }, { at: BASE, identity: IDENTITY, record: mId(M2) })
  assert.deepEqual(s.log.entries(), r.body.signed)
  const held = (await s.call('GET', `/v1/identities/${IDENTITY}/records`)).body
  assert.deepEqual(held.anchors, r.body.signed)
  assert.equal(held.memberships.length, 2)
  assert.deepEqual(Object.keys(held).sort(), ['anchors', 'cancelled', 'contests', 'freezes', 'matured', 'memberships', 'notices', 'revocations', 'roots', 'settlements'])
  s.at(BASE + WINDOW - 1)
  assert.deepEqual(await s.svc.tick(), [])
  s.at(BASE + WINDOW)
  const settled = await s.svc.tick()
  assert.equal(settled.length, 1)
  assert.equal(bodyOf(settled[0], 'settlement').outcome, mId(M2))
  assert.deepEqual(s.log.entries().slice(1), settled)
  const head = (await s.call('GET', `/v1/identities/${IDENTITY}/head`)).body.head
  assert.equal(bodyOf(head, 'head').epoch, 2)
})

test('a refused record is 422 with its reason, and changes nothing', async () => {
  const s = setup()
  await s.submit('root', rootText('a'))
  const r = await s.submit('root', rootText('b'))
  assert.deepEqual(r, { status: 422, body: { ok: false, reason: 'root-unnamed' }, type: 'application/json' })
  assert.equal((await s.call('GET', `/v1/identities/${IDENTITY}/records`)).body.roots.length, 1)
  assert.deepEqual((await s.submit('nonsense', 'x')).body, { ok: false, reason: 'type' })
  assert.deepEqual((await s.submit('anchor', 'x')).body, { ok: false, reason: 'type' })
  // A refusal for an identity the witness has never held leaves nothing behind for the tick.
  assert.equal((await s.submit('root', rootText('a'), 'e'.repeat(64))).body.reason, 'root-unnamed')
  assert.deepEqual(await s.svc.tick(), [])
  for (const type of ['root', 'membership', 'contest', 'freeze']) assert.equal((await s.submit(type, 'x')).body.reason, 'envelope-encoding', type)
})

test('malformed requests: 400, 404, 405 and 413, each with its reason', async () => {
  const s = setup()
  const is = async (p, status, reason, label) => assert.deepEqual(await p, { status, body: { ok: false, reason }, type: 'application/json' }, label)
  await is(s.call('POST', '/v1/records', '{'), 400, 'json')
  await is(s.call('POST', '/v1/records'), 400, 'json') // no body at all
  await is(s.call('POST', '/v1/revocations', '{'), 400, 'json')
  for (const b of ['[]', 'null', '1', '"x"', JSON.stringify([IDENTITY])]) await is(s.call('POST', '/v1/records', b), 400, 'request', b)
  await is(s.call('POST', '/v1/records', { identity: IDENTITY, type: 'root' }), 400, 'request', 'no text')
  for (const identity of ['x', 'x' + IDENTITY, IDENTITY + 'x', [IDENTITY]]) {
    await is(s.call('POST', '/v1/records', { identity, type: 'root', text: 'x' }), 400, 'request', JSON.stringify(identity))
  }
  await is(s.call('POST', '/v1/records', { identity: IDENTITY, type: 1, text: 'x' }), 400, 'request')
  await is(s.call('POST', '/v1/revocations', { identity: IDENTITY, text: 'x', delegation: 1 }), 400, 'request')
  // The body limit, 131,072 characters: at it, the request is read; past it, refused.
  const sized = (n) => { const b = JSON.stringify({ identity: IDENTITY, type: 'root', text: '' }); return b.replace('"text":""', '"text":"' + 'x'.repeat(n - b.length) + '"') }
  assert.equal(sized(131_072).length, 131_072)
  await is(s.call('POST', '/v1/records', sized(131_072)), 422, 'envelope-encoding')
  await is(s.call('POST', '/v1/records', sized(131_073)), 413, 'too-large')
  for (const path of ['/v1/nothing', `/v1/identities/${IDENTITY}/other`, '/v1/identities/x/head', `/v1/identities/${IDENTITY}/headx`,
    `/x/v1/identities/${IDENTITY}/head`]) await is(s.call('GET', path), 404, 'not-found', path)
  await is(s.call('GET', `/v1/identities/${IDENTITY}/records`), 404, 'unknown-identity', 'nothing held')
  await is(s.call('GET', `/v1/identities/${IDENTITY}/head`), 404, 'unknown-identity')
  await is(s.call('GET', '/v1/records'), 405, 'method')
  await is(s.call('DELETE', `/v1/identities/${IDENTITY}/head`), 405, 'method')
})

// Found by review: the body was buffered in full before its size was checked.
test('a body past the limit is refused without being read in full', async () => {
  let pulled = 0
  const chunk = new Uint8Array(16_384).fill(0x78)
  // 1 MiB, far past the limit: a reader that reads it all is caught by how much it pulled.
  const body = new ReadableStream({ pull (c) { if (pulled >= 1_048_576) { c.close(); return } pulled += chunk.length; c.enqueue(chunk) } })
  const res = await setup().svc.handle(new Request('https://witness.example/v1/records', { method: 'POST', body, duplex: 'half' }))
  assert.equal(res.status, 413)
  assert.ok(pulled < 131_072 + 4 * chunk.length, `read ${pulled} bytes`)
  // Several chunks below the limit are joined in order.
  const parts = ['{"ide', 'ntity":"x","t', 'ext":"x"}']
  const small = new ReadableStream({ start (c) { for (const p of parts) c.enqueue(new TextEncoder().encode(p)); c.close() } })
  assert.equal((await setup().svc.handle(new Request('https://witness.example/v1/records', { method: 'POST', body: small, duplex: 'half' }))).status, 400)
})

test('heads: signed when asked, reused within headInterval while nothing changes, and every one logged', async () => {
  const s = setup()
  await s.submit('root', rootText('a'))
  const h1 = (await s.call('GET', `/v1/identities/${IDENTITY}/head`)).body.head
  assert.equal(bodyOf(h1, 'head').at, BASE)
  s.at(BASE + 59)
  assert.deepEqual(await s.svc.tick(), [])
  assert.equal((await s.call('GET', `/v1/identities/${IDENTITY}/head`)).body.head, h1, 'a tick that signs nothing changes nothing')
  s.at(BASE + 60)
  const h2 = (await s.call('GET', `/v1/identities/${IDENTITY}/head`)).body.head
  assert.equal(bodyOf(h2, 'head').at, BASE + 60)
  // A change makes the next head fresh, even inside the interval: logging a delegation, then revoking it.
  const logged = (await s.call('POST', '/v1/delegations', { identity: IDENTITY, text: DELEGATION })).body.logged
  await s.call('POST', '/v1/revocations', { identity: IDENTITY, text: signed('revocation', { identity: IDENTITY, target: del.id, at: BASE }, 'a') })
  const h3 = (await s.call('GET', `/v1/identities/${IDENTITY}/head`)).body.head
  assert.deepEqual(Array.from(bodyOf(h3, 'head').revoked), [del.id])
  assert.deepEqual(s.log.entries(), [h1, h2, logged, h3])
  // Frozen: no head can be signed.
  await s.submit('freeze', signed('freeze', { identity: IDENTITY, membership: IDENTITY }, 'a'))
  assert.deepEqual((await s.call('GET', `/v1/identities/${IDENTITY}/head`)), { status: 409, body: { ok: false, reason: 'no-head' }, type: 'application/json' })
})

// Found by review: a resubmission that changed nothing (a record already held, a delegation already logged) still
// dropped the cached head, so anyone could have the witness sign and log a new head on every request.
test('a resubmission that changes nothing keeps the cached head: no new head is signed or logged', async () => {
  const s = setup()
  await s.submit('root', rootText('a'))
  const logged = (await s.call('POST', '/v1/delegations', { identity: IDENTITY, text: DELEGATION })).body.logged
  const h1 = (await s.call('GET', `/v1/identities/${IDENTITY}/head`)).body.head
  for (let i = 0; i < 5; i++) {
    s.at(BASE + 1 + i)
    assert.equal((await s.submit('root', rootText('a'))).status, 200)
    assert.equal((await s.call('POST', '/v1/delegations', { identity: IDENTITY, text: DELEGATION })).body.logged, logged)
    assert.equal((await s.call('GET', `/v1/identities/${IDENTITY}/head`)).body.head, h1)
  }
  assert.deepEqual(s.log.entries(), [logged, h1])
})

test('revocations: admitted through their own endpoint, refusals as 422', async () => {
  const s = setup()
  await s.submit('root', rootText('a'))
  const rev = signed('revocation', { identity: IDENTITY, target: 'd'.repeat(64), at: BASE }, 'a')
  assert.deepEqual((await s.call('POST', '/v1/revocations', { identity: IDENTITY, text: rev })).body, { ok: true, signed: [] })
  const other = signed('revocation', { identity: IDENTITY, target: 'e'.repeat(64), at: BASE }, 'c')
  assert.deepEqual((await s.call('POST', '/v1/revocations', { identity: IDENTITY, text: other })).body, { ok: false, reason: 'signer' })
  assert.deepEqual((await s.call('POST', '/v1/revocations', { identity: IDENTITY, text: other, delegation: 'x' })).body, { ok: false, reason: 'signer' })
  assert.deepEqual((await s.call('GET', `/v1/identities/${IDENTITY}/records`)).body.revocations, [rev])
})

test("concurrent submissions for one identity are serialised: neither is lost", async () => {
  const s = setup()
  await s.submit('root', rootText('a'))
  const [a, b] = await Promise.all([s.submit('membership', signed('membership', M2, 'a')),
    s.submit('freeze', signed('freeze', { identity: IDENTITY, membership: IDENTITY }, 'a'))])
  assert.equal(a.status, 200)
  assert.equal(b.status, 200)
  const held = (await s.call('GET', `/v1/identities/${IDENTITY}/records`)).body
  assert.equal(held.memberships.length, 1)
  assert.equal(held.freezes.length, 1)
})

test('a log that fails: 503, and nothing it did not take is kept', async () => {
  const inner = memoryLog()
  let down = true
  const s = setup({ log: { append: async (t) => { if (down) throw new Error('down'); return inner.append(t) }, entries: inner.entries } })
  await s.submit('root', rootText('a'))
  await s.submit('membership', signed('membership', M2, 'a'))
  await s.submit('root', rootText('b'))
  const r = await s.submit('membership', signed('membership', M2, 'b'))
  assert.deepEqual(r.body, { ok: false, reason: 'log' })
  assert.equal(r.status, 503)
  assert.equal((await s.call('GET', `/v1/identities/${IDENTITY}/records`)).body.memberships.length, 1, 'the signature that led to the anchor is not kept')
  assert.equal((await s.call('GET', `/v1/identities/${IDENTITY}/head`)).status, 503)
  down = false
  // The anchor signed before the failure is appended first, once the log is back: the same text, not a new one.
  assert.deepEqual((await s.submit('membership', signed('membership', M2, 'b'))).body, { ok: true, signed: [] })
  const anchors = (await s.call('GET', `/v1/identities/${IDENTITY}/records`)).body.anchors
  assert.equal(anchors.length, 1)
  assert.deepEqual(inner.entries(), anchors, 'the log took exactly the anchor that is served')
  down = true
  s.at(BASE + WINDOW)
  await assert.rejects(s.svc.tick(), /log unavailable/)
  assert.equal((await s.call('GET', `/v1/identities/${IDENTITY}/records`)).body.settlements.length, 0, 'the settlement is not kept')
  down = false
  assert.deepEqual(await s.svc.tick(), [], 'the settlement signed before is appended from the outbox, not signed anew')
  assert.equal((await s.call('GET', `/v1/identities/${IDENTITY}/records`)).body.settlements.length, 1)
})

// Found by review: a log that took an entry but whose answer was lost led the witness to sign a rival anchor later.
test('a lost log answer never leads to a rival: what was signed is appended again, before anything new', async () => {
  const inner = memoryLog()
  let lose = false
  const s = setup({ log: { append: async (t) => { await inner.append(t); if (lose) { lose = false; throw new Error('answer lost') } }, entries: inner.entries } })
  await s.submit('root', rootText('a'))
  const X = mBody(2, ['a'], IDENTITY)
  const Y = mBody(2, ['a', 'b'], IDENTITY)
  lose = true
  assert.deepEqual((await s.submit('membership', signed('membership', X, 'a'))).body, { ok: false, reason: 'log' })
  assert.equal(inner.entries().length, 1, 'the log has the anchor of X')
  // A rival arrives: X's anchor is appended again first, so X is pending and the rival is refused.
  assert.deepEqual((await s.submit('membership', signed('membership', Y, 'a'))).body, { ok: false, reason: 'prev' })
  const anchored = inner.entries().map((t) => envelope.open(t, 'anchor').body.record)
  assert.deepEqual([...new Set(anchored)], [mId(X)], 'every anchor in the log is X\'s')
  assert.deepEqual((await s.call('GET', `/v1/identities/${IDENTITY}/records`)).body.anchors, [inner.entries()[0]])
})

test('the outbox is appended before a head is served and before a tick advances', async () => {
  const inner = memoryLog()
  let lose = false
  const s = setup({ log: { append: async (t) => { await inner.append(t); if (lose) { lose = false; throw new Error('answer lost') } }, entries: inner.entries } })
  await s.submit('root', rootText('a'))
  lose = true
  await s.submit('membership', signed('membership', mBody(2, ['a'], IDENTITY), 'a'))
  const head = (await s.call('GET', `/v1/identities/${IDENTITY}/head`)).body.head
  assert.deepEqual(Array.from(envelope.open(head, 'head').body.memberships), [IDENTITY, mId(mBody(2, ['a'], IDENTITY))], 'the head is of the logged anchor')
  lose = true
  s.at(BASE + WINDOW)
  await assert.rejects(s.svc.tick(), /log unavailable/)
  const settled = await s.svc.tick()
  assert.deepEqual(settled, [], 'the settlement signed before the failure was appended again, not signed anew')
  assert.equal((await s.call('GET', `/v1/identities/${IDENTITY}/records`)).body.settlements.length, 1)
})

// While an append is in flight the signed records wait in the outbox, beside the holding the log already has. A
// records read is served from that holding: it shows nothing the log has not taken, and does not wait for the log.
test('records read while an append is in flight show only what is logged', async () => {
  const inner = memoryLog()
  let entered
  const blocked = new Promise((resolve) => { entered = resolve })
  let release
  let gate = false
  const s = setup({ log: {
    append: async (t) => {
      if (gate) {
        entered()
        await new Promise((resolve) => { release = resolve })
        gate = false
      }
      return inner.append(t)
    },
    entries: inner.entries,
  } })
  await s.submit('root', rootText('a'))
  const before = (await s.call('GET', `/v1/identities/${IDENTITY}/records`)).body
  const logged = inner.entries().length
  gate = true
  const writing = s.submit('membership', signed('membership', mBody(2, ['a'], IDENTITY), 'a'))
  await blocked
  const during = await s.call('GET', `/v1/identities/${IDENTITY}/records`)
  assert.equal(during.status, 200)
  assert.deepEqual(during.body, before, 'the staged membership and its anchor are not served')
  assert.equal(inner.entries().length, logged, 'and nothing more is logged yet')
  release()
  assert.equal((await writing).status, 200)
  const after = (await s.call('GET', `/v1/identities/${IDENTITY}/records`)).body
  assert.equal(after.memberships.length, before.memberships.length + 1)
  assert.equal(after.anchors.length, 1)
  for (const text of after.anchors) assert.ok(inner.entries().includes(text), 'what is served is logged')
})

test('a store that fails: 503', async () => {
  const s = setup({ holdings: { get: async () => { throw new Error('disk') }, update: async () => { throw new Error('disk') }, identities: async () => [] } })
  assert.deepEqual((await s.submit('root', rootText('a'))).body, { ok: false, reason: 'storage' })
  assert.equal((await s.call('GET', `/v1/identities/${IDENTITY}/records`)).status, 503)
})

test('configuration is checked at construction', () => {
  const ok = { witness: w, holdings: memoryHoldings(), log: memoryLog(), clock: () => BASE, headInterval: 60 }
  for (const bad of [{ witness: undefined }, { holdings: {} }, { holdings: undefined }, { log: {} }, { log: undefined }, { clock: 1 }, { headInterval: -1 }, { headInterval: 1.5 }]) {
    assert.throws(() => witnessService({ ...ok, ...bad }), { name: 'TypeError', message: /^service configuration/ }, JSON.stringify(bad))
  }
  assert.doesNotThrow(() => witnessService({ ...ok, headInterval: 0 }))
})

test('delegations: logged through their own endpoint, the logged record appended once; refusals as 422', async () => {
  const s = setup()
  await s.submit('root', rootText('a'))
  const r = await s.call('POST', '/v1/delegations', { identity: IDENTITY, text: DELEGATION })
  assert.equal(r.status, 200)
  assert.deepEqual(Object.keys(r.body), ['ok', 'signed', 'logged'])
  assert.deepEqual(r.body.signed, [r.body.logged])
  assert.deepEqual({ ...bodyOf(r.body.logged, 'logged') }, { at: BASE, delegation: del.id, identity: IDENTITY })
  assert.deepEqual(s.log.entries(), [r.body.logged])
  // Again: the same record, nothing new appended.
  s.at(BASE + 5)
  assert.deepEqual((await s.call('POST', '/v1/delegations', { identity: IDENTITY, text: DELEGATION })).body, { ok: true, signed: [], logged: r.body.logged })
  assert.equal(s.log.entries().length, 1)
  // Revoked: never logged again; refusals are 422 with the witness's reason.
  const other = await s.call('POST', '/v1/delegations', { identity: IDENTITY, text: 'x' })
  assert.deepEqual({ status: other.status, body: other.body }, { status: 422, body: { ok: false, reason: 'envelope-encoding' } })
  const unknown = await s.call('POST', '/v1/delegations', { identity: 'f'.repeat(64), text: DELEGATION })
  assert.deepEqual(unknown.body, { ok: false, reason: 'identity' })
  assert.deepEqual((await s.call('GET', '/v1/delegations')).status, 405)
})

// Found by review: the in-memory holdings kept a queue for every identity ever named, each holding its last answer.
test('memory holdings: an identity\'s queue is dropped once its last update is done, in order, failures included', async () => {
  const h = memoryHoldings()
  const order = []
  let release
  const gate = new Promise((resolve) => { release = resolve })
  const first = h.update('i', async () => { await gate; order.push(1); return { entry: 'one', value: 1 } })
  const second = h.update('i', async (e) => { order.push(e); throw new Error('x') })
  const third = h.update('i', async (e) => { order.push(e); return { value: 3 } })
  for (let i = 0; i < 100; i++) await h.update('u' + i, async () => ({ value: 0 }))
  await new Promise((resolve) => setImmediate(resolve))
  assert.equal(h.inFlight(), 1, 'the hundred done are dropped; one identity still waits')
  release()
  assert.equal(await first, 1)
  await assert.rejects(second)
  assert.equal(await third, 3)
  assert.deepEqual(order, [1, 'one', 'one'])
  await new Promise((resolve) => setImmediate(resolve))
  assert.equal(h.inFlight(), 0)
  assert.equal(await h.get('i'), 'one')
  // A queue's cleanup never drops a later update's place: one queued after it still waits for the one before.
  const seen = []
  let open
  const held = new Promise((resolve) => { open = resolve })
  const quick = h.update('j', async () => ({ value: 'first' }))
  const slow = h.update('j', async () => { await held; seen.push('slow'); return { value: 0 } }) // queued behind it
  await quick
  await new Promise((resolve) => setImmediate(resolve)) // the first update's cleanup has run, with slow queued
  const after = h.update('j', async () => { seen.push('after'); return { value: 0 } })
  open()
  await Promise.all([slow, after])
  assert.deepEqual(seen, ['slow', 'after'])
})

// R11 through the service: a party's signature comes with its root record, a cancel is a submitted record, and what
// the witness says of a recovery is logged and served with the rest.
test('a recovery through the service: the notice is logged and served and is in the head; a cancel ends it', async () => {
  const s = setup({ headInterval: 0 })
  const D = { parties: [commitmentOf('g')], threshold: 1, window: 259_200 }
  const m2 = { identity: IDENTITY, prev: IDENTITY, epoch: 2, roots: [rootId('a')], recovery: D }
  await s.submit('root', rootText('a'))
  await s.submit('membership', signed('membership', m2, 'a'))
  s.at(BASE + WINDOW)
  await s.svc.tick()
  const R = { identity: IDENTITY, prev: mId(m2), epoch: 3, roots: [rootId('n')] }
  const party = partySigned('membership', R, 'g')
  assert.deepEqual((await s.submit('membership', party)).body, { ok: false, reason: 'root-missing' })
  assert.equal((await s.call('POST', '/v1/records', { identity: IDENTITY, type: 'membership', text: party, root: 7 })).status, 400)
  assert.deepEqual((await s.call('POST', '/v1/records', { identity: IDENTITY, type: 'membership', text: party, root: rootText('h') })).body, { ok: false, reason: 'root-record' })
  assert.equal((await s.call('POST', '/v1/records', { identity: IDENTITY, type: 'membership', text: party, root: rootText('g') })).status, 200)
  await s.submit('root', rootText('n'))
  const asked = await s.submit('membership', signed('membership', R, 'n'))
  assert.equal(asked.body.signed.length, 1)
  assert.deepEqual({ ...bodyOf(asked.body.signed[0], 'notice') }, { at: BASE + WINDOW, identity: IDENTITY, record: mId(R) })
  assert.ok(s.log.entries().includes(asked.body.signed[0]))
  const held = (await s.call('GET', `/v1/identities/${IDENTITY}/records`)).body
  assert.deepEqual([held.notices, held.cancelled, held.matured], [asked.body.signed, [], []])
  const head = (await s.call('GET', `/v1/identities/${IDENTITY}/head`)).body.head
  assert.deepEqual({ ...bodyOf(head, 'head').recovering }, { at: BASE + WINDOW, record: mId(R) })
  s.at(BASE + WINDOW + 50)
  const cancelled = await s.submit('cancel', signed('cancel', { identity: IDENTITY, record: mId(R) }, 'a'))
  assert.equal(cancelled.status, 200)
  assert.deepEqual({ ...bodyOf(cancelled.body.signed[0], 'cancelled') }, { at: BASE + WINDOW + 50, identity: IDENTITY, record: mId(R) })
  assert.deepEqual((await s.call('GET', `/v1/identities/${IDENTITY}/records`)).body.cancelled, cancelled.body.signed)
  assert.equal('recovering' in bodyOf((await s.call('GET', `/v1/identities/${IDENTITY}/head`)).body.head, 'head'), false)
  assert.deepEqual((await s.submit('cancel', signed('cancel', { identity: IDENTITY, record: mId(R) }, 'a'))).body, { ok: true, signed: [] }, 'the same cancel again: held, nothing signed')
})
