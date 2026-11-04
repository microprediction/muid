// The witness service: the witness's decisions behind a small HTTP API (fetch-style Request and Response), with a
// store that serialises each identity's changes and a log every signed record is appended to before it is kept.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { envelope } from '../impl.mjs'
import { witnessService, memoryHoldings, memoryLog } from './impl.mjs'
import { w, IDENTITY, BASE, WINDOW, M2, mId, signed, rootText } from './fixtures.mjs'

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
  assert.deepEqual(Object.keys(held).sort(), ['anchors', 'contests', 'freezes', 'memberships', 'revocations', 'roots', 'settlements'])
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
  for (const type of ['root', 'membership', 'contest', 'freeze']) assert.equal((await s.submit(type, 'x')).body.reason, 'envelope-encoding', type)
})

test('malformed requests: 400, 404, 405 and 413, each with its reason', async () => {
  const s = setup()
  const is = async (p, status, reason, label) => assert.deepEqual(await p, { status, body: { ok: false, reason }, type: 'application/json' }, label)
  await is(s.call('POST', '/v1/records', '{'), 400, 'json')
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
  // A change makes the next head fresh, even inside the interval.
  await s.call('POST', '/v1/revocations', { identity: IDENTITY, text: signed('revocation', { identity: IDENTITY, target: 'd'.repeat(64), at: BASE }, 'a') })
  const h3 = (await s.call('GET', `/v1/identities/${IDENTITY}/head`)).body.head
  assert.deepEqual(Array.from(bodyOf(h3, 'head').revoked), ['d'.repeat(64)])
  assert.deepEqual(s.log.entries(), [h1, h2, h3])
  // Frozen: no head can be signed.
  await s.submit('freeze', signed('freeze', { identity: IDENTITY, membership: IDENTITY }, 'a'))
  assert.deepEqual((await s.call('GET', `/v1/identities/${IDENTITY}/head`)), { status: 409, body: { ok: false, reason: 'no-head' }, type: 'application/json' })
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
  assert.equal((await s.submit('membership', signed('membership', M2, 'b'))).body.signed.length, 1, 'anchored once the log is back')
  down = true
  s.at(BASE + WINDOW)
  await assert.rejects(s.svc.tick(), /log unavailable/)
  assert.equal((await s.call('GET', `/v1/identities/${IDENTITY}/records`)).body.settlements.length, 0, 'the settlement is not kept')
  down = false
  assert.equal((await s.svc.tick()).length, 1)
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
