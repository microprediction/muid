// Forecasts against an in-memory log: a contribution is accepted once, its receipt logged and bundled with a
// cosigned checkpoint that holds it; every other request is refused with its reason; a failing log is 503.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { envelope, receipt as receiptModule } from '../impl.mjs'
import { fakeLog, CONFIG } from './fake-log.mjs'
import { setup, worker, IDENTITY, NOW, FORECASTS, SERVICES } from './fixtures.mjs'

const bytes = (h) => Uint8Array.from(Buffer.from(h, 'hex'))

test('a contribution: accepted once, its receipt logged and bundled with a checkpoint that holds it', async () => {
  const s = setup()
  const w1 = worker(10)
  const records = w1.records({ question: 'q', forecast: 7000 })
  const r = await s.post(records)
  assert.equal(r.status, 200, JSON.stringify(r.body))
  assert.equal(r.body.ok, true)
  assert.equal(r.type, 'application/json')
  const { bundle } = r.body
  assert.deepEqual(Object.keys(bundle), ['receipt', 'checkpoint', 'proof', 'index'])
  assert.deepEqual(s.log.entries(), [bundle.receipt])
  const body = envelope.open(bundle.receipt, 'receipt').body
  assert.deepEqual({ ...body }, { at: NOW, claim: envelope.open(records.claim, 'claim').id, delegation: w1.id, identity: IDENTITY, service: FORECASTS })
  const v = receiptModule.verifyReceipt({ ...bundle, proof: bundle.proof.map(bytes), claim: records.claim }, { services: SERVICES, log: CONFIG, now: NOW, skew: 60 })
  assert.equal(v.ok, true, JSON.stringify(v))
  assert.deepEqual((await s.post(records)).body, { ok: false, reason: 'replay' })
  // A second contribution: the bundle's proof is against a tree of two.
  const r2 = await s.post(worker(20).records({ question: 'q', forecast: 1 }))
  assert.equal(r2.body.bundle.index, 1)
  assert.equal(r2.body.bundle.proof.length, 1)
  assert.match(r2.body.bundle.proof[0], /^[0-9a-f]{64}$/)
})

test("an identity's contributions, each with its bundle and claim; none for another identity", async () => {
  const s = setup()
  const a = worker(10).records({ question: 'q', forecast: 1 })
  const b = worker(30).records({ question: 'q', forecast: 2 })
  const ra = (await s.post(a)).body.bundle
  const rb = (await s.post(b)).body.bundle
  assert.deepEqual((await s.get(`/contributions?identity=${IDENTITY}`)).body, [{ ...ra, claim: a.claim }, { ...rb, claim: b.claim }])
  assert.deepEqual((await s.get(`/contributions?identity=${'f'.repeat(64)}`)).body, [])
})

test('refusals: the adapter\'s reasons as 403, malformed requests, other paths and methods', async () => {
  const s = setup()
  const w1 = worker(10)
  const is = async (p, status, reason) => { const r = await p; assert.deepEqual({ status: r.status, body: r.body }, { status, body: { ok: false, reason } }) }
  await is(s.post({ ...w1.records({ question: 'q', forecast: 1 }), head: 'x' }), 403, 'head')
  await is(s.post(worker(40, { scopes: ['read'] }).records({ question: 'q', forecast: 1 })), 403, 'scope')
  await is(s.post(worker(50, { aud: 'https://other.example' }).records({ question: 'q', forecast: 1 })), 403, 'claim-url')
  await is(s.post('{'), 400, 'json')
  await is(s.get('/forecasts', { method: 'POST' }), 400, 'json') // no body at all
  for (const b of ['null', '1', '[]', '{}']) assert.equal((await s.post(b)).status, 403, b)
  const max = 262_144
  const sized = (n) => JSON.stringify({ claim: 'x'.repeat(n - 12) })
  assert.equal(sized(max).length, max)
  await is(s.post(sized(max)), 403, 'envelope-encoding')
  await is(s.post(sized(max + 1)), 413, 'too-large')
  await is(s.get('/forecasts'), 405, 'method')
  await is(s.get('/contributions', { method: 'POST', body: '' }), 405, 'method')
  await is(s.get('/other'), 404, 'not-found')
  assert.deepEqual(s.log.entries(), [], 'nothing refused is logged')
})

// Found by review: the body was buffered in full before its size was checked.
test('a body past the limit is refused without being read in full', async () => {
  let pulled = 0
  const chunk = new Uint8Array(16_384).fill(0x78)
  // 1 MiB, far past the limit: a reader that reads it all is caught by how much it pulled.
  const body = new ReadableStream({ pull (c) { if (pulled >= 1_048_576) { c.close(); return } pulled += chunk.length; c.enqueue(chunk) } })
  const res = await setup().f.handle(new Request('https://forecasts.example/forecasts', { method: 'POST', body, duplex: 'half' }))
  assert.equal(res.status, 413)
  assert.ok(pulled < 262_144 + 4 * chunk.length, `read ${pulled} bytes`)
  // Several chunks below the limit are joined in order.
  const parts = ['{"cla', 'im":"x","dele', 'gation":"x"}']
  const small = new ReadableStream({ start (c) { for (const p of parts) c.enqueue(new TextEncoder().encode(p)); c.close() } })
  assert.equal((await setup().f.handle(new Request('https://forecasts.example/forecasts', { method: 'POST', body: small, duplex: 'half' }))).status, 403)
})

// Issue #33: the claim is consumed before the action runs, so an accepted contribution is kept before its receipt
// is published, and publication is retried from that record (an outbox), never lost with the response.
test('a failing log: the contribution is kept, pending (202); publish appends its receipt once and bundles it', async () => {
  const log = fakeLog({ cosignTime: () => NOW, failAppend: true })
  const s = setup({ log })
  const records = worker(10).records({ question: 'q', forecast: 1 })
  const down = await s.post(records)
  assert.equal(down.status, 202)
  assert.deepEqual(Object.keys(down.body), ['ok', 'pending', 'receipt'])
  assert.deepEqual([down.body.ok, down.body.pending], [true, true])
  assert.deepEqual((await s.get(`/contributions?identity=${IDENTITY}`)).body, [{ receipt: down.body.receipt, claim: records.claim, pending: true }])
  assert.deepEqual((await s.post(records)).body, { ok: false, reason: 'replay' }, 'the claim is spent; the contribution is not lost')
  assert.equal(await s.f.publish(), 0, 'the log still down')
  log.state.failAppend = false
  assert.equal(await s.f.publish(), 1)
  assert.deepEqual(s.log.entries(), [down.body.receipt], 'the receipt signed at acceptance, appended once')
  const [c] = (await s.get(`/contributions?identity=${IDENTITY}`)).body
  assert.deepEqual([c.receipt, c.index, c.claim, c.pending], [down.body.receipt, 0, records.claim, undefined])
  const v = receiptModule.verifyReceipt({ ...c, proof: c.proof.map(bytes) }, { services: SERVICES, log: CONFIG, now: NOW, skew: 60 })
  assert.equal(v.ok, true, JSON.stringify(v))
  assert.equal(await s.f.publish(), 0, 'nothing left to publish')
})

test('the log took the receipt but its proof failed: publish fetches the proof without appending again', async () => {
  const log = fakeLog({ cosignTime: () => NOW })
  log.state.failProof = true
  const s = setup({ log })
  const r = await s.post(worker(10).records({ question: 'q', forecast: 1 }))
  assert.equal(r.status, 202)
  assert.equal(s.log.entries().length, 1)
  log.state.failProof = false
  assert.equal(await s.f.publish(), 1)
  assert.equal(s.log.entries().length, 1, 'not appended twice')
  assert.equal((await s.get(`/contributions?identity=${IDENTITY}`)).body[0].index, 0)
})

test('the log took the receipt but its answer was lost: publish appends again, and the bundle is for the entry it gets', async () => {
  const log = fakeLog({ cosignTime: () => NOW, failAppend: true })
  log.state.lostAnswer = true
  const s = setup({ log })
  assert.equal((await s.post(worker(10).records({ question: 'q', forecast: 1 }))).status, 202)
  log.state.failAppend = false
  assert.equal(await s.f.publish(), 1)
  const [c] = (await s.get(`/contributions?identity=${IDENTITY}`)).body
  assert.equal(c.index, 1, 'the second entry: a lost answer cannot be told from a failed append')
  const v = receiptModule.verifyReceipt({ ...c, proof: c.proof.map(bytes) }, { services: SERVICES, log: CONFIG, now: NOW, skew: 60 })
  assert.equal(v.ok, true, JSON.stringify(v))
})

test('a question resolving while a receipt is pending scores the contribution: acceptance, not publication, counts', async () => {
  const log = fakeLog({ cosignTime: () => NOW, failAppend: true })
  const s = setup({ log })
  assert.equal((await s.post(worker(10).records({ question: 'q', forecast: 10_000 }))).status, 202)
  assert.equal(s.f.resolve('q', 1), 1)
  assert.equal((await s.get(`/earnings?identity=${IDENTITY}`)).body.earned, 10_000)
})

test('the receipt waits for a checkpoint that holds it and verifies; none in time is 503', async () => {
  // Checkpoints held back: the log has the entry, but publishes it only after a few polls.
  let polls = 0
  const log = fakeLog({ cosignTime: () => NOW })
  log.state.publish = false
  const s = setup({ log, wait: async () => { polls++; if (polls === 3) { log.state.publish = true; await log.append('another') } } })
  const r = await s.post(worker(10).records({ question: 'q', forecast: 1 }))
  assert.equal(r.status, 200, JSON.stringify(r.body))
  assert.equal(polls, 3)
  assert.equal(r.body.bundle.index, 0)
  // A checkpoint whose cosignature is from the future does not count toward the quorum; nor, then, does it hold. The
  // contribution stays pending.
  let waits = 0
  const late = setup({ log: fakeLog({ cosignTime: () => NOW + 1000 }), wait: async () => { waits++ } })
  const p = await late.post(worker(20).records({ question: 'q', forecast: 1 }))
  assert.deepEqual([p.status, p.body.pending], [202, true])
  assert.equal(waits, 300)
})

test('the default wait is a real pause of 100 ms', async () => {
  const log = fakeLog({ cosignTime: () => NOW })
  log.state.publish = false
  const s = setup({ log, realWait: true })
  setTimeout(() => { log.state.publish = true; log.append('another') }, 250)
  const started = Date.now()
  assert.equal((await s.post(worker(10).records({ question: 'q', forecast: 1 }))).status, 200)
  assert.ok(Date.now() - started >= 200)
})

test("a failing store is the adapter's refusal; the service unable to sign its receipt is 503, and nothing is kept", async () => {
  const failing = { lastHead: async () => { throw new Error('store down') }, transaction: async () => { throw new Error('store down') } }
  const r = await setup({ store: failing }).post(worker(10).records({ question: 'q', forecast: 1 }))
  assert.deepEqual({ status: r.status, body: r.body }, { status: 403, body: { ok: false, reason: 'storage' } })
  const s = setup({ sign: () => { throw new Error('key unavailable') } })
  const down = await s.post(worker(10).records({ question: 'q', forecast: 1 }))
  assert.deepEqual({ status: down.status, body: down.body }, { status: 503, body: { ok: false, reason: 'unavailable' } })
  assert.deepEqual((await s.get(`/contributions?identity=${IDENTITY}`)).body, [])
})
