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
  const records = w1.records({ forecast: 7000 })
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
  const r2 = await s.post(worker(20).records({ forecast: 1 }))
  assert.equal(r2.body.bundle.index, 1)
  assert.equal(r2.body.bundle.proof.length, 1)
  assert.match(r2.body.bundle.proof[0], /^[0-9a-f]{64}$/)
})

test("an identity's contributions, each with its bundle and claim; none for another identity", async () => {
  const s = setup()
  const a = worker(10).records({ forecast: 1 })
  const b = worker(30).records({ forecast: 2 })
  const ra = (await s.post(a)).body.bundle
  const rb = (await s.post(b)).body.bundle
  assert.deepEqual((await s.get(`/contributions?identity=${IDENTITY}`)).body, [{ ...ra, claim: a.claim }, { ...rb, claim: b.claim }])
  assert.deepEqual((await s.get(`/contributions?identity=${'f'.repeat(64)}`)).body, [])
})

test('refusals: the adapter\'s reasons as 403, malformed requests, other paths and methods', async () => {
  const s = setup()
  const w1 = worker(10)
  const is = async (p, status, reason) => { const r = await p; assert.deepEqual({ status: r.status, body: r.body }, { status, body: { ok: false, reason } }) }
  await is(s.post({ ...w1.records({ forecast: 1 }), head: 'x' }), 403, 'head')
  await is(s.post(worker(40, { scopes: ['read'] }).records({ forecast: 1 })), 403, 'scope')
  await is(s.post(worker(50, { aud: 'https://other.example' }).records({ forecast: 1 })), 403, 'claim-url')
  await is(s.post('{'), 400, 'json')
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

test('a failing log is 503, and nothing is kept; the claim stays consumed', async () => {
  const s = setup({ log: fakeLog({ cosignTime: () => NOW, failAppend: true }) })
  const records = worker(10).records({ forecast: 1 })
  const down = await s.post(records)
  assert.deepEqual({ status: down.status, body: down.body }, { status: 503, body: { ok: false, reason: 'unavailable' } })
  assert.deepEqual((await s.get(`/contributions?identity=${IDENTITY}`)).body, [])
  assert.deepEqual((await s.post(records)).body, { ok: false, reason: 'replay' })
})

test('the receipt waits for a checkpoint that holds it and verifies; none in time is 503', async () => {
  // Checkpoints held back: the log has the entry, but publishes it only after a few polls.
  let polls = 0
  const log = fakeLog({ cosignTime: () => NOW })
  log.state.publish = false
  const s = setup({ log, wait: async () => { polls++; if (polls === 3) { log.state.publish = true; await log.append('another') } } })
  const r = await s.post(worker(10).records({ forecast: 1 }))
  assert.equal(r.status, 200, JSON.stringify(r.body))
  assert.equal(polls, 3)
  assert.equal(r.body.bundle.index, 0)
  // A checkpoint whose cosignature is from the future does not count toward the quorum; nor, then, does it hold.
  let waits = 0
  const late = setup({ log: fakeLog({ cosignTime: () => NOW + 1000 }), wait: async () => { waits++ } })
  assert.deepEqual((await late.post(worker(20).records({ forecast: 1 }))).body, { ok: false, reason: 'unavailable' })
  assert.equal(waits, 300)
})

test('the default wait is a real pause of 100 ms', async () => {
  const log = fakeLog({ cosignTime: () => NOW })
  log.state.publish = false
  const s = setup({ log, realWait: true })
  setTimeout(() => { log.state.publish = true; log.append('another') }, 250)
  const started = Date.now()
  assert.equal((await s.post(worker(10).records({ forecast: 1 }))).status, 200)
  assert.ok(Date.now() - started >= 200)
})
