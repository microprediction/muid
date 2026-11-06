// History: an identity's bundles verified under its own pinned services and log; refusals by index and reason.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { envelope } from '../impl.mjs'
import { history } from './impl.mjs'
import { CONFIG } from './fake-log.mjs'
import { setup, worker, IDENTITY, NOW, FORECASTS, SERVICES } from './fixtures.mjs'

async function bundles () {
  const s = setup()
  const w1 = worker(10)
  await s.post(w1.records({ question: 'q', forecast: 1 }))
  await s.post(worker(30).records({ question: 'q', forecast: 2 }))
  return { list: (await s.get(`/contributions?identity=${IDENTITY}`)).body, w1 }
}

test('each bundle that verifies is accepted, with when it existed by; long after its delegation expired', async () => {
  const { list, w1 } = await bundles()
  const h = history({ services: SERVICES, log: CONFIG, skew: 60 })
  const r = h.verify(IDENTITY, list, NOW + 10 * 365 * 86_400)
  assert.deepEqual(r.refused, [])
  assert.equal(r.accepted.length, 2)
  assert.deepEqual(r.accepted[0], { service: FORECASTS, identity: IDENTITY, delegation: w1.id, claim: envelope.open(list[0].claim, 'claim').id, at: NOW, existedBy: NOW })
})

test('refusals: unpinned service, another identity, a broken bundle, a claim that is not the receipt\'s', async () => {
  const { list } = await bundles()
  const h = history({ services: SERVICES, log: CONFIG, skew: 60 })
  assert.deepEqual(history({ services: [], log: CONFIG, skew: 60 }).verify(IDENTITY, list, NOW).refused, [{ index: 0, reason: 'service' }, { index: 1, reason: 'service' }])
  assert.deepEqual(h.verify('f'.repeat(64), list, NOW).refused, [{ index: 0, reason: 'identity' }, { index: 1, reason: 'identity' }])
  const broken = [{ ...list[0], proof: 'x' }, { ...list[0], proof: ['zz'] }, { ...list[0], proof: ['abc'] }, { ...list[0], proof: [1] }, null,
    { ...list[1], proof: [] }, { ...list[0], claim: list[1].claim }, { ...list[1], proof: ['ab'.repeat(32)] }, { ...list[1], proof: [''] }, { ...list[1], proof: [['ab'.repeat(32)]] }]
  assert.deepEqual(h.verify(IDENTITY, broken, NOW), { accepted: [], refused: [
    { index: 0, reason: 'bundle' }, { index: 1, reason: 'bundle' }, { index: 2, reason: 'bundle' }, { index: 3, reason: 'bundle' }, { index: 4, reason: 'bundle' },
    { index: 5, reason: 'inclusion' }, { index: 6, reason: 'claim' }, { index: 7, reason: 'inclusion' }, { index: 8, reason: 'inclusion' }, { index: 9, reason: 'bundle' }] })
  // Found by review: an answer that is not a list is refused as a whole, never thrown or iterated as a length.
  for (const bad of [null, undefined, 'x', { length: 1e9 }, { 0: list[0], length: 1 }]) {
    assert.deepEqual(h.verify(IDENTITY, bad, NOW), { accepted: [], refused: [{ index: null, reason: 'bundles' }] }, JSON.stringify(bad))
  }
  // A contribution the service has not yet published (its receipt alone, pending) has nothing to verify yet.
  assert.deepEqual(h.verify(IDENTITY, [{ receipt: list[0].receipt, claim: list[0].claim, pending: true }], NOW).refused, [{ index: 0, reason: 'pending' }])
  // Mixed: what verifies is kept, in order.
  const mixed = h.verify(IDENTITY, [list[1], { ...list[0], proof: 'x' }, list[0]], NOW)
  assert.deepEqual(mixed.accepted.map((a) => a.claim), [list[1], list[0]].map((b) => envelope.open(b.claim, 'claim').id))
  assert.deepEqual(mixed.refused, [{ index: 1, reason: 'bundle' }])
})
