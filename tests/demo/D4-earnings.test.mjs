// The organizing example: log in, authorise a temporary agent, let it contribute, retire it, and collect its later
// earnings under the continuing identity. The beneficiary is bound when Forecasts accepts a contribution (the
// delegation's identity), never decided later from whoever holds the agent's key; earnings are credited to the
// identity, with each agent's share shown, and collected only by a live delegation of that identity.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { setup, worker, IDENTITY, NOW } from './fixtures.mjs'

const q = (question, forecast) => ({ question, forecast })

test('an agent contributes, retires, and its earnings arrive later under the identity', async () => {
  let now = NOW
  const s = setup({ clock: () => now })
  const agent = worker(10) // a short-lived agent
  assert.equal((await s.post(agent.records(q('rain-tomorrow', 7000)))).status, 200)
  assert.equal((await s.post(agent.records(q('snow-tomorrow', 2000), NOW - 4))).status, 200)
  // Nothing is earned before the questions resolve.
  assert.deepEqual((await s.get(`/earnings?identity=${IDENTITY}`)).body, { identity: IDENTITY, earned: 0, collected: 0, balance: 0,
    agents: [{ agent: agent.subject, delegation: agent.id, contributions: 2, earned: 0 }] })
  // The agent's delegation lapses (it is gone); the questions resolve afterwards.
  now = NOW + 7200
  assert.deepEqual(s.f.resolve('rain-tomorrow', 1), 1)
  assert.deepEqual(s.f.resolve('snow-tomorrow', 0), 1)
  // Brier, in basis points: 10000 - (f - 10000 o)^2 / 10000.
  const rain = 10000 - (7000 - 10000) ** 2 / 10000
  const snow = 10000 - (2000 - 0) ** 2 / 10000
  assert.deepEqual((await s.get(`/earnings?identity=${IDENTITY}`)).body, { identity: IDENTITY, earned: rain + snow, collected: 0, balance: rain + snow,
    agents: [{ agent: agent.subject, delegation: agent.id, contributions: 2, earned: rain + snow }] })
  // A question resolves once; resolving again credits nothing more.
  assert.equal(s.f.resolve('rain-tomorrow', 0), 0)
})

test('earnings are collected by a live delegation of the identity, with the collect scope; not by the agent', async () => {
  const s = setup()
  const agent = worker(10)
  await s.post(agent.records(q('rain', 10000)))
  s.f.resolve('rain', 1)
  const owner = worker(30, { scopes: ['collect'] }) // the owner's own device
  // The agent cannot collect: its delegation does not hold the scope.
  assert.deepEqual((await s.collect(agent)).body, { ok: false, reason: 'scope' })
  const r = await s.collect(owner)
  assert.deepEqual(r.body, { ok: true, collected: 10000 })
  assert.deepEqual((await s.get(`/earnings?identity=${IDENTITY}`)).body.balance, 0)
  assert.deepEqual((await s.collect(owner, NOW - 3)).body, { ok: true, collected: 0 }, 'nothing left')
})

test("several agents' earnings add up under the one identity, each shown; another identity's are its own", async () => {
  const s = setup()
  const a1 = worker(10)
  const a2 = worker(50)
  await s.post(a1.records(q('x', 10000)))
  await s.post(a2.records(q('x', 5000)))
  s.f.resolve('x', 1)
  const e = (await s.get(`/earnings?identity=${IDENTITY}`)).body
  assert.equal(e.earned, 10000 + 7500)
  assert.deepEqual(e.agents.map((a) => [a.agent, a.earned]), [[a1.subject, 10000], [a2.subject, 7500]])
  assert.deepEqual((await s.get(`/earnings?identity=${'f'.repeat(64)}`)).body, { identity: 'f'.repeat(64), earned: 0, collected: 0, balance: 0, agents: [] })
})

test('a contribution that is not a forecast is refused, and its claim is spent; resolutions are checked', async () => {
  const s = setup()
  const a = worker(10)
  const bad = [{ forecast: 1 }, q('', 1), q('x'.repeat(65), 1), q('x', -1), q('x', 10001), q(1, 1), q('x', '1'), { ...q('x', 1), extra: 1 }, { ...q('x', 1), zzz: 1 }, { forecast: 1, zzz: 'x' }]
  for (let i = 0; i < bad.length; i++) {
    const data = bad[i]
    const r = await s.post(a.records(data, NOW - 5 - i))
    assert.deepEqual({ status: r.status, body: r.body }, { status: 422, body: { ok: false, reason: 'forecast' } }, JSON.stringify(data))
  }
  assert.deepEqual((await s.get(`/earnings?identity=${IDENTITY}`)).body.agents, [])
  assert.throws(() => s.f.resolve('x', 2), { name: 'TypeError', message: 'a question and an outcome of 0 or 1' })
  assert.throws(() => s.f.resolve(1, 1), { name: 'TypeError', message: 'a question and an outcome of 0 or 1' })
  assert.equal(s.f.resolve('nothing', 1), 0)
  assert.deepEqual((await s.get('/earnings')).body, { ok: false, reason: 'identity' })
  for (const id of ['x' + IDENTITY, IDENTITY + 'x']) assert.deepEqual((await s.get(`/earnings?identity=${id}`)).body, { ok: false, reason: 'identity' })
  // The bounds are inclusive: 0 and 10,000 are forecasts.
  assert.equal((await s.post(a.records(q('edge', 0), NOW - 30))).status, 200)
  assert.equal((await s.post(a.records(q('edge2', 10_000), NOW - 31))).status, 200)
  assert.deepEqual((await s.get(`/earnings?identity=${IDENTITY}`, { method: 'POST', body: '' })).body, { ok: false, reason: 'method' })
  assert.deepEqual((await s.get('/collect')).body, { ok: false, reason: 'method' })
})
