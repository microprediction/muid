// The organizing example: log in, authorise a temporary agent, let it contribute, retire it, and collect its later
// earnings under the continuing identity. The beneficiary is bound when Forecasts accepts a contribution (the
// delegation's identity), never decided later from whoever holds the agent's key; earnings are credited to the
// identity, with each agent's share shown, and collected only by a live delegation of that identity.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { setup, worker, IDENTITY, NOW, CLOSES } from './fixtures.mjs'
import { score } from './impl.mjs'

const q = (question, forecast) => ({ question, forecast })

test('an agent contributes, retires, and its earnings arrive later under the identity', async () => {
  let now = NOW
  const s = setup({ clock: () => now, questions: ['rain-tomorrow', 'snow-tomorrow'] })
  const agent = worker(10) // a short-lived agent
  assert.equal((await s.post(agent.records(q('rain-tomorrow', 7000)))).status, 200)
  assert.equal((await s.post(agent.records(q('snow-tomorrow', 2000), NOW - 4))).status, 200)
  // Nothing is earned before the questions resolve.
  assert.deepEqual((await s.get(`/earnings?identity=${IDENTITY}`)).body, { identity: IDENTITY, earned: 0, collected: 0, balance: 0,
    agents: [{ agent: agent.agent, name: 'worker', contributions: 2, earned: 0 }] })
  // The agent's delegation lapses (it is gone); the questions resolve afterwards.
  now = NOW + 7200
  assert.deepEqual(s.f.resolve('rain-tomorrow', 1), 1)
  assert.deepEqual(s.f.resolve('snow-tomorrow', 0), 1)
  // The Brier score's exact numerator, in units of which a perfect forecast earns 100,000,000: 10^8 - (f - 10000 o)^2.
  const rain = 91_000_000
  const snow = 96_000_000
  assert.deepEqual((await s.get(`/earnings?identity=${IDENTITY}`)).body, { identity: IDENTITY, earned: rain + snow, collected: 0, balance: rain + snow,
    agents: [{ agent: agent.agent, name: 'worker', contributions: 2, earned: rain + snow }] })
  // A question resolves once: again with its outcome credits nothing more; with the other, it is an error.
  assert.equal(s.f.resolve('rain-tomorrow', 1), 0)
  assert.throws(() => s.f.resolve('rain-tomorrow', 0), { message: 'already resolved with the other outcome' })
})

// Decision 13: an agent's share follows its name, not its key. A replaced key under the same name continues the same
// light identity's share; another name is another agent.
test('an agent\'s share survives its key being replaced; another name is another share', async () => {
  const s = setup({ questions: ['rain', 'snow', 'hail'] })
  const first = worker(10)
  const replaced = worker(50) // the same agent on a new server: a new key, the same name
  const other = worker(70, { agent: 'scorer' })
  assert.notEqual(first.subject, replaced.subject)
  assert.equal(first.agent, replaced.agent)
  for (const [w, question] of [[first, 'rain'], [replaced, 'snow'], [other, 'hail']]) {
    assert.equal((await s.post(w.records(q(question, 5000)))).status, 200, question)
  }
  for (const question of ['rain', 'snow', 'hail']) s.f.resolve(question, 1)
  const each = 75_000_000
  assert.deepEqual((await s.get(`/earnings?identity=${IDENTITY}`)).body.agents, [
    { agent: first.agent, name: 'worker', contributions: 2, earned: 2 * each },
    { agent: other.agent, name: 'scorer', contributions: 1, earned: each },
  ])
})

test('earnings are collected by a live delegation of the identity, with the collect scope; not by the agent', async () => {
  const s = setup({ questions: ['rain'] })
  const agent = worker(10)
  await s.post(agent.records(q('rain', 10000)))
  s.f.resolve('rain', 1)
  const owner = worker(30, { scopes: ['collect'] }) // the owner's own device
  // The agent cannot collect: its delegation does not hold the scope.
  assert.deepEqual((await s.collect(agent)).body, { ok: false, reason: 'scope' })
  const r = await s.collect(owner)
  assert.deepEqual(r.body, { ok: true, collected: 100_000_000 })
  assert.deepEqual((await s.get(`/earnings?identity=${IDENTITY}`)).body.balance, 0)
  assert.deepEqual((await s.collect(owner, NOW - 3)).body, { ok: true, collected: 0 }, 'nothing left')
})

// Issue #32: a claim is not a reward. Each identity holds one standing forecast per question, its latest, whichever
// agent made it; more agents or more claims earn nothing more. Distinct questions are distinct work.
test("one standing forecast per identity and question, its latest, whichever agent made it; each agent's share shown", async () => {
  const s = setup({ questions: ['x', 'y'] })
  const a1 = worker(10, { agent: 'alpha' })
  const a2 = worker(50, { agent: 'beta' })
  await s.post(a1.records(q('x', 10000)))
  await s.post(a2.records(q('x', 5000))) // the identity's later forecast of x stands
  await s.post(a1.records(q('y', 10000), NOW - 6))
  assert.equal(s.f.resolve('x', 1), 1, 'one identity, one score')
  assert.equal(s.f.resolve('y', 1), 1)
  const e = (await s.get(`/earnings?identity=${IDENTITY}`)).body
  assert.equal(e.earned, 75_000_000 + 100_000_000)
  assert.deepEqual(e.agents.map((a) => [a.agent, a.contributions, a.earned]), [[a1.agent, 2, 100_000_000], [a2.agent, 1, 75_000_000]])
  assert.deepEqual((await s.get(`/earnings?identity=${'f'.repeat(64)}`)).body, { identity: 'f'.repeat(64), earned: 0, collected: 0, balance: 0, agents: [] })
})

// Found by review: the standing forecast was the last to arrive, so a forecast held back on the network could stand
// over the identity's later one.
test('the standing forecast is the one signed last, whatever order they arrive in; on a tie, the later to arrive', async () => {
  const s = setup()
  const a1 = worker(10, { agent: 'alpha' })
  const a2 = worker(50, { agent: 'beta' })
  await s.post(a2.records(q('q', 10000), NOW - 3)) // signed later, arrives first
  await s.post(a1.records(q('q', 0), NOW - 5)) // signed earlier, held back
  s.f.resolve('q', 1)
  const e = (await s.get(`/earnings?identity=${IDENTITY}`)).body
  assert.equal(e.earned, 100_000_000)
  assert.deepEqual(e.agents.map((a) => [a.agent, a.earned]), [[a2.agent, 100_000_000], [a1.agent, 0]])
})

test('the same forecast under a new claim, or again by the same agent, does not earn twice', async () => {
  const s = setup()
  const a = worker(10)
  assert.equal((await s.post(a.records(q('q', 5000)))).status, 200)
  assert.equal((await s.post(a.records(q('q', 5000), NOW - 6))).status, 200, 'a new claim id, the same forecast')
  assert.equal(s.f.resolve('q', 1), 1)
  assert.equal((await s.get(`/earnings?identity=${IDENTITY}`)).body.earned, 75_000_000)
})

test('a question closes at its time and when resolved: later forecasts are refused, and resolution is final', async () => {
  let now = NOW
  const s = setup({ clock: () => now, questions: ['q', 'late'] })
  const a = worker(10)
  assert.equal((await s.post(a.records(q('q', 9000)))).status, 200)
  assert.equal(s.f.resolve('q', 1), 1)
  // After resolution: refused, the claim spent; resolving again with the same outcome scores nothing more.
  const after = await s.post(a.records(q('q', 10_000), NOW - 6))
  assert.deepEqual({ status: after.status, body: after.body }, { status: 422, body: { ok: false, reason: 'question' } })
  assert.equal(s.f.resolve('q', 1), 0)
  assert.throws(() => s.f.resolve('q', 0), { message: 'already resolved with the other outcome' })
  assert.equal((await s.get(`/earnings?identity=${IDENTITY}`)).body.earned, 99_000_000)
  // A question not asked, or past its closing time, is refused.
  assert.equal((await s.post(a.records(q('unasked', 1), NOW - 7))).body.reason, 'question')
  now = CLOSES - 1
  assert.equal((await s.post(a.records(q('late', 1), CLOSES - 8))).status, 200, 'open until its closing time')
  now = CLOSES
  assert.equal((await s.post(a.records(q('late', 2), CLOSES - 9))).body.reason, 'question', 'closed at it')
  assert.equal(s.f.resolve('late', 0), 1)
  assert.equal((await s.get(`/earnings?identity=${IDENTITY}`)).body.agents[0].earned, 99_000_000 + 99_999_999, 'a forecast one basis point off loses one unit: nothing is rounded away')
})

// Issue #64: the score was rounded to whole basis points, and a rounded Brier score is no longer proper: believing
// 0.5%, a forecast of 0.99% earned as much if the outcome was 0 and more if it was 1. The exact numerator is kept.
test('the score is the exact Brier numerator: the truthful forecast alone earns the most in expectation', () => {
  assert.deepEqual([score(0, 0), score(0, 1), score(10_000, 1), score(10_000, 0), score(5000, 0), score(5000, 1)], [100_000_000, 0, 100_000_000, 0, 75_000_000, 75_000_000])
  assert.deepEqual([score(50, 0), score(50, 1), score(99, 0), score(99, 1)], [99_997_500, 997_500, 99_990_199, 1_970_199])
  // The expected score, times 10,000, of forecast f under a belief of p basis points; every value is a safe integer.
  const expected = (p, f) => p * score(f, 1) + (10_000 - p) * score(f, 0)
  assert.ok(expected(50, 50) > expected(50, 99), 'the counterexample')
  for (const p of [0, 1, 50, 99, 3333, 5000, 9950, 9999, 10_000]) {
    const best = expected(p, p)
    assert.ok(Number.isSafeInteger(best))
    for (let f = 0; f <= 10_000; f++) if (f !== p) assert.ok(expected(p, f) < best, `believing ${p}, forecasting ${f}`)
  }
})

test('asking: a question once, by a well-formed name and a closing time', () => {
  const s = setup({ questions: [] })
  for (const [question, closes] of [[1, CLOSES], ['', CLOSES], ['x'.repeat(65), CLOSES], ['a b', CLOSES], ['q', -1], ['q', 1.5], ['q', '1']]) {
    assert.throws(() => s.f.ask(question, closes), { name: 'TypeError', message: 'a question and a closing time' }, JSON.stringify([question, closes]))
  }
  s.f.ask('q', 0)
  assert.throws(() => s.f.ask('q', CLOSES), { message: 'already asked' })
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
  assert.throws(() => s.f.resolve('nothing', 1), { message: 'not asked' })
  assert.deepEqual((await s.get('/earnings')).body, { ok: false, reason: 'identity' })
  for (const id of ['x' + IDENTITY, IDENTITY + 'x']) assert.deepEqual((await s.get(`/earnings?identity=${id}`)).body, { ok: false, reason: 'identity' })
  // The bounds are inclusive: 0 and 10,000 are forecasts.
  assert.equal((await s.post(a.records(q('q', 0), NOW - 30))).status, 200)
  assert.equal((await s.post(a.records(q('q', 10_000), NOW - 31))).status, 200)
  assert.deepEqual((await s.get(`/earnings?identity=${IDENTITY}`, { method: 'POST', body: '' })).body, { ok: false, reason: 'method' })
  assert.deepEqual((await s.get('/collect')).body, { ok: false, reason: 'method' })
})
