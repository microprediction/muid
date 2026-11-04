// Issue #21: the relying-party adapter makes replay refusal and head memory atomic around the pure verifier. A claim
// is consumed by one atomic insert before the protected action runs; the remembered head only moves forward; storage
// that fails or reads back corrupt is refused, and the action does not run.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { relyingParty, memoryStore, sqliteStore } from './impl.mjs'
import { verifier, records, claim, head, CALL, NOW, IDENTITY } from './fixtures.mjs'

const refused = (reason) => ({ ok: false, reason })
const tmp = () => mkdtempSync(join(tmpdir(), 'muid-rp-'))

for (const [name, open] of [['memory', () => memoryStore()], ['sqlite', () => sqliteStore(join(tmp(), 'rp.db'))]]) {
  test(`${name}: a claim runs the action once; a replay is refused and the action does not run again`, async () => {
    const rp = relyingParty({ verifier: verifier(), store: open() })
    let runs = 0
    const action = async (r) => { runs++; return r.body.data.text }
    const first = await rp.acceptClaim(records(), CALL, action)
    assert.deepEqual([first.ok, first.value], [true, 'a forecast'])
    assert.deepEqual(await rp.acceptClaim(records(), CALL, action), refused('replay'))
    assert.equal(runs, 1)
  })

  test(`${name}: a refused claim consumes nothing and runs nothing`, async () => {
    const store = open()
    const rp = relyingParty({ verifier: verifier(), store })
    let runs = 0
    assert.deepEqual(await rp.acceptClaim(records(), { ...CALL, scope: 'read' }, () => runs++), refused('claim-scope'))
    assert.equal((await rp.acceptClaim(records(), CALL, () => runs++)).ok, true, 'still unconsumed')
    assert.equal(runs, 1)
  })

  test(`${name}: the remembered head only moves forward, and an older head is then refused`, async () => {
    const store = open()
    const rp = relyingParty({ verifier: verifier(), store })
    assert.equal((await rp.acceptClaim(records(claim(NOW - 5, 'one'), head(NOW - 50)), CALL, () => 1)).ok, true)
    assert.equal(await store.lastHead(IDENTITY), head(NOW - 50))
    assert.deepEqual(await rp.acceptClaim(records(claim(NOW - 4, 'two'), head(NOW - 100)), CALL, () => 1), refused('stale'))
    await store.advanceHead(IDENTITY, head(NOW - 100), NOW - 100) // a late writer with an older head
    assert.equal(await store.lastHead(IDENTITY), head(NOW - 50), 'not moved back')
    assert.equal((await rp.acceptClaim(records(claim(NOW - 3, 'three'), head(NOW - 20)), CALL, () => 1)).ok, true)
    assert.equal(await store.lastHead(IDENTITY), head(NOW - 20))
  })

  test(`${name}: delegations alone use and advance the same memory`, async () => {
    const store = open()
    const rp = relyingParty({ verifier: verifier(), store })
    const { claim: _, ...d } = records(undefined, head(NOW - 40))
    assert.equal((await rp.acceptDelegation(d, CALL)).ok, true)
    assert.equal(await store.lastHead(IDENTITY), head(NOW - 40))
    assert.deepEqual(await rp.acceptDelegation({ ...d, head: head(NOW - 90) }, CALL), refused('stale'))
  })

  test(`${name}: expiry removes a claim id only once the verifier refuses the claim by its time`, async () => {
    const store = open()
    const rp = relyingParty({ verifier: verifier(), store })
    const c = claim(NOW - 5)
    const r = await rp.acceptClaim(records(c), CALL, () => 1)
    assert.equal(r.until, NOW - 5 + 301)
    await store.expire(r.until - 1)
    assert.deepEqual(await rp.acceptClaim(records(c), { ...CALL, now: r.until - 1 }, () => 1), refused('replay'), 'kept while now < until')
    await store.expire(r.until)
    assert.deepEqual(await rp.acceptClaim(records(c), { ...CALL, now: r.until }, () => 1), refused('claim-time'), 'refused by time once removed')
  })
}

test('sqlite: a restart keeps consumed claims and the remembered head', async () => {
  const file = join(tmp(), 'rp.db')
  const a = sqliteStore(file)
  assert.equal((await relyingParty({ verifier: verifier(), store: a }).acceptClaim(records(undefined, head(NOW - 30)), CALL, () => 1)).ok, true)
  a.close()
  const b = sqliteStore(file)
  const rp = relyingParty({ verifier: verifier(), store: b })
  assert.deepEqual(await rp.acceptClaim(records(undefined, head(NOW - 30)), CALL, () => 1), refused('replay'))
  assert.equal(await b.lastHead(IDENTITY), head(NOW - 30))
  b.close()
})

test('storage that fails is refused, and the action does not run', async () => {
  for (const method of ['lastHead', 'advanceHead', 'consume']) {
    const store = { ...memoryStore(), [method]: async () => { throw new Error('disk') } }
    let runs = 0
    assert.deepEqual(await relyingParty({ verifier: verifier(), store }).acceptClaim(records(), CALL, () => runs++), refused('storage'), method)
    assert.equal(runs, 0, method)
  }
})

test('a stored head that reads back corrupt is refused as storage; a malformed call is still a programming error', async () => {
  const store = memoryStore()
  await store.advanceHead(IDENTITY, 'not a head', NOW)
  const rp = relyingParty({ verifier: verifier(), store })
  let runs = 0
  assert.deepEqual(await rp.acceptClaim(records(), CALL, () => runs++), refused('storage'))
  assert.equal(runs, 0)
  await assert.rejects(rp.acceptClaim(records(), { ...CALL, scope: 'not a scope!' }, () => runs++), TypeError)
  await assert.rejects(relyingParty({ verifier: verifier(), store: memoryStore() }).acceptClaim(records(), { ...CALL, now: -1 }, () => 1), TypeError)
})

test('an action that fails leaves the claim consumed: the delegate makes a new claim', async () => {
  const rp = relyingParty({ verifier: verifier(), store: memoryStore() })
  await assert.rejects(rp.acceptClaim(records(), CALL, async () => { throw new Error('downstream') }), /downstream/)
  assert.deepEqual(await rp.acceptClaim(records(), CALL, () => 1), refused('replay'))
  assert.equal((await rp.acceptClaim(records(claim(NOW - 4)), CALL, () => 1)).ok, true)
})

test('concurrent requests in one process: exactly one runs the action', async () => {
  const rp = relyingParty({ verifier: verifier(), store: memoryStore() })
  let runs = 0
  const results = await Promise.all(Array.from({ length: 20 }, () => rp.acceptClaim(records(), CALL, async () => { runs++ })))
  assert.equal(results.filter((r) => r.ok).length, 1)
  assert.equal(runs, 1)
})

test('a presented head that cannot be read is not looked up; the verifier refuses it', async () => {
  const store = memoryStore()
  let lookups = 0
  const counting = { ...store, lastHead: async (i) => { lookups++; return store.lastHead(i) } }
  const rp = relyingParty({ verifier: verifier(), store: counting })
  const { envelope } = await import('../impl.mjs')
  const odd = (b) => envelope.wrap(envelope.seal('head', b).payload, { signature: 'x' })
  for (const h of ['not a head', odd({ identity: 5, at: 'x' }), odd({ identity: IDENTITY, at: 'x' }), odd({ identity: 5, at: NOW })]) {
    assert.deepEqual(await rp.acceptClaim(records(undefined, h), CALL, () => 1), refused('head'))
  }
  assert.deepEqual(await rp.acceptDelegation(null, CALL), refused('head'))
  assert.deepEqual(await rp.acceptClaim(null, CALL, () => 1), refused('envelope-encoding'), 'a claim is opened first')
  assert.equal(lookups, 0)
})

for (const [name, open] of [['memory', () => memoryStore()], ['sqlite', () => sqliteStore(join(tmp(), 'rp.db'))]]) {
  test(`${name} store: consume once; expire removes exactly the ids whose until has come; equal times keep the first head`, async () => {
    const s = open()
    assert.equal(await s.consume('a', 10), true)
    assert.equal(await s.consume('a', 10), false)
    await s.consume('b', 11)
    await s.expire(9)
    assert.deepEqual([await s.consume('a', 10), await s.consume('b', 11)], [false, false], 'nothing before its until')
    await s.expire(10)
    assert.deepEqual([await s.consume('a', 10), await s.consume('b', 11)], [true, false], 'a at its until, b not yet')
    await s.advanceHead('i', 'first', 5)
    await s.advanceHead('i', 'second', 5)
    assert.equal(await s.lastHead('i'), 'first', 'a head of the same time does not replace the one held')
    assert.equal(await s.lastHead('unknown'), undefined)
  })
}

test('sqlite store: closed, it refuses to work', async () => {
  const s = sqliteStore(join(tmp(), 'rp.db'))
  s.close()
  await assert.rejects(s.lastHead('i'))
})

test('anything other than a TypeError from the verifier propagates, with or without a stored head', async () => {
  const store = memoryStore()
  await store.advanceHead(IDENTITY, head(NOW - 100), NOW - 100)
  const boom = { verifyClaim () { throw new Error('boom') }, verifyDelegation () { throw new Error('boom') } }
  await assert.rejects(relyingParty({ verifier: boom, store }).acceptClaim(records(), CALL, () => 1), /boom/)
  // Throwing only when given the stored head: still propagated, not mistaken for corrupt storage.
  const v = verifier()
  const onlyWithLast = { verifyClaim (g, c) { if (c.lastHead !== undefined) throw new Error('boom'); return v.verifyClaim(g, c) } }
  await assert.rejects(relyingParty({ verifier: onlyWithLast, store }).acceptClaim(records(), CALL, () => 1), /boom/)
  await assert.rejects(relyingParty({ verifier: boom, store: memoryStore() }).acceptDelegation(records(), CALL), /boom/)
})
