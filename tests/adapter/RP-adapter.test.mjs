// Issue #21: the relying-party adapter makes replay refusal and head memory atomic around the pure verifier. A claim
// is consumed by one atomic insert before the protected action runs; the remembered head only moves forward; storage
// that fails or reads back corrupt is refused, and the action does not run.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { relyingParty, memoryStore, sqliteStore } from './impl.mjs'
import { verifier, verifierWithKey, records, claim, head, CALL, NOW, IDENTITY, DELEGATION_ID, W2, delegation2 } from './fixtures.mjs'

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
    assert.deepEqual(await store.lastHead(IDENTITY), { head: head(NOW - 50), at: NOW - 50 })
    assert.deepEqual(await rp.acceptClaim(records(claim(NOW - 4, 'two'), head(NOW - 100)), CALL, () => 1), refused('stale'))
    await store.transaction((tx) => tx.advanceHead(IDENTITY, head(NOW - 100), NOW - 100)) // a late writer with an older head
    assert.deepEqual(await store.lastHead(IDENTITY), { head: head(NOW - 50), at: NOW - 50 }, 'not moved back')
    assert.equal((await rp.acceptClaim(records(claim(NOW - 3, 'three'), head(NOW - 20)), CALL, () => 1)).ok, true)
    assert.deepEqual(await store.lastHead(IDENTITY), { head: head(NOW - 20), at: NOW - 20 })
  })

  test(`${name}: delegations alone use and advance the same memory`, async () => {
    const store = open()
    const rp = relyingParty({ verifier: verifier(), store })
    const { claim: _, ...d } = records(undefined, head(NOW - 40))
    assert.equal((await rp.acceptDelegation(d, CALL)).ok, true)
    assert.deepEqual(await store.lastHead(IDENTITY), { head: head(NOW - 40), at: NOW - 40 })
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
  assert.deepEqual(await b.lastHead(IDENTITY), { head: head(NOW - 30), at: NOW - 30 })
  b.close()
})

test('storage that fails is refused, and the action does not run', async () => {
  const failing = memoryStore()
  failing.transaction = async () => { throw new Error('disk') }
  let runs = 0
  assert.deepEqual(await relyingParty({ verifier: verifier(), store: failing }).acceptClaim(records(), CALL, () => runs++), refused('storage'), 'transaction')
  for (const op of ['lastHead', 'advanceHead', 'consume']) {
    const base = memoryStore()
    const store = { ...base, transaction: (fn) => base.transaction((tx) => fn({ ...tx, [op]: () => { throw new Error('disk') } })) }
    assert.deepEqual(await relyingParty({ verifier: verifier(), store }).acceptClaim(records(), CALL, () => runs++), refused('storage'), op)
  }
  assert.equal(runs, 0)
})

// Found by review: a stored head the verifier can no longer read (corrupt, or signed by a witness key since removed)
// locked its identity out for good. Its stored time still bounds rollback.
test('a stored head the verifier cannot read still bounds rollback by its time; a corrupt time is refused as storage', async () => {
  const store = memoryStore()
  await store.transaction((tx) => tx.advanceHead(IDENTITY, 'not a head', NOW - 60))
  const rp = relyingParty({ verifier: verifier(), store })
  let runs = 0
  assert.deepEqual(await rp.acceptClaim(records(undefined, head(NOW - 100)), CALL, () => runs++), refused('stale'), 'older than the stored time')
  assert.equal((await rp.acceptClaim(records(undefined, head(NOW - 30)), CALL, () => runs++)).ok, true, 'newer')
  assert.equal(runs, 1)
  for (const at of ['x', -1, 1.5]) {
    const bad = memoryStore()
    await bad.transaction((tx) => tx.advanceHead(IDENTITY, 'not a head', at))
    assert.deepEqual(await relyingParty({ verifier: verifier(), store: bad }).acceptClaim(records(), CALL, () => runs++), refused('storage'), `time ${at}`)
  }
  const zero = memoryStore()
  await zero.transaction((tx) => tx.advanceHead(IDENTITY, 'not a head', 0))
  assert.equal((await relyingParty({ verifier: verifier(), store: zero }).acceptClaim(records(), CALL, () => runs++)).ok, true, 'time 0 is a time')
  assert.equal(runs, 2)
  // The caller's own floor applies when it is the later one; a malformed call still throws, whatever is stored.
  const floored = memoryStore()
  await floored.transaction((tx) => tx.advanceHead(IDENTITY, 'not a head', NOW - 200))
  const fr = relyingParty({ verifier: verifier(), store: floored })
  assert.deepEqual(await fr.acceptClaim(records(claim(NOW - 5, 'x'), head(NOW - 100)), { ...CALL, minHeadAt: NOW - 80 }, () => 1), refused('stale'), 'the call floor, later')
  assert.equal((await fr.acceptClaim(records(claim(NOW - 4, 'y'), head(NOW - 100)), { ...CALL, minHeadAt: NOW - 250 }, () => 1)).ok, true, 'the stored floor, later')
  await assert.rejects(fr.acceptClaim(records(claim(NOW - 3, 'z'), head(NOW - 50)), { ...CALL, minHeadAt: -1 }, () => 1), TypeError, 'a malformed floor')
  const corrupt = memoryStore()
  await corrupt.transaction((tx) => tx.advanceHead(IDENTITY, 'not a head', 'x'))
  await assert.rejects(relyingParty({ verifier: verifier(), store: corrupt }).acceptClaim(records(), { ...CALL, now: -1 }, () => 1), TypeError, 'malformed call, corrupt store')
  await assert.rejects(rp.acceptClaim(records(), { ...CALL, scope: 'not a scope!' }, () => runs++), TypeError)
  await assert.rejects(relyingParty({ verifier: verifier(), store: memoryStore() }).acceptClaim(records(), { ...CALL, now: -1 }, () => 1), TypeError)
})

test('a witness key rotation: memory under the removed key does not lock the identity out', async () => {
  const store = memoryStore()
  assert.equal((await relyingParty({ verifier: verifier(), store }).acceptClaim(records(claim(NOW - 5, 'a'), head(NOW - 60)), CALL, () => 1)).ok, true)
  const rotated = relyingParty({ verifier: verifierWithKey(W2), store })
  assert.equal((await rotated.acceptClaim(records(claim(NOW - 4, 'b'), head(NOW - 30, { secret: W2 })), CALL, () => 1)).ok, true)
  assert.deepEqual(await rotated.acceptClaim(records(claim(NOW - 3, 'c'), head(NOW - 90, { secret: W2 })), CALL, () => 1), refused('stale'))
})

// Found by review: the memory was read, then the records verified, then the head advanced, so a request holding an
// old head could pass while another stored a newer one that revokes its delegation. Verification now happens inside
// the transaction, against the memory as it stands there.
test('a request whose transaction waits behind another is verified against the memory that one left', async () => {
  const base = memoryStore()
  await base.transaction((tx) => tx.advanceHead(IDENTITY, head(NOW - 300), NOW - 300))
  let release
  const held = new Promise((resolve) => { release = resolve })
  let holdNext = true
  const store = { ...base, transaction: async (fn) => { if (holdNext) { holdNext = false; await held } return base.transaction(fn) } }
  const rp = relyingParty({ verifier: verifier(), store })
  let runs = 0
  const attacker = rp.acceptClaim(records(claim(NOW - 5, 'attacker'), head(NOW - 200)), CALL, () => runs++)
  const { claim: _, ...d } = records(undefined, head(NOW - 100, { revoked: [DELEGATION_ID] }))
  assert.equal((await rp.acceptDelegation({ ...d, delegation: delegation2 }, CALL)).ok, true, 'an honest request stores a head revoking the first delegation')
  release()
  assert.deepEqual(await attacker, refused('stale'))
  assert.equal(runs, 0)
})

// Found by review: the records were read more than once, so an object returning different heads could bypass the
// memory or store a head under another identity.
test('the presented records are read once each', async () => {
  const reads = { claim: 0, delegation: 0, root: 0, head: 0 }
  const r = records()
  const given = Object.defineProperties({}, Object.fromEntries(Object.keys(reads).map((k) => [k, { enumerable: true, get () { reads[k]++; return r[k] } }])))
  assert.equal((await relyingParty({ verifier: verifier(), store: memoryStore() }).acceptClaim(given, CALL, () => 1)).ok, true)
  assert.deepEqual(reads, { claim: 1, delegation: 1, root: 1, head: 1 })
  const throwing = Object.defineProperty({}, 'head', { get () { throw new Error('boom') } })
  assert.deepEqual(await relyingParty({ verifier: verifier(), store: memoryStore() }).acceptDelegation(throwing, CALL), refused('head'))
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
  const counting = { ...store, transaction: (fn) => store.transaction((tx) => fn({ ...tx, lastHead: (i) => { lookups++; return tx.lastHead(i) } })) }
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
    const consume = (id, until) => s.transaction((tx) => tx.consume(id, until))
    assert.equal(await consume('a', 10), true)
    assert.equal(await consume('a', 10), false)
    await consume('b', 11)
    await s.expire(9 + 60) // the default grace: 60 s past until
    assert.deepEqual([await consume('a', 10), await consume('b', 11)], [false, false], 'nothing before its until')
    await s.expire(10 + 60)
    assert.deepEqual([await consume('a', 10), await consume('b', 11)], [true, false], 'a at its until, b not yet')
    await s.transaction((tx) => tx.advanceHead('i', 'first', 5))
    await s.transaction((tx) => tx.advanceHead('i', 'second', 5))
    assert.deepEqual(await s.lastHead('i'), { head: 'first', at: 5 }, 'a head of the same time does not replace the one held')
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
  await store.transaction((tx) => tx.advanceHead(IDENTITY, head(NOW - 100), NOW - 100))
  const boom = { verifyClaim () { throw new Error('boom') }, verifyDelegation () { throw new Error('boom') } }
  await assert.rejects(relyingParty({ verifier: boom, store }).acceptClaim(records(), CALL, () => 1), /boom/)
  // Throwing only when given the stored head: still propagated, not mistaken for corrupt storage.
  const v = verifier()
  const onlyWithLast = { verifyHead: (h, c) => v.verifyHead(h, c), verifyClaim (g, c) { if (c.lastHead !== undefined) throw new Error('boom'); return v.verifyClaim(g, c) } }
  await assert.rejects(relyingParty({ verifier: onlyWithLast, store }).acceptClaim(records(), CALL, () => 1), /boom/)
  await assert.rejects(relyingParty({ verifier: boom, store: memoryStore() }).acceptDelegation(records(), CALL), /boom/)
})

test('sqlite store: a transaction that fails is rolled back', async () => {
  const s = sqliteStore(join(tmp(), 'rp.db'))
  await assert.rejects(s.transaction((tx) => { tx.advanceHead('i', 'h', 5); tx.consume('c', 9); throw new Error('midway') }), /midway/)
  assert.equal(await s.lastHead('i'), undefined)
  assert.equal(await s.transaction((tx) => tx.consume('c', 9)), true, 'the claim was not consumed')
  s.close()
})

// Found by review: an instance whose clock is behind another's (within skew) could accept a claim the other had already
// expired. Claim ids are kept a grace period past `until`: 60 s by default, a deployment's largest clock difference.
for (const [name, open] of [['memory', (o) => memoryStore(o)], ['sqlite', (o) => sqliteStore(join(tmp(), 'rp.db'), o)]]) {
  test(`${name}: claim ids are kept a grace period past until, so a slower clock cannot replay one`, async () => {
    const store = open()
    const b = relyingParty({ verifier: verifier(), store })
    const r = await b.acceptClaim(records(), CALL, () => 1)
    await store.expire(r.until + 6) // another instance, 6 s ahead
    assert.deepEqual(await b.acceptClaim(records(), { ...CALL, now: r.until - 10 }, () => 1), refused('replay'))
    const consume = (id, until) => store.transaction((tx) => tx.consume(id, until))
    await store.expire(r.until + 59)
    assert.equal(await consume(r.id, r.until), false, 'kept until until + 60')
    await store.expire(r.until + 60)
    assert.equal(await consume(r.id, r.until), true, 'removed at until + 60')
    const strict = open({ grace: 0 })
    await strict.transaction((tx) => tx.consume('x', 10))
    await strict.expire(10)
    assert.equal(await strict.transaction((tx) => tx.consume('x', 10)), true, 'grace 0: removed at until')
  })
}

test("the request's nonce and body digest reach the verifier", async () => {
  const rp = relyingParty({ verifier: verifier(), store: memoryStore() })
  const digest = Buffer.alloc(32, 7).toString('base64')
  const c = claim(NOW - 5, 'n', { nonce: 'n-1', content_digest: digest })
  assert.deepEqual(await rp.acceptClaim(records(c), { ...CALL, nonce: 'n-1' }, () => 1), refused('claim-digest'))
  assert.deepEqual(await rp.acceptClaim(records(c), { ...CALL, contentDigest: digest }, () => 1), refused('claim-nonce'))
  assert.equal((await rp.acceptClaim(records(c), { ...CALL, nonce: 'n-1', contentDigest: digest }, () => 1)).ok, true)
})

// Found by review: the call's fields were copied with a spread, which drops inherited ones; now read once.
test('call fields are read once, including inherited ones', async () => {
  const store = memoryStore()
  const rp = relyingParty({ verifier: verifier(), store })
  assert.equal((await rp.acceptClaim(records(claim(NOW - 5, 'a'), head(NOW - 100)), CALL, () => 1)).ok, true)
  const inherited = Object.assign(Object.create({ minHeadAt: NOW - 50 }), CALL)
  assert.deepEqual(await rp.acceptClaim(records(claim(NOW - 4, 'b'), head(NOW - 80)), inherited, () => 1), refused('stale'))
  const reads = {}
  const counting = new Proxy({ ...CALL }, { get (t, k) { reads[k] = (reads[k] ?? 0) + 1; return t[k] } })
  await rp.acceptClaim(records(claim(NOW - 3, 'c'), head(NOW - 70)), counting, () => 1)
  for (const k of ['now', 'scope', 'method', 'url', 'nonce', 'contentDigest', 'revoked', 'minHeadAt']) assert.equal(reads[k], 1, k)
  await assert.rejects(rp.acceptClaim(records(), null, () => 1), TypeError)
})

// Found by review: every request whose head parsed held the database lock for a full verification; and (a third
// review) a head that revoked a delegation was never remembered when the request carrying it was refused. A head
// that verifies is remembered whatever else the request carries (F6); a refused request takes the lock only to
// remember a head newer than the memory, and one whose head does not verify never takes it.
test('a refused request takes the transaction only to remember a newer head', async () => {
  const base = memoryStore()
  let transactions = 0
  const store = { ...base, transaction: (fn) => { transactions++; return base.transaction(fn) } }
  const rp = relyingParty({ verifier: verifier(), store })
  assert.deepEqual(await rp.acceptClaim(records(undefined, 'not a head'), CALL, () => 1), refused('head'))
  assert.equal(transactions, 0, 'a head that does not verify')
  assert.deepEqual(await rp.acceptClaim(records(), { ...CALL, scope: 'read' }, () => 1), refused('claim-scope'))
  assert.equal(transactions, 1, 'a newer head, remembered')
  assert.deepEqual(await base.lastHead(IDENTITY), { head: head(NOW - 100), at: NOW - 100 })
  assert.deepEqual(await rp.acceptClaim(records(), { ...CALL, scope: 'read' }, () => 1), refused('claim-scope'))
  assert.equal(transactions, 1, 'the same head again: nothing to remember')
  assert.deepEqual(await rp.acceptClaim(records(undefined, head(NOW - 200)), { ...CALL, scope: 'read' }, () => 1), refused('claim-scope'), 'checked before the head')
  assert.equal(transactions, 1, 'an older head: nothing to remember')
  assert.equal((await rp.acceptClaim(records(), CALL, () => 1)).ok, true)
  assert.equal(transactions, 2)
})

test('a head that revokes the delegation is remembered from the request it refuses, so an older head is then stale', async () => {
  for (const store of [memoryStore(), sqliteStore(join(tmp(), 'rp.db'))]) {
    await store.transaction((tx) => tx.advanceHead(IDENTITY, head(NOW - 200), NOW - 200)) // an older memory, replaced
    const rp = relyingParty({ verifier: verifier(), store })
    let runs = 0
    assert.deepEqual(await rp.acceptClaim(records(claim(NOW - 5), head(NOW - 50, { revoked: [DELEGATION_ID] })), CALL, () => runs++), refused('revoked'))
    assert.equal((await store.lastHead(IDENTITY)).at, NOW - 50)
    assert.deepEqual(await rp.acceptClaim(records(claim(NOW - 4), head(NOW - 100)), CALL, () => runs++), refused('stale'))
    assert.equal(runs, 0)
  }
})

test('a replayed claim still moves the memory to its newer head; a stale head moves nothing', async () => {
  const store = memoryStore()
  const rp = relyingParty({ verifier: verifier(), store })
  const c = claim(NOW - 5)
  assert.equal((await rp.acceptClaim(records(c, head(NOW - 100)), CALL, () => 1)).ok, true)
  assert.deepEqual(await rp.acceptClaim(records(c, head(NOW - 30)), CALL, () => 1), refused('replay'))
  assert.equal((await store.lastHead(IDENTITY)).at, NOW - 30)
  assert.deepEqual(await rp.acceptClaim(records(claim(NOW - 4), head(NOW - 60)), CALL, () => 1), refused('stale'))
  assert.equal((await store.lastHead(IDENTITY)).at, NOW - 30)
})

test('a lastHead in the call is a programming error: the adapter supplies it from its memory', async () => {
  const rp = relyingParty({ verifier: verifier(), store: memoryStore() })
  await assert.rejects(rp.acceptClaim(records(), { ...CALL, lastHead: head(NOW - 50) }, () => 1), /supplies lastHead/)
})

test('storage failing on the memory read before the lock is refused as storage', async () => {
  const store = memoryStore()
  await store.transaction((tx) => tx.advanceHead(IDENTITY, head(NOW - 200), NOW - 200))
  store.lastHead = async () => { throw new Error('disk') }
  let runs = 0
  assert.deepEqual(await relyingParty({ verifier: verifier(), store }).acceptClaim(records(), { ...CALL, scope: 'read' }, () => runs++), refused('storage'))
  assert.equal(runs, 0)
})

test('a head that verifies alone but not against the memory (equivocation) is not remembered', async () => {
  const store = memoryStore()
  const settled = head(NOW - 100, { epoch: 3, memberships: ['6'.repeat(64)] })
  await store.transaction((tx) => tx.advanceHead(IDENTITY, settled, NOW - 100))
  const rp = relyingParty({ verifier: verifier(), store })
  const forked = head(NOW - 50, { epoch: 2, memberships: ['5'.repeat(64)] })
  assert.deepEqual(await rp.acceptClaim(records(undefined, forked), CALL, () => 1), refused('equivocation'))
  assert.deepEqual(await store.lastHead(IDENTITY), { head: settled, at: NOW - 100 })
})

// Found by review: heads of one second may come in either order (F5), and the memory kept whichever it saw first. On
// a tie it now keeps the one the verifier ranks later: the new head if it may follow the stored one and not the
// reverse.
test('two heads of one second: the memory keeps the later in the honest order, whichever arrives first', async () => {
  const T = NOW - 100
  for (const [name, later] of [['settled into another membership', head(T, { epoch: 2, memberships: ['5'.repeat(64)] })],
    ['a successor turned pending', head(T, { memberships: [IDENTITY, '5'.repeat(64)] })]]) {
    for (const store of [memoryStore(), sqliteStore(join(tmp(), 'rp.db'))]) {
      const rp = relyingParty({ verifier: verifier(), store })
      assert.equal((await rp.acceptClaim(records(claim(NOW - 5, 'a'), head(T)), CALL, () => 1)).ok, true, name)
      await rp.acceptClaim(records(claim(NOW - 4, 'b'), later), CALL, () => 1)
      assert.equal((await store.lastHead(IDENTITY)).head, later, name)
      assert.deepEqual(await rp.acceptClaim(records(claim(NOW - 3, 'c'), head(T)), CALL, () => 1), refused('stale'), name)
      assert.equal((await store.lastHead(IDENTITY)).head, later, `${name}: not moved back`)
    }
  }
})

// Found by review: a request refused before the lock gave its reason without the memory, so equivocation by the
// witness could be reported as the request's other fault.
test('a request refused before the lock gives the reason the memory gives', async () => {
  const T = NOW - 100
  const store = memoryStore()
  const stored = head(T, { epoch: 2, memberships: ['6'.repeat(64)] })
  await store.transaction((tx) => tx.advanceHead(IDENTITY, stored, T))
  const rp = relyingParty({ verifier: verifier(), store })
  assert.deepEqual(await rp.acceptClaim(records(undefined, head(T, { epoch: 2, memberships: ['5'.repeat(64)] })), CALL, () => 1), refused('equivocation'))
  assert.deepEqual(await rp.acceptClaim(records(undefined, head(T - 10, { epoch: 2, memberships: ['6'.repeat(64)] })), CALL, () => 1), refused('stale'))
})

test('two heads of one second, each able to follow the other: the memory keeps the one it holds', async () => {
  const T = NOW - 100
  const revoking = head(T, { revoked: ['7'.repeat(64)] }) // differs only in what it revokes
  const store = memoryStore()
  await store.transaction((tx) => tx.advanceHead(IDENTITY, revoking, T))
  await relyingParty({ verifier: verifier(), store }).acceptClaim(records(undefined, head(T)), CALL, () => 1)
  assert.equal((await store.lastHead(IDENTITY)).head, revoking, 'not replaced by a head that drops a revocation')
})

for (const [name, open] of [['memory', () => memoryStore()], ['sqlite', () => sqliteStore(join(tmp(), 'rp.db'))]]) {
  test(`${name} store: replaceHead replaces only the head given, of the same time`, async () => {
    const s = open()
    await s.transaction((tx) => tx.replaceHead('i', 'b', 5, 'a'))
    assert.equal(await s.lastHead('i'), undefined, 'nothing held')
    await s.transaction((tx) => tx.advanceHead('i', 'a', 5))
    await s.transaction((tx) => tx.replaceHead('i', 'b', 5, 'x'))
    assert.deepEqual(await s.lastHead('i'), { head: 'a', at: 5 }, 'another head held')
    await s.transaction((tx) => tx.replaceHead('i', 'b', 6, 'a'))
    assert.deepEqual(await s.lastHead('i'), { head: 'a', at: 5 }, 'another time')
    await s.transaction((tx) => tx.replaceHead('i', 'b', 5, 'a'))
    assert.deepEqual(await s.lastHead('i'), { head: 'b', at: 5 })
  })
}
