// Recovery parties (SPEC §5, R11) in the executable model: what a designated party can and cannot do, what an owner
// with any one root can always do about it, and the limits that are stated rather than hidden. Each rule has a
// negative control: the model with that rule turned off, where the property it is for fails.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { history, evaluate, witness, tick, reach, forkedView, contestId, WINDOW } from '../../model/settled.mjs'
import { membershipId, genesisOf, withRules, COOL, RMIN, RMAX } from '../../model/recovery.mjs'

const G = genesisOf('a').id
const one = (w = 2) => ({ parties: ['g'], k: 1, w })
const two = { parties: ['g', 'h'], k: 2, w: 2 }
// Epoch 2: roots a and b, with the designation given. Its record id, and the item set once it has settled.
const base = (rec) => ({ m2: membershipId(2, ['a', 'b'], G, rec), items: history('a', [{ roots: ['a', 'b'], rec }]) })
// A recovery of epoch 2 to `roots`, signed by `parties` and by every root it adds; the designation is kept.
const recovery = (m2, rec, roots, parties) => {
  const sorted = [...roots].sort()
  const signers = [...parties, ...sorted.filter((r) => !['a', 'b'].includes(r))]
  return { id: membershipId(3, sorted, m2, rec), sign: signers.map((signer) => ({ kind: 'M', n: 3, roots: sorted, prev: m2, rec, signer })) }
}
const ev = (items) => evaluate('a', items)
const ticks = (items, n) => { let s = items; for (let i = 0; i < n; i++) s = tick('a', s); return s }
const kinds = (items, kind, id) => items.filter((it) => it.kind === kind && (id === undefined || it.id === id))
const asItWas = (items, m2) => { const e = ev(items); return !e.dead && !e.pending && !e.frozen && e.record.id === m2 && e.authority.join() === 'a,b' }

test('a designation is an ordinary change: a majority of the roots; a party is not a root and has no authority', () => {
  const { m2, items } = base(one())
  assert.ok(asItWas(items, m2))
  assert.deepEqual(ev(items).record.rec, one())
  assert.equal(ev(items).notice, null)
  // One root of two is no majority, with or without the party it would name, or the party already named.
  for (const signers of [['b'], ['b', 'x'], ['b', 'g']]) {
    const rec = { parties: ['x'], k: 1, w: 2 }
    const s = witness('a', [...items, ...signers.map((signer) => ({ kind: 'M', n: 3, roots: ['a', 'b'], prev: m2, rec, signer }))])
    assert.equal(kinds(s, 'A', membershipId(3, ['a', 'b'], m2, rec)).length, 0, signers.join())
  }
  // A designation out of form is no membership: no party, too many, k not a majority of them or above their number,
  // or the window out of range.
  for (const rec of [{ parties: [], k: 1, w: 2 }, { parties: ['g', 'h', 'i', 'j'], k: 1, w: 2 },
    { parties: ['g'], k: 2, w: 2 }, { parties: ['g'], k: 0, w: 2 }, { parties: ['g', 'h'], k: 1, w: 2 }, { parties: ['g', 'h', 'i'], k: 1, w: 2 }, { parties: ['g'], k: 1, w: RMIN - 1 }, { parties: ['g'], k: 1, w: RMAX + 1 }]) {
    const s = witness('a', [...items, ...['a', 'b'].map((signer) => ({ kind: 'M', n: 3, roots: ['a', 'b'], prev: m2, rec, signer }))])
    assert.equal(kinds(s, 'A').filter((it) => it.id.startsWith('M3')).length, 0, JSON.stringify(rec))
  }
  // A root named as its own membership's party is no party (the record names commitments, so it cannot be refused
  // for it): one root of two starts no recovery by it, alone or with the root it would add.
  const self = { parties: ['b'], k: 1, w: 2 }
  const named = base(self)
  const r = recovery(named.m2, self, ['n'], ['b'])
  const s = ticks(witness('a', [...named.items, ...r.sign]), RMAX + WINDOW + 1)
  assert.equal(kinds(s, 'N').length, 0)
  assert.ok(asItWas(s, named.m2))
})

test('every root lost: the party recovers the identity, after its window under notice and then the contest window', () => {
  for (const w of [RMIN, RMAX]) {
    const { m2, items } = base(one(w))
    const r = recovery(m2, one(w), ['n'], ['g'])
    let s = witness('a', [...items, ...r.sign])
    const began = kinds(s, 'N', r.id)[0].at
    assert.deepEqual(ev(s).notice, { id: r.id, at: began }, 'under notice, and every view that holds the notice shows it')
    assert.ok(asItWas(s, m2), 'nothing else has changed')
    assert.equal(kinds(s, 'A', r.id).length, 0, 'it is not anchored')
    s = ticks(s, w - 1)
    assert.ok(asItWas(s, m2) && kinds(s, 'U').length === 0, 'one tick short of its window')
    s = ticks(s, 1)
    assert.deepEqual(kinds(s, 'U', r.id).map((it) => it.at - began), [w], 'matured exactly when the window has passed')
    const e = ev(s)
    assert.ok(e.pending && e.record.id === r.id, 'and anchored like any record')
    assert.deepEqual(e.authority, [], 'the roots it removes lose authority at anchoring; the new one has none yet (R6)')
    assert.equal(e.notice, null)
    s = ticks(s, WINDOW + 1)
    assert.deepEqual([ev(s).pending, ev(s).authority], [false, ['n']], 'settled: the new root has authority')
    assert.equal(forkedView('a', s), null)
  }
})

test('any one root cancels a recovery under notice, and the identity is as it was; the same record is never noticed again', () => {
  for (const root of ['a', 'b']) {
    const { m2, items } = base(one())
    const r = recovery(m2, one(), ['t'], ['g'])
    let s = witness('a', [...items, ...r.sign])
    s = witness('a', [...s, { kind: 'X', record: r.id, signer: root }])
    assert.equal(kinds(s, 'K', r.id).length, 1)
    assert.ok(asItWas(s, m2))
    assert.equal(ev(s).notice, null)
    s = ticks(s, 10)
    assert.ok(asItWas(s, m2), 'however long after')
    assert.deepEqual([kinds(s, 'U').length, kinds(s, 'A', r.id).length, kinds(s, 'N', r.id).length], [0, 0, 1])
    assert.equal(forkedView('a', s), null)
  }
  // A cancel signed by anyone who is not a root of that membership is nothing: the party itself, a stranger.
  const { m2, items } = base(one())
  const r = recovery(m2, one(), ['t'], ['g'])
  let s = witness('a', [...items, ...r.sign, { kind: 'X', record: r.id, signer: 'g' }, { kind: 'X', record: r.id, signer: 't' }])
  assert.equal(kinds(s, 'K').length, 0)
  s = ticks(s, 2)
  assert.equal(kinds(s, 'U', r.id).length, 1)
})

// The limits, as properties. A party that turns rogue, against an owner who holds one root.
test('a rogue party: it can never end the identity or gain authority before a full window passes unanswered; an owner who answers loses nothing', () => {
  const { m2, items } = base(one())
  const thief = new Set(['g', 't'])
  const states = reach('a', items, thief, ['a', 'b', 't'], 4, 4, true)
  assert.ok(states.length > 50, `the exploration is not empty: ${states.length}`)
  let noticed = 0
  let matured = 0
  for (const s of states) {
    const e = ev(s)
    assert.equal(e.dead, false, 'a party cannot end the identity: a contest needs a majority of the roots')
    for (const u of kinds(s, 'U')) { matured++; assert.ok(u.at - kinds(s, 'N', u.id)[0].at >= 2, 'nothing matures inside its window') }
    if (kinds(s, 'U').length === 0) assert.ok(asItWas(s, m2), 'and until something matures the identity is as it was')
    if (e.notice) {
      noticed++
      const answered = witness('a', [...s, { kind: 'X', record: e.notice.id, signer: 'a' }])
      assert.ok(asItWas(answered, m2) && ev(answered).notice === null, 'one root\'s cancel puts it back')
    }
  }
  assert.ok(noticed > 0 && matured > 0, 'states under notice, and matured, are reached')
  // The stated limit: an owner who does nothing for the whole window, and then the contest window, has lost it.
  let s = witness('a', [...items, ...recovery(m2, one(), ['t'], ['g']).sign])
  s = ticks(s, 2 + WINDOW + 1)
  assert.deepEqual(ev(s).authority, ['t'], 'unanswered, the rogue party has the identity')
})

test('once matured a recovery is past cancelling: the roots it removes have no authority, and only a contest, which ends the identity, stops it', () => {
  const { m2, items } = base(one())
  const r = recovery(m2, one(), ['t'], ['g'])
  let s = ticks(witness('a', [...items, ...r.sign]), 2)
  s = witness('a', [...s, { kind: 'X', record: r.id, signer: 'a' }, { kind: 'X', record: r.id, signer: 'b' }])
  assert.equal(kinds(s, 'K').length, 0, 'a cancel after maturity is not honoured')
  assert.ok(ev(s).pending && ev(s).authority.length === 0)
  const contested = witness('a', [...s, { kind: 'C', record: r.id, signer: 'a' }, { kind: 'C', record: r.id, signer: 'b' }])
  assert.equal(kinds(contested, 'A', contestId(r.id)).length, 1)
  assert.equal(ev(ticks(contested, WINDOW + 1)).dead, true, 'the contest ends the identity (R5)')
  assert.deepEqual(ev(ticks(s, WINDOW + 1)).authority, ['t'], 'uncontested, it settles')
})

test('a thief who can use one root blocks every recovery, and gains nothing by it', () => {
  // The owner has lost both roots; a thief can use b, which is no majority of two.
  const { m2, items } = base(one())
  let s = items
  let last = -Infinity
  for (const to of [['n'], ['o'], ['p']]) {
    const r = recovery(m2, one(), to, ['g'])
    s = witness('a', [...s, ...r.sign])
    while (kinds(s, 'N', r.id).length === 0) s = tick('a', s) // a recovery waits out the cooling-off after a cancel
    assert.ok(kinds(s, 'N', r.id)[0].at >= last + COOL)
    s = witness('a', [...s, { kind: 'X', record: r.id, signer: 'b' }])
    last = kinds(s, 'K', r.id)[0].at
    assert.ok(asItWas(s, m2), 'blocked')
  }
  // What the thief can do with that root alone: no change of membership, no end of the identity.
  for (const q of reach('a', items, new Set(['b', 't']), ['a', 'b', 't'], 4, 3, true)) {
    assert.ok(asItWas(q, m2) || ev(q).frozen, 'a freeze is all one root can do (R2)')
  }
})

test('a threshold: a recovery is put under notice only once k of the designated parties have signed the same record', () => {
  const { m2, items } = base(two)
  const r = recovery(m2, two, ['n'], ['g'])
  let s = ticks(witness('a', [...items, ...r.sign]), 5)
  assert.equal(kinds(s, 'N').length, 0, 'one of two is not enough, however long it waits')
  // Two parties on two different records are not two on one.
  const other = recovery(m2, two, ['o'], ['h'])
  s = ticks(witness('a', [...s, ...other.sign]), 5)
  assert.equal(kinds(s, 'N').length, 0)
  s = witness('a', [...s, { kind: 'M', n: 3, roots: ['n'], prev: m2, rec: two, signer: 'h' }])
  assert.deepEqual(kinds(s, 'N').map((it) => it.id), [r.id])
  // A party not designated by that membership counts for nothing.
  const { m2: m, items: i } = base(one())
  const stranger = witness('a', [...i, ...recovery(m, one(), ['n'], ['h']).sign])
  assert.equal(kinds(ticks(stranger, 5), 'N').length, 0)
})

test('a recovery party has no vote: its signature adds nothing to an ordinary change', () => {
  const { m2, items } = base(two)
  const id = membershipId(3, ['a', 't'], m2, two)
  const sign = ['a', 't', 'g', 'h'].map((signer) => ({ kind: 'M', n: 3, roots: ['a', 't'], prev: m2, rec: two, signer }))
  let s = witness('a', [...items, ...sign])
  assert.equal(kinds(s, 'A', id).length, 0, 'one root of two, with both parties, is not a majority of the roots')
  // It is a recovery, though (both parties signed, and the root it adds): under notice, where b can cancel it.
  assert.deepEqual(kinds(s, 'N').map((it) => it.id), [id])
  s = witness('a', [...s, { kind: 'X', record: id, signer: 'b' }])
  assert.ok(asItWas(s, m2))
})

test('one recovery under notice at a time, and after a cancel none for the cooling-off: notices are bounded by time', () => {
  const { m2, items } = base(one())
  const first = recovery(m2, one(), ['n'], ['g'])
  const second = recovery(m2, one(), ['o'], ['g'])
  let s = witness('a', [...items, ...first.sign, ...second.sign])
  assert.equal(kinds(s, 'N').length, 1, 'the second waits while the first is under notice')
  s = witness('a', [...s, { kind: 'X', record: kinds(s, 'N')[0].id, signer: 'a' }])
  const cancelledAt = kinds(s, 'K')[0].at
  assert.equal(kinds(s, 'N').length, 1, 'and is not noticed at once when the first is cancelled')
  s = ticks(s, COOL - 1)
  assert.equal(kinds(s, 'N').length, 1)
  s = ticks(s, 1)
  assert.deepEqual(kinds(s, 'N').map((it) => it.at).sort((x, y) => x - y)[1], cancelledAt + COOL, 'noticed exactly when the cooling-off ends')
  // Over every state a rogue party and a cancelling owner reach together, notices never outrun the clock.
  let most = 0
  for (const q of reach('a', items, new Set(['g', 'a']), ['a', 'b'], 3, 6, true)) {
    const time = q.filter((it) => it.kind === 'T').length
    most = Math.max(most, kinds(q, 'N').length)
    assert.ok(kinds(q, 'N').length <= 1 + Math.floor(time / COOL), `${kinds(q, 'N').length} notices in ${time} ticks`)
  }
  assert.ok(most >= 2, 'states with a second notice are reached')
})

test('an ordinary change by the owner voids a recovery under notice: it never matures', () => {
  const { m2, items } = base(one())
  const r = recovery(m2, one(), ['t'], ['g'])
  let s = witness('a', [...items, ...r.sign])
  const next = membershipId(3, ['a', 'b', 'c'], m2, one())
  s = witness('a', [...s, ...['a', 'b', 'c'].map((signer) => ({ kind: 'M', n: 3, roots: ['a', 'b', 'c'], prev: m2, rec: one(), signer }))])
  assert.equal(kinds(s, 'A', next).length, 1, 'anchored at once, as ever')
  s = ticks(s, 8)
  assert.deepEqual([ev(s).record.id, ev(s).authority.join(), kinds(s, 'U').length, ev(s).notice], [next, 'a,b,c', 0, null])
  assert.equal(forkedView('a', s), null)
})

test('no view of the records is forked, with a recovery under notice, cancelled, matured or settled', () => {
  const { m2, items } = base(one())
  const r = recovery(m2, one(), ['t'], ['g'])
  const under = witness('a', [...items, ...r.sign])
  const cancelled = witness('a', [...under, { kind: 'X', record: r.id, signer: 'a' }])
  const matured = ticks(under, 2)
  const settled = ticks(matured, WINDOW + 1)
  for (const [name, s] of [['under notice', under], ['cancelled', cancelled], ['matured', matured], ['settled', settled]]) {
    assert.equal(forkedView('a', s), null, name)
  }
  // A view without the witness's word that it matured does not take the recovery as a membership at all.
  const blind = settled.filter((it) => it.kind !== 'U')
  assert.equal(ev(blind).record.id, m2, 'behind, not on another branch')
})

// Negative controls: each rule turned off, and the property it is for fails.
test('negative controls: without each rule, what it is for no longer holds', () => {
  const { m2, items } = base(one())
  const r = recovery(m2, one(), ['t'], ['g'])
  // cancel: an owner who answers loses the identity all the same.
  withRules({ cancel: false }, () => {
    const s = ticks(witness('a', [...witness('a', [...items, ...r.sign]), { kind: 'X', record: r.id, signer: 'a' }]), 2 + WINDOW + 1)
    assert.deepEqual(ev(s).authority, ['t'])
  })
  // mature: a recovery is anchored the moment it is noticed, with no window to answer in.
  withRules({ mature: false }, () => {
    const s = witness('a', [...items, ...r.sign])
    assert.deepEqual(kinds(s, 'U', r.id).map((it) => it.at - kinds(s, 'N', r.id)[0].at), [0])
    assert.ok(ev(s).pending)
  })
  // threshold: one of two designated parties starts a recovery alone.
  withRules({ threshold: false }, () => {
    const b2 = base(two)
    const s = witness('a', [...b2.items, ...recovery(b2.m2, two, ['t'], ['g']).sign])
    assert.equal(kinds(s, 'N').length, 1)
  })
  // noVote: parties outvote the roots in an ordinary change, with no window at all.
  withRules({ noVote: false }, () => {
    const b2 = base(two)
    const id = membershipId(3, ['a', 't'], b2.m2, two)
    const s = witness('a', [...b2.items, ...['a', 't', 'g', 'h'].map((signer) => ({ kind: 'M', n: 3, roots: ['a', 't'], prev: b2.m2, rec: two, signer }))])
    assert.equal(kinds(s, 'A', id).length, 1)
  })
  // cool: a cancelled party is given notice again at once, as often as it likes.
  withRules({ cool: false }, () => {
    let s = witness('a', [...items, ...r.sign, ...recovery(m2, one(), ['o'], ['g']).sign])
    s = witness('a', [...s, { kind: 'X', record: kinds(s, 'N')[0].id, signer: 'a' }])
    assert.equal(kinds(s, 'N').length, 2)
    assert.equal(kinds(s, 'N')[1].at, kinds(s, 'K')[0].at)
  })
  // And with the rules as specified, each of those is as the tests above say.
  assert.equal(kinds(witness('a', [...witness('a', [...items, ...r.sign]), { kind: 'X', record: r.id, signer: 'a' }]), 'K').length, 1)
})
