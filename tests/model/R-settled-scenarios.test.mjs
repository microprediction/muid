// The settled design (SPEC §5 R1–R7) explored against a thief, including every partial view a network attacker can
// choose. Bounds: one thief move, one owner answer inside the window, then further thief play now or after it.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { analyse, history, evaluate, witness, tick, forkedView, contestId } from '../../model/settled.mjs'
import { membershipId, genesisOf } from '../../model/recovery.mjs'

const run = (epochs, roots, stolen) => analyse({ genesis: 'a', history: history('a', epochs),
  owner: new Set([...roots, 'o']), thief: new Set([...stolen, 't']), universe: [...roots, 'o', 't'],
  maxEpoch: epochs.length + 3, thiefDepth: 1 })

const SAFE = [
  ['two roots, the later stolen', [['a', 'b']], ['a', 'b'], ['b']],
  ['two roots, the first stolen', [['a', 'b']], ['a', 'b'], ['a']],
  ['three roots, a later one stolen', [['a', 'b', 'c']], ['a', 'b', 'c'], ['c']],
  ['three roots, the first stolen', [['a', 'b', 'c']], ['a', 'b', 'c'], ['a']],
  ['three roots, the first already retired and stolen', [['a', 'b', 'c'], ['b', 'c', 'd']], ['a', 'b', 'c', 'd'], ['a']],
]
for (const [name, epochs, roots, stolen] of SAFE) {
  test(`${name}: no takeover, no kill, the owner recovers, no forked view`, () => {
    const r = run(epochs, roots, stolen)
    assert.equal(r.takeover, null)
    assert.equal(r.kill, null)
    assert.equal(r.pendingThiefAuthority, null)
    assert.equal(r.cannotStop, null)
    assert.equal(r.forked, null)
    if (roots.length - stolen.length > roots.length / 2) assert.equal(r.unrecoverable, null)
  })
}

const SHARED = [
  ['one root, stolen', [], ['a'], ['a']],
  ['three roots, two stolen', [['a', 'b', 'c']], ['a', 'b', 'c'], ['b', 'c']],
]
for (const [name, epochs, roots, stolen] of SHARED) {
  test(`${name}: takeover settles only if the owner does not contest within the window; no forked view`, () => {
    const r = run(epochs, roots, stolen)
    assert.ok(r.takeover)
    assert.equal(r.pendingThiefAuthority, null, 'the thief\'s own roots have no authority while pending')
    assert.equal(r.cannotStop, null)
    assert.ok(r.lateOwnerCannotStop)
    assert.equal(r.forked, null)
  })
}

test('the reviewer\'s late rival: never anchored, so a view holding it has no effect', () => {
  const g = genesisOf('a').id
  let s = history('a', [['a', 'b', 'c']])
  s = witness('a', [...s, { kind: 'M', n: 2, roots: ['t'], prev: g, signer: 'a' }, { kind: 'M', n: 2, roots: ['t'], prev: g, signer: 't' }])
  assert.equal(s.some((it) => it.kind === 'A' && it.id === membershipId(2, ['t'], g)), false)
  assert.equal(forkedView('a', s), null)
})

test('negative control: a witness that anchors a late rival is caught as a forked view', () => {
  const g = genesisOf('a').id
  const rival = membershipId(2, ['t'], g)
  const s = [...history('a', [['a', 'b', 'c']]), { kind: 'M', n: 2, roots: ['t'], prev: g, signer: 'a' },
    { kind: 'M', n: 2, roots: ['t'], prev: g, signer: 't' }, { kind: 'A', id: rival, at: 9 }]
  const view = forkedView('a', s)
  assert.ok(view)
  assert.equal(evaluate('a', view).record.id, rival)
})

test('an ordinary rival inside the window is not anchored and cannot end the identity; a contest can', () => {
  const g = genesisOf('a').id
  let s = witness('a', [{ kind: 'M', n: 2, roots: ['a', 'b'], prev: g, signer: 'a' }, { kind: 'M', n: 2, roots: ['a', 'b'], prev: g, signer: 'b' }])
  s = witness('a', [...s, { kind: 'M', n: 2, roots: ['a', 'c'], prev: g, signer: 'a' }, { kind: 'M', n: 2, roots: ['a', 'c'], prev: g, signer: 'c' }])
  assert.equal(evaluate('a', s).dead, false, 'a second ordinary record does not end the identity')
  assert.equal(evaluate('a', tick('a', s)).record.id, membershipId(2, ['a', 'b'], g), 'the first one settles')
  const first = membershipId(2, ['a', 'b'], g)
  const contested = witness('a', [...s, { kind: 'C', record: first, signer: 'a' }])
  assert.ok(contested.some((it) => it.kind === 'A' && it.id === contestId(first)))
  assert.equal(evaluate('a', contested).dead, true)
  assert.deepEqual(tick('a', contested).filter((it) => it.kind === 'S').map((it) => it.outcome), ['contested'])
})

test('a contest after settlement is not anchored', () => {
  const g = genesisOf('a').id
  const settled = membershipId(2, ['a', 'b'], g)
  const s = witness('a', [...history('a', [['a', 'b']]), { kind: 'C', record: settled, signer: 'a' }])
  assert.equal(s.some((it) => it.kind === 'A' && it.id === contestId(settled)), false)
  assert.equal(evaluate('a', s).dead, false)
})

test('a contest names its record: one signed against another record is never anchored for this one', () => {
  const g = genesisOf('a').id
  let s = witness('a', [{ kind: 'C', record: membershipId(2, ['a', 'c'], g), signer: 'a' }])
  s = witness('a', [...s, ...['a', 'b'].map((signer) => ({ kind: 'M', n: 2, roots: ['a', 'b'], prev: g, signer }))])
  assert.equal(evaluate('a', s).pending, true)
  assert.equal(evaluate('a', tick('a', s)).record.id, membershipId(2, ['a', 'b'], g), 'the honest record settles')
})

test('a freeze on the settled membership still applies while its successor is pending', () => {
  const e2 = membershipId(2, ['a', 'b', 'c'], genesisOf('a').id)
  const s = witness('a', [...history('a', [['a', 'b', 'c']]), { kind: 'F', target: e2, signer: 'c' },
    ...['a', 'b', 'd'].map((signer) => ({ kind: 'M', n: 3, roots: ['a', 'b', 'd'], prev: e2, signer }))])
  assert.equal(evaluate('a', s).frozen, true)
  assert.equal(evaluate('a', tick('a', s)).frozen, false, 'settlement moves past it')
})

test('while pending, authority is only the roots shared with the settled epoch', () => {
  const s = witness('a', [...history('a', [['a', 'b', 'c']]),
    ...['a', 'b', 'd'].map((signer) => ({ kind: 'M', n: 3, roots: ['a', 'b', 'd'], prev: membershipId(2, ['a', 'b', 'c'], genesisOf('a').id), signer }))])
  const e = evaluate('a', s)
  assert.equal(e.pending, true)
  assert.deepEqual(e.authority, ['a', 'b'])
  assert.deepEqual(evaluate('a', tick('a', s)).authority, ['a', 'b', 'd'])
})
