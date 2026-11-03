// R1, R3, R5 on hand-built record sets: exact boundaries of the model's rules.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import fc from 'fast-check'
import { evaluate, history, membershipId, genesisOf, WINDOW } from '../../model/recovery.mjs'

const g = genesisOf('a').id
const e2 = membershipId(2, ['a', 'b', 'c'], g)
const base = history('a', [['a', 'b', 'c']])
const sign = (n, roots, prev, signers) => signers.map((signer) => ({ kind: 'M', n, roots, prev, signer }))

test('R1: the next epoch needs a strict majority of the previous roots, and every added root', () => {
  const half = [...base, ...sign(3, ['a', 'b'], e2, ['a'])]
  assert.equal(evaluate('a', half).epoch, 2, 'one of three is not a majority')
  const majority = [...base, ...sign(3, ['a', 'b'], e2, ['a', 'b'])]
  assert.equal(evaluate('a', majority).epoch, 3)
  const addedUnsigned = [...base, ...sign(3, ['a', 'b', 'd'], e2, ['a', 'b'])]
  assert.equal(evaluate('a', addedUnsigned).epoch, 2, 'd did not sign')
  const evenSplit = [...history('a', [['a', 'b']]), ...sign(3, ['a'], membershipId(2, ['a', 'b'], g), ['a'])]
  assert.equal(evaluate('a', evenSplit).epoch, 2, 'one of two is exactly half')
})

test('R3 without anchors: two valid records for one epoch end the identity', () => {
  const fork = [...base, ...sign(2, ['a'], g, ['a'])]
  assert.deepEqual(evaluate('a', fork), { dead: true, at: 1 })
})

test('R3 window: rivals less than WINDOW apart end the identity; WINDOW apart, the earlier wins', () => {
  const rival = membershipId(2, ['a'], g)
  const items = [...base, ...sign(2, ['a'], g, ['a'])]
  const anchors = (t1, t2) => [{ kind: 'W', id: e2, at: t1 }, { kind: 'W', id: rival, at: t2 }]
  assert.deepEqual(evaluate('a', [...items, ...anchors(5, 5 + WINDOW - 1)], 'window'), { dead: true, at: 1 })
  assert.deepEqual(evaluate('a', [...items, ...anchors(5 + WINDOW - 1, 5)], 'window'), { dead: true, at: 1 })
  assert.equal(evaluate('a', [...items, ...anchors(5, 5 + WINDOW)], 'window').id, e2)
  assert.equal(evaluate('a', [...items, ...anchors(5 + WINDOW, 5)], 'window').id, rival)
})

test('R3 window: an unanchored record does not count', () => {
  assert.equal(evaluate('a', base, 'window').epoch, 1)
  assert.equal(evaluate('a', [...base, { kind: 'W', id: e2, at: 0 }], 'window').epoch, 2)
})

test('R5: the state does not depend on the order of the items', () => {
  const rival = membershipId(2, ['a'], g)
  const items = [...base, ...sign(2, ['a'], g, ['a']), { kind: 'W', id: e2, at: 0 }, { kind: 'W', id: rival, at: 3 },
    ...sign(3, ['b', 'c'], e2, ['b', 'c']), { kind: 'W', id: membershipId(3, ['b', 'c'], e2), at: 4 },
    { kind: 'F', n: 2, signer: 'a' }, { kind: 'F', n: 3, signer: 'a' }]
  for (const rule of ['none', 'first', 'window']) {
    const expected = evaluate('a', items, rule)
    fc.assert(fc.property(fc.shuffledSubarray(items, { minLength: items.length }), (shuffled) => {
      assert.deepEqual(evaluate('a', shuffled, rule), expected)
    }), { seed: 20261103, numRuns: 200 })
  }
})
