// A root removed from the membership has none of a root's powers, and may still be added back: the change that adds
// it is authorised by the current roots, and its own signature on that change is the added root's proof that it
// holds its key (R1), no act of authority. From review #130.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { w, IDENTITY, BASE, WINDOW, withM2, M2, mBody, mId, signed, rootId, rootText, admitAll, state } from './fixtures.mjs'

const reason = (held, type, text) => { const r = w.admit(held, type, text); return r.ok ? 'ok' : r.reason }
const settle = (held, from) => w.advance(w.advance(held, from).held, from + WINDOW).held

test('a removed root: no contest, no change of its own, no early signature; added back by the current root, it signs as any added root does', () => {
  // {a, b} settles; then {a}, signed by both, settles: b is removed.
  const two = settle(withM2(), BASE)
  assert.deepEqual([state(two).epoch, state(two).roots], [2, [rootId('a'), rootId('b')].sort()])
  const M3 = mBody(3, ['a'], mId(M2))
  const one = settle(admitAll(two, [['membership', signed('membership', M3, 'a')], ['membership', signed('membership', M3, 'b')]]), BASE + WINDOW + 1)
  assert.deepEqual([state(one).epoch, state(one).roots, state(one).authority], [3, [rootId('a')], [rootId('a')]])

  // b adds itself back: its signature alone authorises nothing, and is not taken before a current root's.
  const M4 = mBody(4, ['a', 'b'], mId(M3))
  assert.equal(reason(one, 'membership', signed('membership', M4, 'b')), 'signer')
  assert.equal(state(one).pending, false)
  // Nor may it change the membership otherwise, or contest what the current root proposes.
  const M4c = mBody(4, ['a', 'c'], mId(M3))
  assert.equal(reason(one, 'membership', signed('membership', M4c, 'b')), 'signer')
  const proposed = admitAll(one, [['membership', signed('membership', M4c, 'a')]])
  assert.equal(reason(proposed, 'membership', signed('membership', M4c, 'b')), 'signer', 'a change that does not add it is not its to sign')
  const T3 = BASE + 2 * WINDOW + 2
  const pending = w.advance(admitAll(proposed, [['root', rootText('c')], ['membership', signed('membership', M4c, 'c')]]), T3).held
  assert.equal(state(pending).pending, true)
  const contest = { identity: IDENTITY, record: mId(M4c) }
  assert.equal(reason(pending, 'contest', signed('contest', contest, 'b')), 'signer', 'the removed root contests nothing')
  assert.equal(reason(pending, 'contest', signed('contest', contest, 'a')), 'ok', 'as a current root does')

  // The current root proposes {a, b}: now b's signature is the added root's, and the change anchors and settles.
  const asked = admitAll(one, [['membership', signed('membership', M4, 'a')]])
  assert.equal(state(asked).pending, false, 'not anchored until the added root has signed')
  const both = admitAll(asked, [['membership', signed('membership', M4, 'b')]])
  const T = BASE + 2 * WINDOW + 2
  const anchored = w.advance(both, T).held
  assert.deepEqual([state(anchored).pending, state(anchored).authority], [true, [rootId('a')]], 'pending: b has no authority yet (R6)')
  const back = w.advance(anchored, T + WINDOW).held
  assert.deepEqual([state(back).epoch, state(back).roots, state(back).authority, state(back).pending], [4, [rootId('a'), rootId('b')].sort(), [rootId('a'), rootId('b')].sort(), false])
})
