// A signature that completes a strict majority is kept, as multi-signature systems keep partial signatures until
// their threshold (KERI's escrow of partially signed events; Safe's approvals per transaction). With one proposal per
// root and prev, a thief holding a copy of one root could otherwise remove that root's signature from the owner's
// change, or use up the root's replacements, and so never be removed from a two-root identity.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { envelope } from '../impl.mjs'
import { w, IDENTITY, BASE, WINDOW, start, mBody, mId, signed, rootId, rootText, admitAll } from './fixtures.mjs'

const refused = (r) => (r.ok ? 'accepted' : r.reason)
const junk = (i) => (i + 1).toString(16).padStart(64, '0')
const anchored = (h, at) => w.advance(h, at).signed.filter((x) => x.type === 'anchor').map((x) => envelope.open(x.text, 'anchor').body.record)

// {a, b} settled at epoch 2.
function settledAB () {
  const M = mBody(2, ['a', 'b'], IDENTITY)
  const h = admitAll(start(), [['membership', signed('membership', M, 'a')], ['root', rootText('b')], ['membership', signed('membership', M, 'b')]])
  return { M, held: w.advance(w.advance(h, BASE).held, BASE + WINDOW).held }
}
const thiefs = (M, i) => signed('membership', { ...mBody(3, ['b'], mId(M)), roots: [rootId('b'), junk(i)].sort() }, 'b')

test('a signature that completes a majority is not refused by the quota: the owner removes a thief who used it up', () => {
  const { M, held } = settledAB()
  let h = held
  for (let i = 0; i < 20; i++) { const r = w.admit(h, 'membership', thiefs(M, i)); if (r.ok) h = r.held }
  assert.equal(refused(w.admit(h, 'membership', thiefs(M, 99))), 'quota', "the thief has used up b's replacements")
  // The owner's change to {a}: a signs, then b's signature makes it a majority (2 of 2), and is admitted.
  const R = mBody(3, ['a'], mId(M))
  h = admitAll(h, [['membership', signed('membership', R, 'a')]])
  const b = w.admit(h, 'membership', signed('membership', R, 'b'))
  assert.equal(refused(b), 'accepted')
  assert.deepEqual(anchored(b.held, BASE + 2 * WINDOW), [mId(R)])
  // Without a's signature, b's alone is no majority, and the quota still holds.
  assert.equal(refused(w.admit(h, 'membership', signed('membership', mBody(3, ['b'], mId(M)), 'b'))), 'quota')
})

test('a root cannot move its signature off a record a majority has signed', () => {
  const { M, held } = settledAB()
  const X = mBody(3, ['a', 'b', 'o'], mId(M))
  let h = admitAll(held, [['membership', signed('membership', X, 'a')], ['membership', signed('membership', X, 'b')]])
  // A thief with a copy of b proposes another change: refused, so X keeps its majority and o may sign it.
  assert.equal(refused(w.admit(h, 'membership', thiefs(M, 0))), 'quorate')
  h = admitAll(h, [['root', rootText('o')], ['membership', signed('membership', X, 'o')]])
  assert.deepEqual(anchored(h, BASE + 2 * WINDOW), [mId(X)])
  // a is held to X as well.
  assert.equal(refused(w.admit(h, 'membership', signed('membership', mBody(3, ['a'], mId(M)), 'a'))), 'quorate')
})

test('before a majority, an owner may still change its mind', () => {
  const { M, held } = settledAB()
  const X = mBody(3, ['a', 'b', 'o'], mId(M))
  const Y = mBody(3, ['a'], mId(M))
  const h = admitAll(held, [['membership', signed('membership', X, 'a')], ['membership', signed('membership', Y, 'a')]])
  assert.deepEqual(h.memberships.slice(held.memberships.length).map((t) => envelope.open(t, 'membership').id), [mId(Y)])
})
