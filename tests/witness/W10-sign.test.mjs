// The witness signs only what it keeps (CT: what is signed is logged). advance() decides each candidate anchor with a
// trial key that no verifier pins, so `sign` is never asked for an anchor that is then thrown away: a proposal
// without a majority, a contest that would not end the identity, or a record outside the witness key's window.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { ed25519 } from '@noble/curves/ed25519.js'
import { witness } from './impl.mjs'
import { CONFIG, IDENTITY, BASE, WINDOW, WITNESS, start, withM2, M2, mBody, mId, signed, rootText, admitAll, state } from './fixtures.mjs'

// A witness whose `sign` counts its calls.
function counting (config = CONFIG) {
  const c = { calls: 0 }
  c.w = witness({ ...config, sign: (bytes) => { c.calls++; return CONFIG.sign(bytes) } })
  return c
}

test('a change without a majority, advanced again and again: sign is never called', () => {
  const c = counting()
  // b's root record and a's signature: the added root b has not signed.
  let h = admitAll(start(), [['membership', signed('membership', M2, 'a')], ['root', rootText('b')]])
  for (let i = 0; i < 5; i++) {
    const r = c.w.advance(h, BASE + i * WINDOW)
    assert.deepEqual(r.signed, [])
    h = r.held
  }
  assert.equal(c.calls, 0)
})

test('a contest by a minority of the settled roots: sign is never called; by a majority, once, for its anchor', () => {
  const c = counting()
  const settled = c.w.advance(c.w.advance(withM2(), BASE).held, BASE + WINDOW).held
  const M3 = mBody(3, ['a', 'b', 'c'], mId(M2))
  let h = admitAll(settled, [['membership', signed('membership', M3, 'a')], ['membership', signed('membership', M3, 'b')],
    ['root', rootText('c')], ['membership', signed('membership', M3, 'c')]])
  h = c.w.advance(h, BASE + 2 * WINDOW).held
  h = admitAll(h, [['contest', signed('contest', { identity: IDENTITY, record: mId(M3) }, 'b')]])
  c.calls = 0
  assert.deepEqual(c.w.advance(h, BASE + 2 * WINDOW + 1).signed, [])
  assert.equal(c.calls, 0)
  const both = admitAll(h, [['contest', signed('contest', { identity: IDENTITY, record: mId(M3) }, 'a')]])
  const r = c.w.advance(both, BASE + 2 * WINDOW + 1)
  assert.deepEqual(r.signed.map((s) => s.type), ['anchor'])
  assert.equal(c.calls, 1)
  assert.equal(state(r.held).dead, true)
})

test('an honest change: one call for each record signed, and nothing else', () => {
  const c = counting()
  const a = c.w.advance(withM2(), BASE)
  const s = c.w.advance(a.held, BASE + WINDOW)
  assert.deepEqual([...a.signed, ...s.signed].map((x) => x.type), ['anchor', 'settlement'])
  assert.equal(c.calls, 2)
})

test('outside the witness key\'s window (another key\'s does not count) nothing is anchored and sign is not called; inside it, the same holding is', () => {
  const closed = counting({ ...CONFIG, witnessKeys: [{ key: WITNESS, nbf: 0, exp: BASE }] })
  assert.deepEqual(closed.w.advance(withM2(), BASE).signed, [])
  assert.equal(closed.calls, 0)
  const early = counting({ ...CONFIG, witnessKeys: [{ key: WITNESS, nbf: BASE + 1, exp: BASE + 10 * WINDOW }] })
  assert.deepEqual(early.w.advance(withM2(), BASE).signed, [])
  assert.equal(early.calls, 0)
  // Another pinned key in window does not lend the trial key its window: only the witness key's own windows count.
  const other = Buffer.from(ed25519.getPublicKey(Uint8Array.from({ length: 32 }, (_, i) => i + 1))).toString('hex')
  const lent = counting({ ...CONFIG, witnessKeys: [{ key: WITNESS, nbf: 0, exp: BASE }, { key: other, nbf: 0, exp: BASE + 10 * WINDOW }] })
  assert.deepEqual(lent.w.advance(withM2(), BASE).signed, [])
  assert.equal(lent.calls, 0)
  const open = counting({ ...CONFIG, witnessKeys: [{ key: WITNESS, nbf: BASE, exp: BASE + 1 }] })
  assert.deepEqual(open.w.advance(withM2(), BASE).signed.map((x) => x.type), ['anchor'])
  assert.equal(open.calls, 1)
})

test('a configuration that pins the trial key (the Ed25519 key of 32 zero bytes) is refused', () => {
  const trial = Buffer.from(ed25519.getPublicKey(new Uint8Array(32))).toString('hex')
  assert.throws(() => witness({ ...CONFIG, witnessKeys: [...CONFIG.witnessKeys, { key: trial, nbf: 0, exp: BASE }] }),
    { name: 'TypeError', message: /^configuration must hold/ })
})
