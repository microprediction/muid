// R3–R5 and R9 on the witness's side: what it signs as time passes — anchors, settlements and heads — each kept only
// if verifiers, running the core's own membershipState, would follow it.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { ed25519 } from '@noble/curves/ed25519.js'
import { envelope, membership } from '../impl.mjs'
import { witness } from './impl.mjs'
import { w, CONFIG, IDENTITY, BASE, WINDOW, WITNESS, start, withM2, M2, mBody, mId, signed, rootText, admitAll, state, open } from './fixtures.mjs'

const bodies = (r) => r.signed.map((s) => ({ type: s.type, ...open(s.text, s.type).body }))

test('an honest change: anchored when valid, settled once the contest window has passed', () => {
  const a = w.advance(withM2(), BASE)
  assert.deepEqual(bodies(a), [{ type: 'anchor', identity: IDENTITY, record: mId(M2), at: BASE }])
  assert.deepEqual(a.held.anchors, [a.signed[0].text])
  assert.equal(state(a.held).pending, true)
  assert.deepEqual(w.advance(a.held, BASE + WINDOW - 1).signed, [], 'inside the window: nothing')
  const s = w.advance(a.held, BASE + WINDOW)
  assert.deepEqual(bodies(s), [{ type: 'settlement', identity: IDENTITY, prev: IDENTITY, outcome: mId(M2), at: BASE + WINDOW }])
  const st = state(s.held)
  assert.equal(st.pending, false)
  assert.equal(st.epoch, 2)
  assert.deepEqual(w.advance(s.held, BASE + 10 * WINDOW).signed, [], 'nothing more to do')
})

test('the texts it signs verify under its key, as the records it would be shown', () => {
  const a = w.advance(withM2(), BASE)
  const r = envelope.open(a.signed[0].text, 'anchor')
  assert.deepEqual({ ...r.sig }, { signature: r.sig.signature, witness: WITNESS })
  assert.ok(ed25519.verify(Buffer.from(r.sig.signature, 'hex'), envelope.signedBytes(envelope.seal('anchor', r.body).payload), Buffer.from(WITNESS, 'hex')))
})

test('an incomplete change is not anchored: an added root has not signed', () => {
  const h = admitAll(start(), [['membership', signed('membership', M2, 'a')], ['root', rootText('b')]])
  assert.deepEqual(w.advance(h, BASE).signed, [])
})

test('a successor held while its predecessor was pending is anchored at settlement, in the same step', () => {
  const pending = w.advance(withM2(), BASE).held
  const M3 = mBody(3, ['b'], mId(M2))
  const h = admitAll(pending, [['membership', signed('membership', M3, 'a')], ['membership', signed('membership', M3, 'b')]])
  const r = w.advance(h, BASE + WINDOW)
  assert.deepEqual(bodies(r).map((b) => b.type + ' ' + (b.record ?? b.outcome)), ['settlement ' + mId(M2), 'anchor ' + mId(M3)])
})

test('of several valid successors, exactly one is anchored: the lowest record id', () => {
  const pending = w.advance(withM2(), BASE).held
  const candidates = [mBody(3, ['a'], mId(M2)), mBody(3, ['b'], mId(M2)), mBody(3, ['a', 'b'], mId(M2))]
  let h = pending
  // Held in descending id order, so the first held is not the lowest.
  candidates.sort((x, y) => (mId(x) < mId(y) ? 1 : -1))
  for (const c of candidates) h = admitAll(h, [['membership', signed('membership', c, 'a')], ['membership', signed('membership', c, 'b')]])
  const r = w.advance(h, BASE + WINDOW)
  const anchored = bodies(r).filter((b) => b.type === 'anchor').map((b) => b.record)
  assert.deepEqual(anchored, [candidates.map(mId).sort()[0]])
  assert.equal(state(r.held).pending, true)
})

test('R5: a contest inside the window is anchored, and the epoch then settles as contested; the identity ends', () => {
  const pending = w.advance(withM2(), BASE).held
  const contest = signed('contest', { identity: IDENTITY, record: mId(M2) }, 'a')
  const h = admitAll(pending, [['contest', contest]])
  const c = w.advance(h, BASE + WINDOW - 1)
  assert.deepEqual(bodies(c), [{ type: 'anchor', identity: IDENTITY, record: envelope.open(contest, 'contest').id, at: BASE + WINDOW - 1 }])
  assert.equal(state(c.held).dead, true, 'verifiers see the identity end at once')
  assert.deepEqual(w.advance(c.held, BASE + WINDOW - 1).signed, [])
  const s = w.advance(c.held, BASE + WINDOW)
  assert.deepEqual(bodies(s), [{ type: 'settlement', identity: IDENTITY, prev: IDENTITY, outcome: 'contested', at: BASE + WINDOW }])
  assert.deepEqual(w.advance(s.held, BASE + 5 * WINDOW).signed, [])
})

test('a contest first seen after the window has passed is not anchored: the record settles', () => {
  const pending = w.advance(withM2(), BASE).held
  const h = admitAll(pending, [['contest', signed('contest', { identity: IDENTITY, record: mId(M2) }, 'a')]])
  assert.deepEqual(bodies(w.advance(h, BASE + WINDOW)).map((b) => b.type + ' ' + b.outcome), ['settlement ' + mId(M2)])
})

test('a contest signed by a minority of the settled roots is not anchored', () => {
  // Settle {a, b}, then a change to {a, b, c} contested by b alone: one of two is not a strict majority.
  const settled = w.advance(w.advance(withM2(), BASE).held, BASE + WINDOW).held
  const M3 = mBody(3, ['a', 'b', 'c'], mId(M2))
  let h = admitAll(settled, [['membership', signed('membership', M3, 'a')], ['membership', signed('membership', M3, 'b')],
    ['root', rootText('c')], ['membership', signed('membership', M3, 'c')]])
  h = w.advance(h, BASE + 2 * WINDOW).held
  h = admitAll(h, [['contest', signed('contest', { identity: IDENTITY, record: mId(M3) }, 'b')]])
  assert.deepEqual(w.advance(h, BASE + 2 * WINDOW + 1).signed, [])
  const both = admitAll(h, [['contest', signed('contest', { identity: IDENTITY, record: mId(M3) }, 'a')]])
  assert.deepEqual(bodies(w.advance(both, BASE + 2 * WINDOW + 1)).map((b) => b.type), ['anchor'])
})

test('nothing is signed for a dead identity, or a holding without the first root', () => {
  assert.deepEqual(w.advance(w.empty(IDENTITY), BASE).signed, [])
})

test('R9: a head is the core\'s headOf of what the witness holds, signed; none where headOf gives none', () => {
  const h = w.advance(withM2(), BASE).held
  const text = w.head(h, BASE + 5)
  const r = envelope.open(text, 'head')
  assert.equal(r.payload, envelope.seal('head', membership.headOf(state(h), BASE + 5, [])).payload)
  assert.ok(ed25519.verify(Buffer.from(r.sig.signature, 'hex'), envelope.signedBytes(envelope.seal('head', r.body).payload), Buffer.from(WITNESS, 'hex')))
  assert.equal(r.sig.witness, WITNESS)
  const frozen = admitAll(start(), [['freeze', signed('freeze', { identity: IDENTITY, membership: IDENTITY }, 'a')]])
  assert.equal(w.head(frozen, BASE), undefined)
  assert.equal(w.head(w.empty(IDENTITY), BASE), undefined)
})

test('configuration is checked at construction; a time that is not a non-negative integer is a programming error', () => {
  for (const bad of [{ key: 'x' }, { sign: undefined }, { contestWindow: 0 }, { contestWindow: 1.5 }, { witnessKeys: [] }, { witnessKeys: 'x' },
    { rpId: 1 }, { origin: undefined }, { skew: -1 }, { skew: undefined }, { maxLifetime: 1.5 }, { maxLifetime: undefined }]) {
    assert.throws(() => witness({ ...CONFIG, ...bad }), { name: 'TypeError', message: /^configuration must hold/ }, JSON.stringify(bad))
  }
  assert.throws(() => witness(null), TypeError)
  assert.throws(() => witness('x'), { name: 'TypeError', message: /^configuration must hold/ })
  assert.doesNotThrow(() => witness({ ...CONFIG, contestWindow: 1 }))
  for (const t of [-1, 1.5, '1']) {
    assert.throws(() => w.advance(start(), t), { name: 'TypeError', message: /now must be a non-negative integer/ })
    assert.throws(() => w.head(start(), t), { name: 'TypeError', message: /now must be a non-negative integer/ })
  }
  assert.deepEqual(w.advance(start(), 0).signed, [])
  assert.equal(typeof w.head(start(), 0), 'string')
})

test('a signing function that signs with another key is caught: nothing it signs is kept', () => {
  const other = Uint8Array.from({ length: 32 }, (_, i) => 7 + i)
  const liar = witness({ ...CONFIG, sign: (bytes) => Buffer.from(ed25519.sign(bytes, other)).toString('hex') })
  assert.throws(() => liar.advance(withM2(), BASE), /signature/)
  assert.throws(() => liar.head(start(), BASE), /signature/)
})
