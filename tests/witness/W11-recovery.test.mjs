// R11 on the witness's side: a recovery party's signature is admitted only if it opens a commitment of the settled
// membership's designation; a recovery its parties' threshold has signed is put under notice, never anchored; any one
// root's cancel ends it; left alone for its window it matures and is anchored like any record. Every step is what
// verifiers, running the core's own membershipState, would follow, and every head says what is under notice.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { membership, envelope } from '../impl.mjs'
import { witness } from './impl.mjs'
import { w, CONFIG, IDENTITY, BASE, WINDOW, start, signed, rootText, rootId, admitAll, state, open, sign, WITNESS, forged } from './fixtures.mjs'
import { partySigned, commitmentOf, saltOf, secretOf } from '../membership/translate.mjs'
import { make } from '../assertion/helpers.mjs'

const { MIN_RECOVERY_WINDOW: MIN, MAX_RECORDS } = membership
const DAY = 86_400
const mId = (body) => envelope.seal('membership', body).id
const D = (letters = ['g'], threshold = 1, window = MIN) => ({ parties: letters.map(commitmentOf).sort(), threshold, window })
const ids = (...letters) => letters.map(rootId).sort()
const bodies = (r) => r.signed.map((s) => ({ type: s.type, ...open(s.text, s.type).body }))
const types = (r) => r.signed.map((s) => s.type)
const reason = (held, type, text, root) => { const r = w.admit(held, type, text, root); return r.ok ? 'ok' : r.reason }
const T0 = BASE + WINDOW // the designation has settled

// Epoch 2: `roots`, designating `recovery`; settled at T0. Epoch 3 bodies follow it.
function designated (recovery, roots = ['a']) {
  const body = recovery === undefined ? { identity: IDENTITY, prev: IDENTITY, epoch: 2, roots: ids(...roots) } : { identity: IDENTITY, prev: IDENTITY, epoch: 2, roots: ids(...roots), recovery }
  let held = admitAll(start(), [['membership', signed('membership', body, 'a')]])
  for (const l of roots.filter((x) => x !== 'a')) held = admitAll(held, [['root', rootText(l)], ['membership', signed('membership', body, l)]])
  held = w.advance(w.advance(held, BASE).held, T0).held
  assert.deepEqual([state(held).epoch, state(held).pending], [2, false])
  const next = (letters, recovery3) => (recovery3 === undefined ? { identity: IDENTITY, prev: mId(body), epoch: 3, roots: ids(...letters) } : { identity: IDENTITY, prev: mId(body), epoch: 3, roots: ids(...letters), recovery: recovery3 })
  return { held, id: mId(body), next }
}
// The party's signature (with its root record), then the root the recovery adds.
const asked = (held, body, parties = ['g'], added = ['n']) => admitAll2(held, [
  ...parties.map((l) => ['membership', partySigned('membership', body, l), rootText(l)]),
  ...added.flatMap((l) => [['root', rootText(l)], ['membership', signed('membership', body, l)]])])
function admitAll2 (held, items) {
  for (const [type, text, root] of items) {
    const r = w.admit(held, type, text, root)
    assert.equal(r.ok, true, `refused ${type}: ${r.reason}`)
    held = r.held
  }
  return held
}
const cancel = (record, letter = 'a') => signed('cancel', { identity: IDENTITY, record }, letter)
const headOf = (held, now) => open(w.head(held, now), 'head').body

test('a recovery signed by the party is put under notice, not anchored: nothing changes but that every head says so', () => {
  const d = designated(D())
  const R = d.next(['n'])
  const held = asked(d.held, R)
  const before = state(held)
  const r = w.advance(held, T0 + 5)
  assert.deepEqual(bodies(r), [{ type: 'notice', identity: IDENTITY, record: mId(R), at: T0 + 5 }])
  assert.deepEqual(r.held.notices, [r.signed[0].text])
  assert.deepEqual(r.held.anchors, held.anchors)
  const s = state(r.held)
  assert.deepEqual({ ...s, recovering: null }, { ...before }, 'the same membership and the same authority')
  assert.deepEqual({ ...s.recovering }, { record: mId(R), at: T0 + 5 })
  assert.deepEqual({ ...headOf(r.held, T0 + 9).recovering }, { at: T0 + 5, record: mId(R) })
  assert.equal('recovering' in headOf(held, T0 + 9), false, 'before the notice, no head says so')
  assert.deepEqual(w.advance(r.held, T0 + 6).signed, [], 'nothing more until a cancel or the window')
  const text = r.signed[0].text
  assert.deepEqual({ ...open(text, 'notice').sig }.witness, WITNESS)
})

test("a party's signature is admitted only as a party's: with its salt, its root record, for the settled membership's designation", () => {
  const d = designated(D())
  const R = d.next(['n'])
  const g = partySigned('membership', R, 'g')
  const sig = (letter, more, secret = letter) => {
    const { payload, id } = envelope.seal('membership', R)
    return envelope.wrap(payload, { root: rootId(letter), assertion: make({ covers: [id], secret: secretOf(secret) }), ...more })
  }
  assert.equal(reason(d.held, 'membership', g), 'root-missing', 'nothing names a party until it acts: its root record comes with its signature')
  assert.equal(reason(d.held, 'root', rootText('g')), 'root-unnamed', 'and is not taken alone')
  assert.equal(reason(d.held, 'membership', g, rootText('h')), 'root-record', "another key's root record")
  assert.equal(reason(d.held, 'membership', g, 'x'), 'root-record')
  assert.equal(reason(d.held, 'membership', signed('membership', R, 'g'), rootText('g')), 'signer', 'without its salt it is nobody')
  assert.equal(reason(d.held, 'membership', sig('g', { salt: saltOf('h') }), rootText('g')), 'signer', "another party's salt")
  assert.equal(reason(d.held, 'membership', partySigned('membership', R, 'h'), rootText('h')), 'signer', 'a root that was not designated')
  assert.equal(reason(d.held, 'membership', sig('a', { salt: saltOf('a') })), 'signer', 'a root of the membership is no party of it')
  assert.equal(reason(d.held, 'membership', sig('g', { salt: saltOf('g') }, 'h'), rootText('g')), 'signature', "the party's salt on another key's assertion")
  for (const salt of ['x', saltOf('g').toUpperCase(), saltOf('g') + '00', 7]) assert.equal(reason(d.held, 'membership', sig('g', { salt }), rootText('g')), 'shape', String(salt))
  assert.equal(reason(d.held, 'membership', sig('g', { salt: saltOf('g'), zz: 1 }), rootText('g')), 'shape')
  assert.equal(reason(d.held, 'contest', (() => { const b = { identity: IDENTITY, record: d.id }; const { payload, id } = envelope.seal('contest', b); return envelope.wrap(payload, { root: rootId('g'), salt: saltOf('g'), assertion: make({ covers: [id], secret: secretOf('g') }) }) })()), 'shape', 'a salt belongs to a membership record only')
  const r = w.admit(d.held, 'membership', g, rootText('g'))
  assert.equal(r.ok, true)
  assert.deepEqual(r.held.roots, [...d.held.roots, rootText('g')], "the party's root record is held with its signature")
  assert.equal(w.admit(r.held, 'membership', g).held, r.held, 'again: nothing changes')
  assert.equal(state(r.held).ok, true)
  // A root named as its own membership's party is no party, though its commitment opens.
  const own = designated(D(['a']))
  const own3 = own.next(['n'])
  const { payload: ownPayload, id: ownId } = envelope.seal('membership', own3)
  assert.equal(reason(own.held, 'membership', envelope.wrap(ownPayload, { root: rootId('a'), salt: saltOf('a'), assertion: make({ covers: [ownId], secret: secretOf('a') }) })), 'signer')
  // A membership that designates nobody has no parties, and one whose designation is out of form is no record.
  const none = designated()
  assert.equal(reason(none.held, 'membership', partySigned('membership', none.next(['n']), 'g'), rootText('g')), 'signer')
  const bad = { identity: IDENTITY, prev: d.id, epoch: 3, roots: ids('a'), recovery: { ...D(), threshold: 2 } }
  assert.equal(reason(d.held, 'membership', signed('membership', bad, 'a')), 'shape')
  assert.equal(reason(d.held, 'membership', signed('membership', { ...bad, recovery: { ...D(), window: MIN - 1 } }, 'a')), 'shape')
})

test('nothing pending is recovered: while a successor is in its contest window, a party is refused', () => {
  const d = designated(D())
  const M3 = d.next(['a', 'b'], D())
  const pending = w.advance(admitAll(d.held, [['membership', signed('membership', M3, 'a')], ['root', rootText('b')], ['membership', signed('membership', M3, 'b')]]), T0 + 1).held
  assert.equal(state(pending).pending, true)
  assert.equal(reason(pending, 'membership', partySigned('membership', d.next(['n']), 'g'), rootText('g')), 'prev')
  const M4 = { identity: IDENTITY, prev: mId(M3), epoch: 4, roots: ids('n') }
  assert.equal(reason(pending, 'membership', partySigned('membership', M4, 'g'), rootText('g')), 'signer')
})

test('a threshold of two: one party alone starts nothing, and the root a recovery adds signs only once both have', () => {
  const d = designated(D(['g', 'h'], 2))
  const R = d.next(['n'])
  let held = asked(d.held, R, ['g'], [])
  assert.deepEqual(w.advance(held, T0 + 5).signed, [])
  held = admitAll(held, [['root', rootText('n')]])
  assert.equal(reason(held, 'membership', signed('membership', R, 'n')), 'signer')
  held = asked(held, R, ['h'], [])
  assert.deepEqual(w.advance(held, T0 + 5).signed, [], 'the added root has not signed')
  held = admitAll(held, [['membership', signed('membership', R, 'n')]])
  assert.deepEqual(types(w.advance(held, T0 + 5)), ['notice'])
})

test('any one root cancels a recovery under notice: the witness says so, the identity is as it was, and that record is never noticed again', () => {
  const d = designated(D(), ['a', 'b'])
  const R = d.next(['n'])
  const noticed = w.advance(asked(d.held, R), T0 + 5).held
  const quiet = state(d.held)
  // Refused: a cancel of anything else, or by anyone else.
  assert.equal(reason(noticed, 'cancel', cancel(d.id)), 'record')
  assert.equal(reason(noticed, 'cancel', cancel('ab'.repeat(32))), 'record')
  assert.equal(reason(d.held, 'cancel', cancel(mId(R))), 'record', 'nothing is under notice')
  assert.equal(reason(noticed, 'cancel', cancel(mId(R), 'g')), 'signer', 'the party itself')
  assert.equal(reason(noticed, 'cancel', cancel(mId(R), 'n')), 'signer', 'the root it would add')
  assert.equal(reason(noticed, 'cancel', forged('cancel', { identity: IDENTITY, record: mId(R) }, 'a', 'g')), 'signature')
  assert.equal(reason(noticed, 'cancel', signed('cancel', { identity: IDENTITY, record: mId(R), zz: 1 }, 'a')), 'shape')
  assert.equal(reason(noticed, 'cancel', signed('cancel', { identity: '9'.repeat(64), record: mId(R) }, 'a')), 'identity')
  for (const root of ['a', 'b']) {
    const held = admitAll(noticed, [['cancel', cancel(mId(R), root)]])
    assert.equal(w.admit(held, 'cancel', cancel(mId(R), root === 'a' ? 'b' : 'a')).held, held, 'one cancel is enough')
    const r = w.advance(held, T0 + 9)
    assert.deepEqual(bodies(r), [{ type: 'cancelled', identity: IDENTITY, record: mId(R), at: T0 + 9 }], root)
    const s = state(r.held)
    assert.deepEqual([s.membership, s.pending, [...s.authority], s.recovering], [quiet.membership, false, [...quiet.authority], null])
    assert.equal('recovering' in headOf(r.held, T0 + 10), false)
    assert.deepEqual(w.advance(r.held, T0 + 100 * DAY).signed, [], 'never again, whatever time passes')
    assert.equal(reason(r.held, 'cancel', cancel(mId(R), root === 'a' ? 'b' : 'a')), 'record', 'nothing is under notice any more')
  }
})

test('after a cancel, no recovery is put under notice for three days; then another may be', () => {
  const d = designated(D())
  const R = d.next(['n'])
  const cancelled = w.advance(admitAll(w.advance(asked(d.held, R), T0 + 5).held, [['cancel', cancel(mId(R))]]), T0 + 9).held
  // The party asks for another: its cancelled proposal may be replaced.
  const R2 = d.next(['i'])
  const again = asked(cancelled, R2, ['g'], ['i'])
  assert.deepEqual(w.advance(again, T0 + 9 + MIN - 1).signed, [], 'inside the cooling-off')
  const r = w.advance(again, T0 + 9 + MIN)
  assert.deepEqual(bodies(r), [{ type: 'notice', identity: IDENTITY, record: mId(R2), at: T0 + 9 + MIN }])
})

test('a party cannot take its signature from a recovery under notice', () => {
  const d = designated(D())
  const R = d.next(['n'])
  const noticed = w.advance(asked(d.held, R), T0 + 5).held
  assert.equal(reason(noticed, 'membership', partySigned('membership', d.next(['i']), 'g')), 'quorate')
  // Before its threshold is met it may: one of two replaces its proposal.
  const two = designated(D(['g', 'h'], 2))
  const one = asked(two.held, two.next(['n']), ['g'], [])
  const moved = w.admit(one, 'membership', partySigned('membership', two.next(['i']), 'g'))
  assert.equal(moved.ok, true)
  assert.deepEqual(moved.held.memberships.map((t) => open(t, 'membership').id).filter((x) => x !== two.id), [mId(two.next(['i']))])
  assert.equal(reason(moved.held, 'membership', partySigned('membership', two.next(['n']), 'g')), 'replaced')
})

test('left alone for its window, a recovery matures and is anchored in the same step; the old roots lose authority, and it settles a contest window later', () => {
  for (const window of [MIN, 7 * DAY]) {
    const d = designated(D(['g'], 1, window))
    const R = d.next(['n'])
    const noticed = w.advance(asked(d.held, R), T0 + 5).held
    assert.deepEqual(w.advance(noticed, T0 + 5 + window - 1).signed, [], 'one second short')
    const at = T0 + 5 + window
    const m = w.advance(noticed, at)
    assert.deepEqual(bodies(m), [{ type: 'matured', identity: IDENTITY, record: mId(R), at }, { type: 'anchor', identity: IDENTITY, record: mId(R), at }])
    const s = state(m.held)
    assert.deepEqual([s.membership, s.pending, [...s.authority], s.recovering], [mId(R), true, [], null])
    assert.equal(w.head(m.held, at + 1), undefined, 'no root has authority until it settles: no head')
    assert.equal(reason(m.held, 'cancel', cancel(mId(R))), 'record', 'past cancelling')
    assert.deepEqual(w.advance(m.held, at + WINDOW - 1).signed, [])
    const settled = w.advance(m.held, at + WINDOW)
    assert.deepEqual(bodies(settled), [{ type: 'settlement', identity: IDENTITY, prev: d.id, outcome: mId(R), at: at + WINDOW }])
    const e = state(settled.held)
    assert.deepEqual([e.epoch, e.pending, [...e.authority], e.recovery, e.recovering], [3, false, ids('n'), null, null])
    // What is kept replays to the same state: the witness's word that it matured, and the party's root record.
    assert.equal(settled.held.matured.length, 1)
    assert.deepEqual([settled.held.notices, settled.held.cancels, settled.held.cancelled], [[], [], []])
    assert.ok(settled.held.roots.includes(rootText('g')))
    assert.deepEqual(Array.from(headOf(settled.held, at + WINDOW + 1).authority), ids('n'))
    // What remains to the old root is R5's contest, which ends the identity.
    const contested = w.advance(admitAll(m.held, [['contest', signed('contest', { identity: IDENTITY, record: mId(R) }, 'a')]]), at + 1)
    assert.deepEqual(types(contested), ['anchor'])
    assert.equal(state(contested.held).dead, true)
  }
})

test('a cancel held when the window has passed still cancels: the cancel is looked for first', () => {
  const d = designated(D())
  const R = d.next(['n'])
  const noticed = w.advance(asked(d.held, R), T0 + 5).held
  const r = w.advance(admitAll(noticed, [['cancel', cancel(mId(R))]]), T0 + 5 + MIN + 7)
  assert.deepEqual(types(r), ['cancelled'])
})

test("an ordinary change by the owner while a recovery is under notice: anchored at once, and at settlement the recovery is gone", () => {
  const d = designated(D())
  const R = d.next(['n'])
  const noticed = w.advance(asked(d.held, R), T0 + 5).held
  const M3 = d.next(['a', 'b'], D())
  const changed = admitAll(noticed, [['membership', signed('membership', M3, 'a')], ['root', rootText('b')], ['membership', signed('membership', M3, 'b')]])
  const a = w.advance(changed, T0 + 9)
  assert.deepEqual(bodies(a), [{ type: 'anchor', identity: IDENTITY, record: mId(M3), at: T0 + 9 }])
  // Though the recovery's window passes meanwhile, it does not mature: its prev is no longer the settled membership.
  const s = w.advance(a.held, T0 + 9 + MIN + WINDOW)
  assert.deepEqual(types(s), ['settlement'])
  const e = state(s.held)
  assert.deepEqual([e.epoch, e.membership, e.recovering], [3, mId(M3), null])
  assert.deepEqual(s.held.memberships.map((t) => open(t, 'membership').id).includes(mId(R)), false)
  assert.deepEqual([s.held.notices, s.held.matured], [[], []])
  assert.equal(s.held.roots.includes(rootText('g')), false, "the party's root record goes with its signature")
  assert.deepEqual(w.advance(s.held, T0 + 100 * DAY).signed, [])
})

test('the last cancellation outlives a settlement, so the cooling-off does too', () => {
  const d = designated(D())
  const R = d.next(['n'])
  const cancelled = w.advance(admitAll(w.advance(asked(d.held, R), T0 + 5).held, [['cancel', cancel(mId(R))]]), T0 + 9).held
  const M3 = d.next(['a'], D())
  const a = w.advance(admitAll(cancelled, [['membership', signed('membership', M3, 'a')]]), T0 + 10)
  const s = w.advance(a.held, T0 + 10 + WINDOW)
  assert.equal(state(s.held).epoch, 3)
  assert.equal(s.held.cancelled.length, 1)
  const R4 = { identity: IDENTITY, prev: mId(M3), epoch: 4, roots: ids('n') }
  const again = asked(s.held, R4)
  assert.deepEqual(w.advance(again, T0 + 9 + MIN - 1).signed, [])
  assert.deepEqual(types(w.advance(again, T0 + 9 + MIN)), ['notice'])
})

test('notices are bounded by the list that holds them: past it, none is given', () => {
  const d = designated(D())
  const held = asked(d.held, d.next(['n']))
  const junk = Array.from({ length: MAX_RECORDS - 1 }, (_, i) => {
    const { payload } = envelope.seal('notice', { identity: IDENTITY, record: i.toString(16).padStart(64, '0'), at: T0 })
    return envelope.wrap(payload, { signature: sign(envelope.signedBytes(payload)), witness: WITNESS })
  })
  const nearly = Object.freeze({ ...held, notices: Object.freeze(junk) })
  const r = w.advance(nearly, T0 + 5)
  assert.deepEqual(types(r), ['notice'], 'the last place')
  assert.equal(r.held.notices.length, MAX_RECORDS)
  // With the list full, and that notice cancelled, another recovery waits for an ordinary change to clear the list.
  const cancelled = w.advance(admitAll(r.held, [['cancel', cancel(mId(d.next(['n'])))]]), T0 + 6).held
  const again = asked(cancelled, d.next(['i']), ['g'], ['i'])
  assert.deepEqual(w.advance(again, T0 + 6 + MIN).signed, [])
  assert.equal(state(again).ok, true, 'and verifiers still read what is held')
})

test('a dead identity, and one the witness does not know, are advanced without a word (found by review: the step threw)', () => {
  assert.deepEqual(w.advance(w.empty(IDENTITY), T0).signed, [], 'no root held')
  const d = designated(D())
  const R = d.next(['n'])
  const m = w.advance(w.advance(asked(d.held, R), T0 + 5).held, T0 + 5 + MIN)
  const dead = w.advance(w.advance(admitAll(m.held, [['contest', signed('contest', { identity: IDENTITY, record: mId(R) }, 'a')]]), T0 + 6 + MIN).held, T0 + 6 + MIN + WINDOW)
  assert.deepEqual(types(dead), ['settlement'])
  assert.equal(state(dead.held).dead, true)
  assert.deepEqual(w.advance(dead.held, T0 + 100 * DAY).signed, [])
  assert.equal(w.head(dead.held, T0 + 100 * DAY), undefined)
})

test('a witness whose key has run out signs nothing: the step fails, and no settlement is signed over and over (found by a walk that outlived its key)', () => {
  const short = witness({ ...CONFIG, witnessKeys: [{ key: WITNESS, nbf: 0, exp: BASE + 100 }] })
  const body = { identity: IDENTITY, prev: IDENTITY, epoch: 2, roots: ids('a') }
  let held = short.admit(short.admit(short.empty(IDENTITY), 'root', rootText('a')).held, 'membership', signed('membership', body, 'a')).held
  held = short.advance(held, BASE).held
  assert.equal(held.anchors.length, 1)
  assert.deepEqual(short.advance(held, BASE + 99).signed, [], 'inside the contest window')
  assert.throws(() => short.advance(held, BASE + WINDOW), { message: 'the witness key is outside its window at the time it would sign' })
  assert.throws(() => short.head(held, BASE + 100), { message: 'the witness key is outside its window at the time it would sign' })
  assert.equal(open(short.head(held, BASE + 99), 'head').body.at, BASE + 99, 'the last second of its window')
  assert.deepEqual(held.settlements, [])
})

test('an empty holding has the lists recoveries are kept in', () => {
  const e = w.empty(IDENTITY)
  assert.deepEqual([e.cancels, e.notices, e.cancelled, e.matured], [[], [], [], []])
})
