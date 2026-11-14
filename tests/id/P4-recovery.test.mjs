// The id page's records for recovery parties (R11, SPEC §8), in Node and through the witness: what the page builds
// the witness takes and the core reads, and what they would refuse the page refuses first, with a reason to show.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { records } from './impl.mjs'
import * as wf from '../witness/fixtures.mjs'
import { saltOf, secretOf, commitmentOf } from '../membership/translate.mjs'
import { make } from '../assertion/helpers.mjs'
import { membership, envelope } from '../impl.mjs'

const { party, designate, undesignate, possession, designated, cancel, maturesAt, partySigned, rootSigned, currentMembership, addRoot, changeToSign, DEFAULT_RECOVERY_WINDOW } = records
const { IDENTITY, BASE, WINDOW, w } = wf
const { rpId: RP_ID, origin: ORIGIN } = wf.CTX
const MIN = membership.MIN_RECOVERY_WINDOW
const T0 = BASE + WINDOW
const P = (letter) => party(wf.rootText(letter), saltOf(letter), RP_ID)
const by = (letter, id) => make({ covers: [id], secret: secretOf(letter) })
const current = (held) => currentMembership(held, wf.CTX)
const admit = (held, type, text, root) => {
  const r = w.admit(held, type, text, root)
  assert.equal(r.ok, true, `refused ${type}: ${r.reason}`)
  return r.held
}
// Root a's identity with g designated (or `letters`), settled at T0.
function designatedBy (letters = ['g'], threshold = 1, window = DEFAULT_RECOVERY_WINDOW) {
  const start = wf.start()
  const d = designate({ identity: IDENTITY, state: current(start), parties: letters.map(P), threshold, window })
  const held = w.advance(w.advance(admit(start, 'membership', rootSigned(d.payload, wf.rootId('a'), by('a', d.id))), BASE).held, T0).held
  return { held, d }
}

test('a party: its root record and salt give the commitment the core computes, and nothing else is taken', () => {
  const p = P('g')
  assert.deepEqual([p.root, p.salt, p.commitment], [wf.rootId('g'), saltOf('g'), commitmentOf('g')])
  assert.throws(() => party('nonsense', saltOf('g'), RP_ID), { message: /^that is not a root record: / })
  assert.throws(() => party(wf.rootText('g'), saltOf('g'), 'other.example'), { message: /^that is not a root record: / })
  for (const bad of [undefined, '', 'ab', saltOf('g').toUpperCase(), saltOf('g') + '0', 7, [saltOf('g')]]) {
    assert.throws(() => party(wf.rootText('g'), bad, RP_ID), { message: 'a salt is 64 lowercase hex digits' })
  }
})

test('a designation the page builds is taken by the witness, settles, and is read back as the designation in force', () => {
  assert.equal(DEFAULT_RECOVERY_WINDOW, 14 * 86_400)
  const { held, d } = designatedBy(['h', 'g', 'i'], 2)
  assert.deepEqual(d.body, { identity: IDENTITY, prev: IDENTITY, epoch: 2, roots: [wf.rootId('a')], recovery: { parties: ['g', 'h', 'i'].map(commitmentOf).sort(), threshold: 2, window: DEFAULT_RECOVERY_WINDOW } })
  const s = current(held)
  assert.deepEqual([s.epoch, s.pending, s.recovery, s.recovering], [2, false, d.body.recovery, null])
  assert.equal(designated(s.recovery, P('h')), true)
  assert.equal(designated(s.recovery, P('n')), false)
  assert.equal(designated(s.recovery, party(wf.rootText('h'), saltOf('g'), RP_ID)), false, 'another salt opens nothing')
  assert.equal(designated(null, P('h')), false)
})

test('what R11 would refuse of a designation, the page refuses first', () => {
  const state = current(wf.start())
  const of = (x) => () => designate({ identity: IDENTITY, state, parties: [P('g')], threshold: 1, window: MIN, ...x })
  const taken = (c) => changeToSign(c.payload).id === c.id // the core's own form
  assert.equal(taken(of({})()), true)
  assert.throws(of({ state: { ...state, pending: true } }), { message: 'a change is already pending: wait for it to settle' })
  for (const parties of [undefined, [], [P('g'), P('h'), P('i'), P('n')]]) assert.throws(of({ parties }), { message: 'name 1 to 3 recovery parties' })
  assert.throws(of({ parties: [P('a')] }), { message: "a recovery party must not be one of this identity's own passkeys" })
  assert.throws(of({ parties: [P('g'), P('a')], threshold: 2 }), { message: "a recovery party must not be one of this identity's own passkeys" })
  assert.throws(of({ parties: [P('g'), P('g')], threshold: 2 }), { message: 'a recovery party is named twice' })
  assert.throws(of({ parties: [P('g'), party(wf.rootText('g'), saltOf('h'), RP_ID)], threshold: 2 }), { message: 'a recovery party is named twice' })
  for (const [n, threshold] of [[1, 0], [1, 2], [2, 1], [2, 3], [3, 1], [3, 4], [1, 1.5], [1, '1']]) {
    assert.throws(of({ parties: ['g', 'h', 'i'].slice(0, n).map(P), threshold }), { message: 'the parties needed must be more than half of those named' }, `${threshold} of ${n}`)
  }
  for (const [n, threshold] of [[1, 1], [2, 2], [3, 2], [3, 3]]) assert.equal(taken(of({ parties: ['g', 'h', 'i'].slice(0, n).map(P), threshold })()), true)
  for (const window of [MIN - 1, membership.MAX_RECOVERY_WINDOW + 1, 1.5 * MIN + 0.5, undefined]) assert.throws(of({ window }), { message: 'the waiting period must be 3 to 90 days' })
  for (const window of [MIN, membership.MAX_RECOVERY_WINDOW]) assert.equal(of({ window })().body.recovery.window, window)
})

test("a party shows it holds its key over the designating record; another key, record, origin or rp ID fails there", () => {
  const d = designate({ identity: IDENTITY, state: current(wf.start()), parties: [P('g')], threshold: 1, window: MIN })
  const ctx = { record: d.id, rpId: RP_ID, origin: ORIGIN }
  assert.equal(possession(P('g'), by('g', d.id), ctx), undefined)
  const fails = { message: /^the party's passkey did not sign this: / }
  assert.throws(() => possession(P('g'), by('h', d.id), ctx), fails)
  assert.throws(() => possession(P('g'), by('g', IDENTITY), ctx), fails)
  assert.throws(() => possession(P('g'), by('g', d.id), { ...ctx, origin: 'https://other.example' }), fails)
  assert.throws(() => possession(P('g'), by('g', d.id), { ...ctx, rpId: 'other.example' }), fails)
  assert.throws(() => possession(P('g'), {}, ctx), fails)
})

test('adding a root states the designation in force again; a change shown to co-sign shows it; ending it is a change without one', () => {
  const { held, d } = designatedBy()
  const state = current(held)
  const c = addRoot({ identity: IDENTITY, state, root: wf.rootText('b'), rpId: RP_ID })
  assert.deepEqual(c.body.recovery, d.body.recovery)
  assert.deepEqual(changeToSign(c.payload).body, c.body)
  let h = admit(held, 'membership', rootSigned(c.payload, wf.rootId('a'), by('a', c.id)))
  h = admit(admit(h, 'root', wf.rootText('b')), 'membership', rootSigned(c.payload, wf.rootId('b'), by('b', c.id)))
  const after = current(w.advance(w.advance(h, T0 + 1).held, T0 + 1 + WINDOW).held)
  assert.deepEqual([after.epoch, after.roots.length, after.recovery], [3, 2, d.body.recovery])
  // Without a designation in force, none is stated, as before.
  assert.equal('recovery' in addRoot({ identity: IDENTITY, state: current(wf.start()), root: wf.rootText('b'), rpId: RP_ID }).body, false)
  assert.equal('recovery' in changeToSign(addRoot({ identity: IDENTITY, state: current(wf.start()), root: wf.rootText('b'), rpId: RP_ID }).payload).body, false)
  const u = undesignate({ identity: IDENTITY, state })
  assert.deepEqual(u.body, { identity: IDENTITY, prev: d.id, epoch: 3, roots: [wf.rootId('a')] })
  const ended = current(w.advance(w.advance(admit(held, 'membership', rootSigned(u.payload, wf.rootId('a'), by('a', u.id))), T0 + 1).held, T0 + 1 + WINDOW).held)
  assert.deepEqual([ended.epoch, ended.recovery], [3, null])
  assert.throws(() => undesignate({ identity: IDENTITY, state: ended }), { message: 'no recovery parties are designated' })
  assert.throws(() => undesignate({ identity: IDENTITY, state: { ...state, pending: true } }), { message: 'a change is already pending: wait for it to settle' })
  assert.throws(() => changeToSign('nonsense'), { message: 'that is not a membership change' })
})

test("a party's signature built by the page starts a recovery; the page reads the notice and when it matures; its cancel ends it", () => {
  const { held } = designatedBy(['g'], 1, MIN)
  const state = current(held)
  assert.throws(() => cancel({ identity: IDENTITY, state }), { message: 'no recovery is under notice' })
  const R = { identity: IDENTITY, prev: state.membership, epoch: 3, roots: [wf.rootId('n')] }
  const sealed = changeToSign(envelope.seal('membership', R).payload)
  assert.deepEqual(sealed.body, R)
  let h = admit(held, 'membership', partySigned(sealed.payload, P('g'), by('g', sealed.id)), wf.rootText('g'))
  h = admit(admit(h, 'root', wf.rootText('n')), 'membership', rootSigned(sealed.payload, wf.rootId('n'), by('n', sealed.id)))
  const noticed = w.advance(h, T0 + 5).held
  const s = current(noticed)
  assert.deepEqual(s.recovering, { record: sealed.id, at: T0 + 5 })
  assert.equal(maturesAt(s), T0 + 5 + MIN)
  const c = cancel({ identity: IDENTITY, state: s })
  assert.deepEqual(c.body, { identity: IDENTITY, record: sealed.id })
  const r = w.advance(admit(noticed, 'cancel', rootSigned(c.payload, wf.rootId('a'), by('a', c.id))), T0 + 6)
  assert.deepEqual(r.signed.map((x) => x.type), ['cancelled'])
  assert.equal(current(r.held).recovering, null)
})
