// The id page's records for recovery parties (R11, SPEC §8), in Node and through the witness: what the page builds
// the witness takes and the core reads, and what they would refuse the page refuses first, with a reason to show.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { records } from './impl.mjs'
import * as wf from '../witness/fixtures.mjs'
import { saltOf, secretOf, commitmentOf } from '../membership/translate.mjs'
import { make } from '../assertion/helpers.mjs'
import { membership, envelope } from '../impl.mjs'
import { createHash } from 'node:crypto'

const { recovery, rescue } = records
const { party, designate, undesignate, possession, possessionId, shows, card, fromCard, kept, newSalt, majority, recoveryChange, storedRoot, MAX_SALTS, designated, cancel, maturesAt, partySigned, rootSigned, currentMembership, addRoot, changeToSign, DEFAULT_RECOVERY_WINDOW } = records
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
// Roots a and b, settled at T0.
const two = () => w.advance(w.advance(wf.withM2(), BASE).held, T0).held
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

test("a party shows it holds its key over the designating record's possession value; another key, record, origin or rp ID fails there", () => {
  const d = designate({ identity: IDENTITY, state: current(wf.start()), parties: [P('g')], threshold: 1, window: MIN })
  const ctx = { record: d.id, rpId: RP_ID, origin: ORIGIN }
  // The value signed, computed here apart: the domain's bytes, then the record id's.
  const value = createHash('sha256').update('muid-possession\n').update(Buffer.from(d.id, 'hex')).digest('hex')
  assert.equal(possessionId(d.id), value)
  for (const bad of [undefined, '', d.id.toUpperCase(), d.id + '0', d.id.slice(1), [d.id]]) assert.throws(() => possessionId(bad), { message: 'a record id is 64 lowercase hex digits' })
  assert.equal(possession(P('g'), by('g', value), ctx), undefined)
  const fails = { message: /^the party's passkey did not sign this: / }
  assert.throws(() => possession(P('g'), by('h', value), ctx), fails)
  assert.throws(() => possession(P('g'), by('g', d.id), ctx), fails, 'the record id itself is not what is signed')
  assert.throws(() => possession(P('g'), by('g', possessionId(IDENTITY)), ctx), fails)
  assert.throws(() => possession(P('g'), by('g', value), { ...ctx, origin: 'https://other.example' }), fails)
  assert.throws(() => possession(P('g'), by('g', value), { ...ctx, rpId: 'other.example' }), fails)
  assert.throws(() => possession(P('g'), {}, ctx), fails)
  // What a party gives back is that assertion as text; anything else shows nothing.
  assert.equal(shows(P('g'), JSON.stringify(by('g', value)), ctx), true)
  for (const text of [JSON.stringify(by('h', value)), JSON.stringify(by('g', d.id)), '{', '', 'null']) assert.equal(shows(P('g'), text, ctx), false, text)
  assert.equal(shows(P('h'), JSON.stringify(by('g', value)), ctx), false)
})

test("what a party signed to show its passkey is held is no signature on a recovery, with its card's salt beside it", () => {
  // Whoever holds a party's card holds its salt. Were the possession check made over a record's id, that party's
  // answer about a recovery record would be its signature on it. The witness takes the real one and not this.
  const { held } = designatedBy(['g'], 1, MIN)
  const R = envelope.seal('membership', { identity: IDENTITY, prev: current(held).membership, epoch: 3, roots: [wf.rootId('n')] })
  const answer = by('g', possessionId(R.id))
  const r = w.admit(held, 'membership', partySigned(R.payload, P('g'), answer), wf.rootText('g'))
  assert.equal(r.ok, false)
  assert.equal(w.admit(held, 'membership', partySigned(R.payload, P('g'), by('g', R.id)), wf.rootText('g')).ok, true)
})

test('a recovery card is the party\'s root record and salt on one line; its salt is kept, up to 32; a majority is more than half', () => {
  const salt = newSalt()
  assert.match(salt, /^[0-9a-f]{64}$/)
  assert.notEqual(newSalt(), salt)
  const text = card(wf.rootText('g'), saltOf('g'))
  assert.equal(text.includes('\n'), false)
  assert.deepEqual(JSON.parse(text), { root: wf.rootText('g'), salt: saltOf('g') })
  assert.deepEqual(fromCard(text, RP_ID), P('g'))
  for (const bad of ['', '{', 'null', '[]', '7', '"x"', JSON.stringify({ salt: saltOf('g') }), JSON.stringify({ root: 7, salt: saltOf('g') }), JSON.stringify([wf.rootText('g')])]) {
    assert.throws(() => fromCard(bad, RP_ID), { message: 'that is not a recovery card' }, bad)
  }
  assert.throws(() => fromCard(JSON.stringify({ root: wf.rootText('g') }), RP_ID), { message: 'a salt is 64 lowercase hex digits' })
  assert.throws(() => fromCard(JSON.stringify({ root: 'x', salt: saltOf('g') }), RP_ID), { message: /^that is not a root record: / })
  assert.throws(() => fromCard(text, 'other.example'), { message: /^that is not a root record: / })
  assert.deepEqual(kept(undefined, 'a'), ['a'])
  assert.deepEqual(kept(['a'], 'b'), ['a', 'b'])
  assert.equal(MAX_SALTS, 32)
  const full = Array.from({ length: 32 }, (_, i) => String(i))
  assert.equal(kept(full.slice(1), 'z').length, 32)
  assert.equal(kept(full, 'z'), full, 'as they were')
  assert.deepEqual([1, 2, 3].map(majority), [1, 2, 2])
  // Kept beside the root, read back as untrusted.
  const root = { credential: 'c', identity: IDENTITY, text: wf.rootText('a') }
  const salts = Array.from({ length: 32 }, () => newSalt())
  assert.deepEqual(storedRoot({ ...root, salts }, RP_ID).salts, salts)
  assert.deepEqual(storedRoot({ ...root, salts: [] }, RP_ID).salts, [])
  for (const bad of [null, 'x', {}, [7], ['ab'], [[salts[0]]], [salts[0].toUpperCase()], [...salts, newSalt()]]) assert.equal(storedRoot({ ...root, salts: bad }, RP_ID), null, JSON.stringify(bad))
})

test('a change to co-sign with another passkey sets or ends the designation and nothing else', () => {
  const state = current(two())
  const ctx = { identity: IDENTITY, state }
  const d = designate({ ...ctx, parties: [P('g')], threshold: 1, window: MIN })
  assert.deepEqual(recoveryChange(d.payload, ctx), { body: d.body, id: d.id, payload: d.payload })
  const fails = { message: "that change does more than set this identity's recovery parties" }
  const of = (x) => envelope.seal('membership', { ...d.body, ...x }).payload
  assert.throws(() => recoveryChange(of({ identity: wf.identityFor('b') }), ctx), fails)
  assert.throws(() => recoveryChange(of({ prev: IDENTITY }), ctx), fails)
  assert.throws(() => recoveryChange(of({ epoch: d.body.epoch + 1 }), ctx), fails)
  assert.throws(() => recoveryChange(of({ roots: [wf.rootId('a')] }), ctx), fails)
  assert.throws(() => recoveryChange(of({ roots: [...d.body.roots, wf.rootId('n')].sort() }), ctx), fails)
  assert.throws(() => recoveryChange(d.payload, { ...ctx, state: { ...state, pending: true } }), { message: 'a change is already pending: wait for it to settle' })
  assert.throws(() => recoveryChange('nonsense', ctx), { message: 'that is not a membership change' })
  // Both passkeys' signatures on it make the designation; ending it is co-signed the same way.
  let h = admit(two(), 'membership', rootSigned(d.payload, wf.rootId('a'), by('a', d.id)))
  assert.equal(current(h).pending, false, 'one of two is no change yet')
  assert.equal(recoveryChange(d.payload, { identity: IDENTITY, state: current(h) }).id, d.id)
  h = admit(h, 'membership', rootSigned(d.payload, wf.rootId('b'), by('b', d.id)))
  const t = T0 + 10 * WINDOW
  const after = current(w.advance(w.advance(h, t).held, t + WINDOW).held)
  assert.deepEqual(after.recovery, d.body.recovery)
  const u = undesignate({ identity: IDENTITY, state: after })
  assert.equal('recovery' in recoveryChange(u.payload, { identity: IDENTITY, state: after }).body, false)
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
  // Issue #243: records read after the notice end it only with what ends it. The cancel stated, or the recovery
  // matured and settled, does; the records from before the notice, served again, only leave it out.
  const matured = w.advance(noticed, T0 + 5 + MIN).held
  assert.deepEqual([current(matured).epoch, current(matured).recovering], [3, null])
  const withheld = (earlier, later) => records.withheld(earlier, later, wf.CTX)
  assert.deepEqual([withheld(noticed, held), withheld(noticed, h), withheld(noticed, r.held), withheld(noticed, matured), withheld(noticed, noticed)],
    [true, true, false, false, false])
  assert.deepEqual([withheld(held, noticed), withheld(r.held, held), withheld(matured, held)], [false, false, false], 'no notice was read')
  assert.throws(() => withheld(noticed, { ...held, memberships: Array(257).fill('x') }), { message: 'the witness holds no record of this identity' })
})

test('one who lost every passkey asks for a recovery; a party reads the request against the identity; signed by both, the witness gives notice', () => {
  const { held, d } = designatedBy(['g', 'h', 'i'], 2, MIN)
  const state = current(held)
  const c = recovery({ identity: IDENTITY, state, root: wf.rootText('n'), rpId: RP_ID })
  assert.deepEqual(c.body, { identity: IDENTITY, prev: d.id, epoch: 3, roots: [wf.rootId('n')], recovery: d.body.recovery })
  assert.equal(c.added, wf.rootId('n'))
  assert.equal(changeToSign(c.payload).id, c.id)
  const of = (x) => () => recovery({ identity: IDENTITY, state, root: wf.rootText('n'), rpId: RP_ID, ...x })
  assert.throws(of({ state: { ...state, pending: true } }), { message: 'a change is already pending: wait for it to settle' })
  assert.throws(of({ state: { ...state, recovery: null } }), { message: 'that identity has designated no recovery parties' })
  assert.throws(of({ state: { ...state, recovering: { record: d.id, at: 1 } } }), { message: 'a recovery of that identity is already under notice' })
  assert.throws(of({ root: 'x' }), { message: /^that is not a root record: / })
  assert.throws(of({ rpId: 'other.example' }), { message: /^that is not a root record: / })
  assert.throws(of({ root: wf.rootText('a') }), { message: 'that passkey is already a root of this identity' })

  // The party: the salt it kept that opens a commitment, among others it kept; the wait.
  const kept = [saltOf('n'), saltOf('h'), saltOf('i')]
  const r = rescue(c.payload, { state, root: wf.rootId('h'), salts: kept })
  assert.deepEqual(r, { body: c.body, id: c.id, payload: c.payload, salt: saltOf('h'), window: MIN })
  const no = (x, message) => assert.throws(() => rescue(c.payload, { state, root: wf.rootId('h'), salts: kept, ...x }), { message })
  no({ salts: [] }, "this passkey is not one of that identity's recovery parties")
  no({ salts: [saltOf('g'), saltOf('i')] }, "this passkey is not one of that identity's recovery parties")
  no({ root: wf.rootId('n') }, "this passkey is not one of that identity's recovery parties")
  no({ root: wf.rootId('a') }, "this passkey is one of that identity's own")
  no({ state: { ...state, pending: true } }, 'that identity has no recovery parties who can act now')
  no({ state: { ...state, recovery: null } }, 'that identity has no recovery parties who can act now')
  no({ state: { ...state, membership: IDENTITY } }, 'that request is not for the identity as it now stands')
  no({ state: { ...state, epoch: 3 } }, 'that request is not for the identity as it now stands')
  assert.throws(() => rescue('nonsense', { state, root: wf.rootId('h'), salts: kept }), { message: 'that is not a membership change' })

  // Through the witness: the new root's record is unnamed, and its signature refused, until the parties have signed.
  const mine = rootSigned(c.payload, wf.rootId('n'), by('n', c.id))
  assert.equal(w.admit(held, 'root', wf.rootText('n')).reason, 'root-unnamed')
  let h = admit(held, 'membership', partySigned(c.payload, { root: wf.rootId('h'), salt: r.salt }, by('h', c.id)), wf.rootText('h'))
  assert.equal(w.admit(h, 'membership', mine).reason, 'signer', 'one of two parties is not enough')
  const g = rescue(c.payload, { state: current(h), root: wf.rootId('g'), salts: [saltOf('g')] })
  h = admit(h, 'membership', partySigned(c.payload, { root: wf.rootId('g'), salt: g.salt }, by('g', c.id)), wf.rootText('g'))
  assert.equal(w.admit(h, 'membership', mine).reason, 'root-missing', 'what the page answers by giving the root record')
  h = admit(admit(h, 'root', wf.rootText('n')), 'membership', mine)
  const noticed = current(w.advance(h, T0 + 5).held)
  assert.deepEqual(noticed.recovering, { record: c.id, at: T0 + 5 })
  assert.throws(() => recovery({ identity: IDENTITY, state: noticed, root: wf.rootText('n'), rpId: RP_ID }), { message: 'a recovery of that identity is already under notice' })
})
