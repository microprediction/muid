// R11, one field at a time: a designation out of form is no membership record; a party's signature counts only if it
// opens a commitment of the settled membership's designation; one party counts once; the witness's notice,
// cancelled and matured records are read as its anchors are; and a head carries the recovery under notice.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { membership, envelope } from '../impl.mjs'
import { make } from '../assertion/helpers.mjs'
import { identityFor, CTX_BASE, rootId, rootText, rootSigned, partySigned, witnessSigned, commitmentOf, saltOf, secretOf, BASE } from './translate.mjs'

const { membershipState, headOf, recoveryCommitment, isMembership, MIN_RECOVERY_WINDOW, MAX_RECOVERY_WINDOW, MAX_RECORDS } = membership
const I = identityFor('a')
const ctx = { ...CTX_BASE, identity: I }
const mid = (body) => envelope.seal('membership', body).id
const state = (records) => JSON.parse(JSON.stringify(membershipState(records, ctx)))
const roots = ['a', 'b', 'g', 'h', 'i', 'n'].map(rootText)
const stated = (type, record, at = BASE + 5, identity = I) => witnessSigned(type, { identity, record, at })
const anchor = (record, at) => stated('anchor', record, at)
const settle = (prev, outcome, at = BASE + 2) => witnessSigned('settlement', { identity: I, prev, outcome, at })
// The commitment of the zero root id under the zero salt, computed apart from the core.
const PINNED = '4fe5e682d6040d8332aee17d5ce46649cd7c38cde1d6402ef505e504854e9520'
const D = (letters = ['g'], threshold = 1, window = MIN_RECOVERY_WINDOW) => ({ parties: letters.map(commitmentOf).sort(), threshold, window })

// Epoch 2: the root a, designating `recovery`; settled.
const epoch2 = (recovery) => {
  const body = recovery === undefined ? { identity: I, prev: I, epoch: 2, roots: [rootId('a')] } : { identity: I, prev: I, epoch: 2, roots: [rootId('a')], recovery }
  return { body, id: mid(body), records: { roots, memberships: [rootSigned('membership', body, 'a')], anchors: [anchor(mid(body), BASE + 1)], settlements: [settle(I, mid(body))] } }
}
// Epoch 3: a recovery of epoch 2 to the root n, with the witness's word that it matured, and its anchor.
const recoveryTo = (e2, letter = 'n', recovery) => {
  const body = recovery === undefined ? { identity: I, prev: e2.id, epoch: 3, roots: [rootId(letter)] } : { identity: I, prev: e2.id, epoch: 3, roots: [rootId(letter)], recovery }
  return { body, id: mid(body) }
}
const withSigs = (e2, r, sigs, more = {}) => ({ ...e2.records, memberships: [...e2.records.memberships, ...sigs],
  anchors: [...e2.records.anchors, anchor(r.id, BASE + 9)], matured: [stated('matured', r.id, BASE + 9)], ...more })
const recovered = (records, r) => { const s = state(records); return s.membership === r.id && s.pending === true }

test('the commitment: SHA-256 of the domain, the root id and the salt; anything but two ids is a programming error', () => {
  const root = rootId('g')
  const salt = saltOf('g')
  const expected = createHash('sha256').update(Buffer.concat([Buffer.from('muid-recovery\n'), Buffer.from(root, 'hex'), Buffer.from(salt, 'hex')])).digest('hex')
  assert.equal(recoveryCommitment(root, salt), expected)
  assert.equal(recoveryCommitment('00'.repeat(32), 'ff'.repeat(32)), createHash('sha256').update(Buffer.concat([Buffer.from('muid-recovery\n'), Buffer.alloc(32), Buffer.alloc(32, 255)])).digest('hex'))
  assert.equal(recoveryCommitment('00'.repeat(32), '00'.repeat(32)), PINNED)
  assert.notEqual(recoveryCommitment(root, salt), recoveryCommitment(salt, root))
  for (const bad of [[root], [root, salt.slice(2)], [root.toUpperCase().replace(/\d/g, 'A'), salt], [root, salt + '00'], [undefined, salt], [root, 7], [Buffer.from(root, 'hex'), salt]]) {
    assert.throws(() => recoveryCommitment(...bad), { name: 'TypeError', message: 'root and salt must be 32 bytes of lowercase hex' })
  }
  assert.deepEqual([MIN_RECOVERY_WINDOW, MAX_RECOVERY_WINDOW], [259_200, 7_776_000])
})

test('a designation in form is the settled membership\'s, given back frozen; at each bound', () => {
  for (const d of [D(), D(['g', 'h', 'i'], 3, MAX_RECOVERY_WINDOW), D(['g', 'h', 'i'], 2, 1_209_600), D(['g', 'h'], 2)]) {
    const e2 = epoch2(d)
    const s = membershipState(e2.records, ctx)
    assert.equal(s.membership, e2.id)
    assert.deepEqual(JSON.parse(JSON.stringify(s.recovery)), d)
    assert.ok(Object.isFrozen(s.recovery) && Object.isFrozen(s.recovery.parties))
    assert.equal(s.recovering, null)
  }
  assert.equal(membershipState(epoch2().records, ctx).recovery, null, 'none designated')
})

test('a designation out of form is no membership record', () => {
  const [g, h, i] = ['g', 'h', 'i'].map(commitmentOf).sort()
  const ok = D()
  for (const [name, d] of [
    ['no party', { ...ok, parties: [] }], ['four parties', { parties: [g, h, i, 'ff'.repeat(32)].sort(), threshold: 3, window: ok.window }],
    ['parties out of order', { parties: [h, g], threshold: 2, window: ok.window }], ['a party twice', { parties: [g, g], threshold: 2, window: ok.window }],
    ['a party that is no id', { ...ok, parties: ['x'] }], ['a party in capitals', { ...ok, parties: ['AB'.repeat(32)] }],
    ['parties not a list', { ...ok, parties: g }], ['parties an object', { ...ok, parties: { a: g } }],
    ['threshold 0', { ...ok, threshold: 0 }], ['one of two', { parties: [g, h], threshold: 1, window: ok.window }], ['one of three', { parties: [g, h, i], threshold: 1, window: ok.window }], ['threshold above the parties', { ...ok, threshold: 2 }], ['threshold a string', { ...ok, threshold: '1' }],
    ['threshold negative', { ...ok, threshold: -1 }], ['threshold above three of three', { parties: [g, h, i], threshold: 4, window: ok.window }],
    ['a window under three days', { ...ok, window: MIN_RECOVERY_WINDOW - 1 }], ['a window over ninety', { ...ok, window: MAX_RECOVERY_WINDOW + 1 }],
    ['a window that is a string', { ...ok, window: String(MIN_RECOVERY_WINDOW) }], ['a window of 0', { ...ok, window: 0 }],
    ['another key', { ...ok, zz: 1 }], ['a key before', { ...ok, a: 1 }], ['no parties', { threshold: 1, window: ok.window }],
    ['no threshold', { parties: [g], window: ok.window }], ['no window', { parties: [g], threshold: 1 }], ['empty', {}],
    ['a list', [g]], ['a string', g], ['a number', 1], ['true', true],
  ]) {
    assert.equal(state(epoch2(d).records).epoch, 1, name)
  }
  // The form the witness admits by is the same one, and total: a null (which no record can carry) is not one.
  // (Keys in the order a decoded record has them.)
  const sorted = (recovery, roots = [rootId('a')]) => (recovery === undefined ? { epoch: 2, identity: I, prev: I, roots } : { epoch: 2, identity: I, prev: I, recovery, roots })
  assert.equal(isMembership(sorted(ok)), true)
  assert.equal(isMembership(sorted()), true)
  assert.equal(isMembership(envelope.open(epoch2(ok).records.memberships[0], 'membership').body), true)
  for (const recovery of [null, [], 'x', 1, {}, { ...ok, threshold: 0 }]) assert.equal(isMembership(sorted(recovery)), false, JSON.stringify(recovery))
  assert.equal(isMembership(sorted(ok, [])), false)
})

test('a recovery: the party opens its commitment; anything less is no recovery, whatever the witness says of it', () => {
  const e2 = epoch2(D())
  const r = recoveryTo(e2)
  const n = rootSigned('membership', r.body, 'n')
  const g = partySigned('membership', r.body, 'g')
  assert.ok(recovered(withSigs(e2, r, [g, n]), r), 'control: the party and the root it adds')
  assert.deepEqual(state(withSigs(e2, r, [g, n])).authority, [], 'pending: the old root is gone and the new one has no authority yet')
  const sig = (letter, more) => {
    const { payload, id } = envelope.seal('membership', r.body)
    return envelope.wrap(payload, { root: rootId(letter), assertion: make({ covers: [id], secret: secretOf(letter) }), ...more })
  }
  for (const [name, sigs, more] of [
    ['the party without its salt', [rootSigned('membership', r.body, 'g'), n]],
    ['another salt', [sig('g', { salt: saltOf('h') }), n]],
    ['a salt that is no id', [sig('g', { salt: 'x' }), n]],
    ['a salt in capitals', [sig('g', { salt: saltOf('g').toUpperCase() }), n]],
    ['a salt and another key', [sig('g', { salt: saltOf('g'), zz: 1 }), n]],
    ['a root that was not designated, with its own salt', [partySigned('membership', r.body, 'h'), n]],
    ['a party\'s salt on another key\'s assertion', [(() => { const { payload, id } = envelope.seal('membership', r.body); return envelope.wrap(payload, { root: rootId('g'), salt: saltOf('g'), assertion: make({ covers: [id], secret: secretOf('h') }) }) })(), n]],
    ['the added root unsigned', [g]],
    ['the witness has not said it matured', [g, n], { matured: [] }],
    ['matured, said of another record', [g, n], { matured: [stated('matured', e2.id)] }],
    ['matured, by a key that is not the witness\'s', [g, n], { matured: [rootSigned('matured', { identity: I, record: r.id, at: BASE + 9 }, 'a')] }],
    ['matured, for another identity', [g, n], { matured: [stated('matured', r.id, BASE + 9, '9'.repeat(64))] }],
    ['matured, with another key in it', [g, n], { matured: [witnessSigned('matured', { identity: I, record: r.id, at: BASE + 9, zz: 1 })] }],
    ['matured, at no time', [g, n], { matured: [stated('matured', r.id, -1)] }],
    ['matured, outside the witness key\'s window', [g, n], { matured: [stated('matured', r.id, BASE + 1_000_000)] }],
    ['a notice in place of matured', [g, n], { matured: [stated('notice', r.id)] }],
    ['not anchored', [g, n], { anchors: e2.records.anchors }],
  ]) {
    assert.equal(recovered(withSigs(e2, r, sigs, more), r), false, name)
    assert.equal(state(withSigs(e2, r, sigs, more)).membership, e2.id, name)
  }
  // The same signatures on an ordinary record count for nothing: a party has no vote.
  assert.equal(recovered({ ...withSigs(e2, r, [g, n]), matured: [] }, r), false)
})

test('a party that adds itself: its one signature opens its commitment and signs as the added root; a plain one beside it changes nothing, in either order', () => {
  const e2 = epoch2(D())
  const r = recoveryTo(e2, 'g')
  const salted = partySigned('membership', r.body, 'g')
  const plain = rootSigned('membership', r.body, 'g')
  assert.ok(recovered(withSigs(e2, r, [salted]), r))
  assert.ok(recovered(withSigs(e2, r, [plain, salted]), r), 'the plain signature first')
  assert.ok(recovered(withSigs(e2, r, [salted, plain]), r), 'the salted signature first')
  assert.equal(recovered(withSigs(e2, r, [plain]), r), false, 'the plain signature alone opens nothing')
  assert.ok(recovered(withSigs(e2, r, [salted, salted, salted]), r), 'a signature repeated')
})

test('a salt belongs to a membership record only: a contest or a freeze signed with one is no record', () => {
  const e2 = epoch2(D())
  const b3 = { identity: I, prev: e2.id, epoch: 3, roots: [rootId('a'), rootId('b')].sort() }
  const pending = { ...e2.records, memberships: [...e2.records.memberships, rootSigned('membership', b3, 'a'), rootSigned('membership', b3, 'b')], anchors: [...e2.records.anchors, anchor(mid(b3), BASE + 3)] }
  const salted = (type, body) => {
    const { payload, id } = envelope.seal(type, body)
    return { id, text: envelope.wrap(payload, { root: rootId('a'), salt: saltOf('a'), assertion: make({ covers: [id], secret: secretOf('a') }) }) }
  }
  const contest = salted('contest', { identity: I, record: mid(b3) })
  assert.equal(state({ ...pending, contests: [contest.text], anchors: [...pending.anchors, anchor(contest.id, BASE + 4)] }).dead, false)
  assert.equal(state({ ...pending, contests: [rootSigned('contest', { identity: I, record: mid(b3) }, 'a')], anchors: [...pending.anchors, anchor(contest.id, BASE + 4)] }).dead, true, 'control: the same contest without a salt')
  assert.equal(state({ ...e2.records, freezes: [salted('freeze', { identity: I, membership: e2.id }).text] }).frozen, false)
  assert.equal(state({ ...e2.records, freezes: [rootSigned('freeze', { identity: I, membership: e2.id }, 'a')] }).frozen, true, 'control')
})

test('one party counts once: a designation that commits to it twice, under two salts, is not met by it alone', () => {
  const other = createHash('sha256').update('another salt').digest('hex')
  const twice = { parties: [commitmentOf('g'), recoveryCommitment(rootId('g'), other)].sort(), threshold: 2, window: MIN_RECOVERY_WINDOW }
  const e2 = epoch2(twice)
  const r = recoveryTo(e2)
  const { payload, id } = envelope.seal('membership', r.body)
  const second = envelope.wrap(payload, { root: rootId('g'), salt: other, assertion: make({ covers: [id], secret: secretOf('g') }) })
  const sigs = [partySigned('membership', r.body, 'g'), second, rootSigned('membership', r.body, 'n')]
  assert.equal(recovered(withSigs(e2, r, sigs), r), false)
  // Two parties of two: both, and neither alone.
  const both = epoch2(D(['g', 'h'], 2))
  const r2 = recoveryTo(both)
  const n = rootSigned('membership', r2.body, 'n')
  assert.ok(recovered(withSigs(both, r2, [partySigned('membership', r2.body, 'g'), partySigned('membership', r2.body, 'h'), n]), r2))
  for (const l of ['g', 'h']) assert.equal(recovered(withSigs(both, r2, [partySigned('membership', r2.body, l), n]), r2), false, l)
})

test('a designation lasts only as long as its membership: a successor that does not repeat it has none, and its parties recover nothing', () => {
  const e2 = epoch2(D())
  const b3 = { identity: I, prev: e2.id, epoch: 3, roots: [rootId('a')] }
  const settled3 = { ...e2.records, memberships: [...e2.records.memberships, rootSigned('membership', b3, 'a')],
    anchors: [...e2.records.anchors, anchor(mid(b3), BASE + 3)], settlements: [...e2.records.settlements, settle(e2.id, mid(b3), BASE + 4)] }
  assert.deepEqual([state(settled3).epoch, state(settled3).recovery], [3, null])
  const b4 = { identity: I, prev: mid(b3), epoch: 4, roots: [rootId('n')] }
  const tried = { ...settled3, memberships: [...settled3.memberships, partySigned('membership', b4, 'g'), rootSigned('membership', b4, 'n')],
    anchors: [...settled3.anchors, anchor(mid(b4), BASE + 9)], matured: [stated('matured', mid(b4), BASE + 9)], notices: [stated('notice', mid(b4), BASE + 5)] }
  assert.deepEqual([state(tried).epoch, state(tried).membership], [3, mid(b3)])
  // A recovery states its own designation, or none, like any record.
  const r = recoveryTo(e2, 'n', D(['h']))
  const kept = { ...withSigs(e2, r, [partySigned('membership', r.body, 'g'), rootSigned('membership', r.body, 'n')]), settlements: [...e2.records.settlements, settle(e2.id, r.id, BASE + 12)] }
  assert.deepEqual([state(kept).epoch, state(kept).recovery], [3, D(['h'])])
})

test('the recovery under notice: the witness\'s notice of a held successor of the settled membership, not cancelled and not anchored', () => {
  const e2 = epoch2(D())
  const r = recoveryTo(e2)
  const other = recoveryTo(e2, 'i')
  const sigs = [partySigned('membership', r.body, 'g'), partySigned('membership', other.body, 'g')]
  const held = { ...e2.records, memberships: [...e2.records.memberships, ...sigs] }
  const under = (more) => state({ ...held, ...more }).recovering
  assert.deepEqual(under({ notices: [stated('notice', r.id, BASE + 5)] }), { record: r.id, at: BASE + 5 })
  const s = membershipState({ ...held, notices: [stated('notice', r.id, BASE + 5)] }, ctx)
  assert.ok(Object.isFrozen(s.recovering))
  assert.deepEqual([s.membership, s.pending, JSON.parse(JSON.stringify(s.authority))], [e2.id, false, [rootId('a')]], 'nothing else changes')
  for (const [name, more] of [
    ['none', {}],
    ['cancelled', { notices: [stated('notice', r.id)], cancelled: [stated('cancelled', r.id, BASE + 6)] }],
    ['anchored', { notices: [stated('notice', r.id)], anchors: [...held.anchors, anchor(r.id, BASE + 6)] }],
    ['of a record that is not held', { notices: [stated('notice', 'ab'.repeat(32))] }],
    ['of the settled membership itself', { notices: [stated('notice', e2.id)] }],
    ['for another identity', { notices: [stated('notice', r.id, BASE + 5, '9'.repeat(64))] }],
    ['with another key', { notices: [witnessSigned('notice', { identity: I, record: r.id, at: BASE + 5, zz: 1 })] }],
    ['at no time', { notices: [stated('notice', r.id, -1)] }],
    ['at a time that is a string', { notices: [witnessSigned('notice', { identity: I, record: r.id, at: String(BASE) })] }],
    ['of no id', { notices: [stated('notice', 'x')] }],
    ['outside the witness key\'s window', { notices: [stated('notice', r.id, BASE + 1_000_000)] }],
    ['signed by a root', { notices: [rootSigned('notice', { identity: I, record: r.id, at: BASE + 5 }, 'a')] }],
    ['a matured record in its place', { notices: [stated('matured', r.id)] }],
  ]) {
    assert.equal(under(more), null, name)
  }
  // A `cancelled` out of form, or of another record, cancels nothing.
  for (const [name, c] of [['another record', stated('cancelled', other.id)], ['another identity', stated('cancelled', r.id, BASE + 6, '9'.repeat(64))],
    ['another key in it', witnessSigned('cancelled', { identity: I, record: r.id, at: BASE + 6, zz: 1 })], ['signed by a root', rootSigned('cancelled', { identity: I, record: r.id, at: BASE + 6 }, 'a')],
    ['a notice in its place', stated('notice', r.id, BASE + 6)]]) {
    assert.equal(under({ notices: [stated('notice', r.id, BASE + 5)], cancelled: [c] })?.record, r.id, name)
  }
  // Of several (a witness that lies): the latest; of two at one time, the least id; in either order given.
  const [lo, hi] = [r.id, other.id].sort()
  for (const flip of [false, true]) {
    const order = (x) => (flip ? x.reverse() : x)
    assert.deepEqual(under({ notices: order([stated('notice', r.id, BASE + 5), stated('notice', other.id, BASE + 7)]) }), { record: other.id, at: BASE + 7 })
    assert.deepEqual(under({ notices: order([stated('notice', hi, BASE + 5), stated('notice', lo, BASE + 5)]) }), { record: lo, at: BASE + 5 })
    // The later one whichever id is the lesser: the id decides only between notices of one time.
    assert.deepEqual(under({ notices: order([stated('notice', hi, BASE + 7), stated('notice', lo, BASE + 5)]) }), { record: hi, at: BASE + 7 })
    assert.deepEqual(under({ notices: order([stated('notice', lo, BASE + 7), stated('notice', hi, BASE + 5)]) }), { record: lo, at: BASE + 7 })
    assert.deepEqual(under({ notices: order([stated('notice', r.id, BASE + 5), stated('notice', other.id, BASE + 7)]), cancelled: [stated('cancelled', other.id, BASE + 8)] }), { record: r.id, at: BASE + 5 })
  }
  // After the settled membership has moved on, the notice is of nothing.
  const b3 = { identity: I, prev: e2.id, epoch: 3, roots: [rootId('a'), rootId('b')].sort(), recovery: D() }
  const moved = { ...held, memberships: [...held.memberships, rootSigned('membership', b3, 'a'), rootSigned('membership', b3, 'b')],
    anchors: [...held.anchors, anchor(mid(b3), BASE + 6)], settlements: [...held.settlements, settle(e2.id, mid(b3), BASE + 7)], notices: [stated('notice', r.id, BASE + 5)] }
  assert.deepEqual([state(moved).epoch, state(moved).recovering], [3, null])
})

test('a head carries the recovery under notice, and has no such field without one', () => {
  const e2 = epoch2(D())
  const r = recoveryTo(e2)
  const held = { ...e2.records, memberships: [...e2.records.memberships, partySigned('membership', r.body, 'g')] }
  const quiet = headOf(membershipState(held, ctx), 77)
  assert.equal('recovering' in quiet, false)
  const s = membershipState({ ...held, notices: [stated('notice', r.id, BASE + 5)] }, ctx)
  const head = headOf(s, 77)
  assert.deepEqual(JSON.parse(JSON.stringify(head)), { identity: I, epoch: 2, memberships: [e2.id], authority: [rootId('a')], revoked: [], at: 77, recovering: { record: r.id, at: BASE + 5 } })
  assert.ok(Object.isFrozen(head) && Object.isFrozen(head.recovering))
  // A state made by hand without the field gives a head without it.
  const { recovering, ...bare } = s
  assert.equal('recovering' in headOf({ ...bare }, 77), false)
  assert.equal('recovering' in headOf({ ...bare, recovering: undefined }, 77), false)
})

test('each of the witness\'s lists about recoveries is bounded like the rest', () => {
  const e2 = epoch2(D())
  const many = Array.from({ length: MAX_RECORDS + 1 }, () => 'x')
  for (const key of ['notices', 'cancelled', 'matured']) {
    assert.deepEqual({ ...membershipState({ ...e2.records, [key]: many }, ctx) }, { ok: false, reason: 'records' }, key)
    assert.equal(membershipState({ ...e2.records, [key]: many.slice(1) }, ctx).ok, true, key)
    assert.equal(membershipState({ ...e2.records, [key]: 'not a list' }, ctx).ok, true, key)
  }
})
