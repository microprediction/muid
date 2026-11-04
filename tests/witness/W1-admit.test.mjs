// R8's admission: the witness keeps only records that can carry authority, so the records it holds for an identity,
// which every head is computed from and which count toward MAX_RECORDS, cannot be filled by anyone else.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { w, IDENTITY, BASE, WINDOW, start, withM2, M2, mBody, mId, signed, forged, rootText, rootId, admitAll, state } from './fixtures.mjs'

const refused = (r) => (r.ok ? 'accepted' : r.reason)

test('an empty holding is the identity alone; the first root is admitted, and nothing else without it', () => {
  const e = w.empty(IDENTITY)
  assert.deepEqual({ ...e }, { identity: IDENTITY, roots: [], memberships: [], contests: [], freezes: [], anchors: [], settlements: [] })
  assert.ok(Object.isFrozen(e) && Object.isFrozen(e.roots))
  assert.equal(refused(w.admit(e, 'membership', signed('membership', M2, 'a'))), 'unknown-identity')
  const r = w.admit(e, 'root', rootText('a'))
  assert.equal(r.ok, true)
  assert.deepEqual(r.held.roots, [rootText('a')])
  assert.equal(e.roots.length, 0, 'the holding given is not changed')
  for (const bad of ['x', 'x' + IDENTITY, IDENTITY + 'x', IDENTITY.toUpperCase(), undefined]) {
    assert.throws(() => w.empty(bad), { name: 'TypeError', message: /identity must be an id/ })
  }
})

test('a root record is admitted only when it is the first root or named by a held membership record', () => {
  const s = start()
  assert.equal(refused(w.admit(s, 'root', rootText('b'))), 'root-unnamed')
  const m = w.admit(s, 'membership', signed('membership', M2, 'a'))
  assert.equal(m.ok, true)
  assert.equal(w.admit(m.held, 'root', rootText('b')).ok, true)
  assert.equal(refused(w.admit(m.held, 'root', rootText('c'))), 'root-unnamed')
  assert.equal(refused(w.admit(s, 'root', 'x')), 'envelope-encoding')
})

test('a membership signature counts only from a root of the effective membership, or an added root after a majority', () => {
  const s = start()
  const M3 = mBody(2, ['a', 'b', 'c'], IDENTITY)
  // b and c are added; their signatures wait for a majority of {a}.
  const held = admitAll(s, [['membership', signed('membership', M3, 'a')], ['root', rootText('b')], ['root', rootText('c')]])
  assert.equal(w.admit(held, 'membership', signed('membership', M3, 'b')).ok, true)
  const early = admitAll(s, [['membership', signed('membership', mBody(2, ['a'], IDENTITY), 'a')]])
  // b is named by no held record here, so its root record and signature are refused.
  assert.equal(refused(w.admit(early, 'root', rootText('b'))), 'root-unnamed')
  // An added root's signature before a majority of the previous roots signed the same record.
  const two = admitAll(withM2(), [])
  const M3b = mBody(3, ['a', 'b', 'c'], mId(M2))
  const sig = (l) => signed('membership', M3b, l)
  const pending = w.advance(two, BASE).held // M2 anchored: the effective membership is {a, b}
  let h = admitAll(pending, [['membership', sig('a')], ['root', rootText('c')]])
  assert.equal(refused(w.admit(h, 'membership', sig('c'))), 'signer', 'one of two previous roots is not a strict majority')
  h = admitAll(h, [['membership', sig('b')]])
  assert.equal(w.admit(h, 'membership', sig('c')).ok, true)
})

test('a membership signature by a stranger, or forged, or for another identity, prev or epoch, is refused', () => {
  const s = start()
  assert.equal(refused(w.admit(s, 'membership', forged('membership', M2, 'a', 'b'))), 'signature')
  assert.equal(refused(w.admit(admitAll(s, [['membership', signed('membership', M2, 'a')], ['root', rootText('b')]]),
    'membership', signed('membership', mBody(2, ['a', 'c'], IDENTITY), 'b'))), 'signer')
  assert.equal(refused(w.admit(s, 'membership', signed('membership', { ...M2, identity: 'f'.repeat(64) }, 'a'))), 'identity')
  assert.equal(refused(w.admit(s, 'membership', signed('membership', mBody(2, ['a', 'b'], 'e'.repeat(64)), 'a'))), 'prev')
  assert.equal(refused(w.admit(s, 'membership', signed('membership', mBody(3, ['a', 'b'], IDENTITY), 'a'))), 'epoch')
  assert.equal(refused(w.admit(s, 'membership', 'x')), 'envelope-encoding')
  assert.equal(refused(w.admit(s, 'membership', signed('freeze', { identity: IDENTITY, membership: IDENTITY }, 'a'))), 'type')
})

test('a record of the wrong form is refused as shape, before anything else is checked', () => {
  const s = start()
  const a = rootId('a')
  const ids = (n) => Array.from({ length: n }, (_, i) => (i + 1).toString(16).padStart(64, '0'))
  for (const roots of [[], ids(6), [ids(2)[1], ids(2)[0]], [a, a], ['x'], 'x', [1]]) {
    assert.equal(refused(w.admit(s, 'membership', signed('membership', { ...M2, roots }, 'a'))), 'shape', JSON.stringify(roots))
  }
  assert.equal(refused(w.admit(s, 'membership', signed('membership', { ...M2, extra: 1 }, 'a'))), 'shape')
  for (const n of [1, 5]) {
    const roots = [a, ...ids(n - 1)].sort()
    assert.equal(w.admit(s, 'membership', signed('membership', { ...M2, roots }, 'a')).ok, true, `${n} roots`)
  }
  for (const bad of ['x' + ids(1)[0], ids(1)[0] + 'x']) assert.equal(refused(w.admit(s, 'membership', signed('membership', { ...M2, roots: [a, bad].sort() }, 'a'))), 'shape')
  assert.equal(refused(w.admit(s, 'contest', signed('contest', { identity: IDENTITY, record: IDENTITY, x: 1 }, 'a'))), 'shape')
  assert.equal(refused(w.admit(s, 'freeze', signed('freeze', { identity: IDENTITY }, 'a'))), 'membership', 'a missing field fails its own check')
  const text = signed('freeze', { identity: IDENTITY, membership: IDENTITY }, 'a')
  const env = JSON.parse(text)
  assert.equal(refused(w.admit(s, 'freeze', JSON.stringify({ payload: env.payload, sig: { ...env.sig, z: 1 } }))), 'shape')
})

test('an added root\'s signature before its root record is refused as root-missing', () => {
  const h = admitAll(start(), [['membership', signed('membership', M2, 'a')]])
  assert.equal(refused(w.admit(h, 'membership', signed('membership', M2, 'b'))), 'root-missing')
})

test('a foreign error opening a record (patched built-ins) is refused, never thrown', () => {
  const s = start()
  const text = signed('freeze', { identity: IDENTITY, membership: IDENTITY }, 'a')
  const original = Uint8Array.prototype.fill
  Uint8Array.prototype.fill = function () { throw new Error('patched') }
  let out
  try { out = refused(w.admit(s, 'freeze', text)) } catch (e) { out = 'threw ' + e } finally { Uint8Array.prototype.fill = original }
  assert.equal(out, 'envelope-encoding')
})

test('R3: once a successor is anchored, a rival is refused, and a record after it is held', () => {
  const pending = w.advance(withM2(), BASE).held
  assert.equal(state(pending).pending, true)
  assert.equal(refused(w.admit(pending, 'membership', signed('membership', mBody(2, ['a', 'c'], IDENTITY), 'a'))), 'prev')
  assert.equal(w.admit(pending, 'membership', signed('membership', mBody(3, ['a'], mId(M2)), 'a')).ok, true)
  const settled = w.advance(pending, BASE + WINDOW).held
  assert.equal(state(settled).pending, false)
  assert.equal(refused(w.admit(settled, 'membership', signed('membership', mBody(2, ['a', 'c'], IDENTITY), 'a'))), 'prev')
})

test('R5: a contest is admitted only for the pending record, signed by a root of the settled membership', () => {
  const contest = (letter, record = mId(M2)) => signed('contest', { identity: IDENTITY, record }, letter)
  assert.equal(refused(w.admit(withM2(), 'contest', contest('a'))), 'record', 'nothing is pending yet')
  const pending = w.advance(withM2(), BASE).held
  assert.equal(w.admit(pending, 'contest', contest('a')).ok, true)
  assert.equal(refused(w.admit(pending, 'contest', contest('b'))), 'signer', 'b is not a root of the settled membership')
  assert.equal(refused(w.admit(pending, 'contest', contest('a', 'e'.repeat(64)))), 'record')
  assert.equal(refused(w.admit(pending, 'contest', forged('contest', { identity: IDENTITY, record: mId(M2) }, 'a', 'b'))), 'signature')
})

test('R2: a freeze is admitted for the settled or pending membership, from one of its roots (decision 11)', () => {
  const freeze = (letter, membership) => signed('freeze', { identity: IDENTITY, membership }, letter)
  const s = start()
  assert.equal(w.admit(s, 'freeze', freeze('a', IDENTITY)).ok, true)
  assert.equal(refused(w.admit(s, 'freeze', freeze('a', mId(M2)))), 'membership')
  const pending = w.advance(withM2(), BASE).held
  assert.equal(w.admit(pending, 'freeze', freeze('b', mId(M2))).ok, true, 'a new root of the pending record')
  assert.equal(w.admit(pending, 'freeze', freeze('a', IDENTITY)).ok, true)
  assert.equal(refused(w.admit(pending, 'freeze', freeze('b', IDENTITY))), 'signer')
})

test('a record already held is accepted again without being stored twice', () => {
  const s = start()
  const once = w.admit(s, 'freeze', signed('freeze', { identity: IDENTITY, membership: IDENTITY }, 'a')).held
  const twice = w.admit(once, 'freeze', signed('freeze', { identity: IDENTITY, membership: IDENTITY }, 'a'))
  assert.equal(twice.ok, true)
  assert.equal(twice.held.freezes.length, 1)
  assert.equal(w.admit(s, 'root', rootText('a')).held.roots.length, 1)
})

test('nothing is admitted to a dead identity', () => {
  const pending = w.advance(withM2(), BASE).held
  const contested = admitAll(pending, [['contest', signed('contest', { identity: IDENTITY, record: mId(M2) }, 'a')]])
  const dead = w.advance(w.advance(contested, BASE + 1).held, BASE + WINDOW).held
  assert.equal(state(dead).dead, true)
  assert.equal(refused(w.admit(dead, 'freeze', signed('freeze', { identity: IDENTITY, membership: IDENTITY }, 'a'))), 'dead')
})

test('each list is capped at MAX_RECORDS (256): a new record is refused when its list is full, before any check', () => {
  const s = start()
  // Built directly: the cap is checked before the state is computed, so the full list need not verify.
  const full = Object.freeze({ ...s, memberships: Object.freeze(Array.from({ length: 256 }, (_, i) => `filler ${i}`)) })
  assert.equal(refused(w.admit(full, 'membership', signed('membership', M2, 'a'))), 'full')
  assert.equal(refused(w.admit({ ...s, freezes: full.memberships }, 'freeze', signed('freeze', { identity: IDENTITY, membership: IDENTITY }, 'a'))), 'full')
  const almost = Object.freeze({ ...s, memberships: Object.freeze(full.memberships.slice(1)) })
  assert.equal(w.admit(almost, 'membership', signed('membership', M2, 'a')).ok, true, 'the 256th is admitted')
  assert.equal(w.admit({ ...full, memberships: [...full.memberships.slice(1), signed('membership', M2, 'a')] }, 'membership',
    signed('membership', M2, 'a')).ok, true, 'a record already held is accepted when its list is full')
})

test('only root-signed record types and roots are submitted; anchors and settlements are the witness\'s own', () => {
  for (const type of ['anchor', 'settlement', 'delegation', 'head']) assert.equal(refused(w.admit(start(), type, '{}')), 'type')
  assert.throws(() => w.admit(start(), 'nonsense', '{}'), TypeError)
})
