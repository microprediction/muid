// R9 and decision 12 on the witness's side: which revocations it admits, and how long heads carry them. A revocation
// is admitted from a root with authority, or from a delegate for its own key with the delegation that makes it one,
// so no one else can add entries. It is kept for the life of the identity, or, for a delegation id given with its
// delegation, until that delegation's expiry plus skew (decision 12, after review round 8).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { ed25519 } from '@noble/curves/ed25519.js'
import { envelope } from '../impl.mjs'
import { make } from '../assertion/helpers.mjs'
import { secretOf } from '../membership/translate.mjs'
import { w, IDENTITY, BASE, WINDOW, start, withM2, M2, mId, signed, forged, rootId, rootText, admitAll, state } from './fixtures.mjs'

const hex = (b) => Buffer.from(b).toString('hex')
const refused = (r) => (r.ok ? 'accepted' : r.reason)
const NOW = BASE + 100
const APP = Uint8Array.from({ length: 32 }, (_, i) => 60 + i)
const SUBJECT = hex(ed25519.getPublicKey(APP))
const DEL_ID = 'd'.repeat(64)

function delegation ({ identity = IDENTITY, membership = IDENTITY, root = 'a', subject = APP, nbf = NOW - 10, exp = NOW + 86_000 } = {}) {
  const body = { identity, membership, root: rootId(root), subject: hex(ed25519.getPublicKey(subject)), aud: 'https://app.example',
    scopes: ['post'], nbf, exp }
  const { payload, id } = envelope.seal('delegation', body)
  return envelope.wrap(payload, { root: make({ covers: [id], secret: secretOf(root) }),
    subject: hex(ed25519.sign(Buffer.concat([Buffer.from('muid/v1/accept\n'), Buffer.from(id, 'hex')]), subject)) })
}
const byRoot = (target, letter = 'a', at = NOW) => signed('revocation', { identity: IDENTITY, target, at }, letter)
function bySelf (target = SUBJECT, secret = APP, at = NOW) {
  const { payload } = envelope.seal('revocation', { identity: IDENTITY, target, at })
  return envelope.wrap(payload, { signature: hex(ed25519.sign(envelope.signedBytes(payload), secret)) })
}
const revokedIn = (held, at = NOW) => {
  const t = w.head(held, at)
  return t === undefined ? undefined : Array.from(envelope.open(t, 'head').body.revoked) // decoded arrays have no iterator
}

test('a root with authority revokes a delegation id or a subject key, and the head carries it', () => {
  const r = w.revoke(start(), byRoot(DEL_ID), NOW)
  assert.equal(r.ok, true)
  assert.deepEqual(revokedIn(r.held), [DEL_ID])
  const both = w.revoke(r.held, byRoot(SUBJECT), NOW).held
  assert.deepEqual(revokedIn(both), [DEL_ID, SUBJECT].sort())
  assert.deepEqual(revokedIn(start()), [])
})

test('a root without authority, a stranger or a forgery cannot revoke', () => {
  const pending = w.advance(withM2(), BASE).held // b is added, without authority until settlement (R6)
  assert.equal(refused(w.revoke(pending, byRoot(DEL_ID, 'b'), NOW)), 'signer')
  assert.equal(refused(w.revoke(start(), byRoot(DEL_ID, 'c'), NOW)), 'signer')
  assert.equal(refused(w.revoke(start(), forged('revocation', { identity: IDENTITY, target: DEL_ID, at: NOW }, 'a', 'b'), NOW)), 'signature')
  assert.equal(w.revoke(pending, byRoot(DEL_ID, 'a'), NOW).ok, true, 'a stays, so keeps authority')
})

test('a delegate revokes its own key, with the delegation that makes it a delegate of this identity', () => {
  const r = w.revoke(start(), bySelf(), NOW, delegation())
  assert.equal(r.ok, true)
  assert.deepEqual(revokedIn(r.held), [SUBJECT])
  // Without it, any fresh key could add entries until no head can be signed (R9 fails closed past 64).
  assert.equal(refused(w.revoke(start(), bySelf(), NOW)), 'delegation')
  const OTHER = Uint8Array.from({ length: 32 }, (_, i) => 90 + i)
  assert.equal(refused(w.revoke(start(), bySelf(), NOW, delegation({ subject: OTHER }))), 'delegation', 'a delegation of another key')
  assert.equal(refused(w.revoke(start(), bySelf(), NOW, delegation({ exp: NOW }))), 'delegation', 'an expired delegation')
  assert.equal(refused(w.revoke(start(), bySelf(), NOW, delegation({ membership: 'e'.repeat(64) }))), 'delegation', 'under another membership')
  assert.equal(refused(w.revoke(start(), bySelf(), NOW, delegation({ root: 'b' }))), 'delegation', 'its root is not held')
  assert.equal(refused(w.revoke(start(), bySelf(), NOW, delegation({ identity: 'f'.repeat(64) }))), 'delegation', "another identity's")
  assert.equal(refused(w.revoke(start(), bySelf(), NOW, 'x')), 'delegation')
  assert.equal(refused(w.revoke(start(), bySelf(SUBJECT, OTHER), NOW, delegation())), 'signature', 'signed by another key')
})

test('kept for the life of the identity: a change of membership does not drop a revocation', () => {
  const r = w.revoke(start(), byRoot(DEL_ID), NOW).held // epoch 1
  const withM = admitAll(r, [['membership', signed('membership', M2, 'a')], ['root', rootText('b')], ['membership', signed('membership', M2, 'b')]])
  const pending = w.advance(withM, NOW).held
  assert.deepEqual(revokedIn(pending, NOW), [DEL_ID])
  const settled = w.advance(pending, NOW + WINDOW).held
  assert.equal(state(settled).epoch, 2)
  assert.deepEqual(revokedIn(settled, NOW + WINDOW), [DEL_ID])
})

// Found by review (round 8): decision 12 (a) dropped a revocation once a later membership settled, but W0 lets the
// owner sign a change and delegations under it in one prompt, so a delegation can exist under a membership before it
// is anchored, and become valid when it settles.
test('a delegation signed under a membership not yet anchored stays revoked once that membership settles', () => {
  const pre = delegation({ membership: mId(M2) }) // under M2, signed before M2 is anchored
  const preId = envelope.open(pre, 'delegation').id
  let h = admitAll(start(), [['membership', signed('membership', M2, 'a')], ['root', rootText('b')]])
  h = w.revoke(h, byRoot(preId), NOW).held // M2 not yet valid: b has not signed
  h = admitAll(h, [['membership', signed('membership', M2, 'b')]])
  h = w.advance(w.advance(h, NOW).held, NOW + WINDOW).held
  assert.equal(state(h).settled, mId(M2))
  assert.deepEqual(revokedIn(h, NOW + WINDOW), [preId])
})

test("a root's revocation of a delegation id, given with that delegation, is dropped once the delegation has expired", () => {
  const d = delegation({ exp: NOW + 1000 })
  const id = envelope.open(d, 'delegation').id
  const r = w.revoke(start(), byRoot(id), NOW, d)
  assert.equal(r.ok, true)
  assert.deepEqual(revokedIn(r.held, NOW + 1000 + 59), [id], 'kept until exp plus skew')
  assert.deepEqual(revokedIn(r.held, NOW + 1000 + 60), [], 'then no delegation it names can verify')
  // Dropped from what is held at the next admission after that; without the delegation, kept.
  const later = w.revoke(r.held, byRoot(SUBJECT), NOW + 1060).held
  assert.deepEqual(later.revocations.map((x) => x.target), [SUBJECT])
  assert.deepEqual(revokedIn(w.revoke(start(), byRoot(id), NOW).held, NOW + 10 ** 6), [id])
  // A delegation that is not the one named is refused.
  assert.equal(refused(w.revoke(start(), byRoot(DEL_ID), NOW, d)), 'delegation')
  assert.equal(refused(w.revoke(start(), byRoot(id), NOW, 'x')), 'delegation')
})

test('while a change is pending, a delegation under either name serves, and a revocation then is carried at once', () => {
  const pending = w.advance(withM2(), BASE).held
  assert.equal(w.revoke(pending, bySelf(), NOW, delegation()).ok, true, 'under the settled membership')
  assert.equal(w.revoke(pending, bySelf(), NOW, delegation({ membership: mId(M2) })).ok, true, 'under the pending one')
  assert.deepEqual(revokedIn(w.revoke(pending, byRoot(DEL_ID), NOW).held), [DEL_ID])
})

test('one entry per target: a revocation already held, or another for the same target, is accepted unchanged', () => {
  const once = w.revoke(start(), bySelf(), NOW, delegation()).held
  const again = w.revoke(once, bySelf(SUBJECT, APP, NOW + 1), NOW, delegation())
  assert.equal(again.ok, true)
  assert.equal(again.held.revocations.length, 1)
  assert.equal(w.revoke(once, byRoot(SUBJECT), NOW).held.revocations.length, 1)
})

test('form, identity and a dead identity', () => {
  for (const body of [{ identity: IDENTITY, target: 'x', at: NOW }, { identity: IDENTITY, target: DEL_ID, at: -1 },
    { identity: IDENTITY, target: DEL_ID, at: NOW, x: 1 }, { identity: IDENTITY, target: DEL_ID + 'x', at: NOW }, { identity: IDENTITY, target: 'x' + DEL_ID, at: NOW }]) {
    assert.equal(refused(w.revoke(start(), signed('revocation', body, 'a'), NOW)), 'shape', JSON.stringify(body))
  }
  const env = JSON.parse(byRoot(DEL_ID))
  for (const sig of [{ ...env.sig, z: 1 }, {}, { signature: 1 }, { signature: 'ab', z: 1 }]) {
    assert.equal(refused(w.revoke(start(), JSON.stringify({ payload: env.payload, sig }), NOW, delegation())), 'shape', JSON.stringify(sig).slice(0, 40))
  }
  assert.equal(refused(w.revoke(start(), signed('revocation', { identity: 'f'.repeat(64), target: DEL_ID, at: NOW }, 'a'), NOW)), 'identity')
  assert.equal(refused(w.revoke(start(), 'x', NOW)), 'envelope-encoding')
  assert.equal(refused(w.revoke(w.empty(IDENTITY), byRoot(DEL_ID), NOW)), 'unknown-identity')
  const pending = w.advance(withM2(), BASE).held
  const dead = w.advance(w.advance(admitAll(pending, [['contest', signed('contest', { identity: IDENTITY, record: mId(M2) }, 'a')]]), BASE + 1).held, BASE + WINDOW).held
  assert.equal(refused(w.revoke(dead, byRoot(DEL_ID), NOW)), 'dead')
  assert.throws(() => w.revoke(start(), byRoot(DEL_ID), -1), { name: 'TypeError', message: /now must be a non-negative integer/ })
})

test('R9 fails closed: with more than 64 live revocations no head is signed; the list is capped at MAX_RECORDS', () => {
  // Built directly: 65 live entries, spread over six roots (one root holds at most 12; past roots' entries stay).
  const live = (n) => Array.from({ length: n }, (_, i) => Object.freeze({ text: `t${i}`, target: (i + 1).toString(16).padStart(64, '0'), until: null, root: `${i % 6}`.repeat(64) }))
  assert.equal(w.head(Object.freeze({ ...start(), revocations: Object.freeze(live(65)) }), NOW), undefined)
  assert.equal(revokedIn(Object.freeze({ ...start(), revocations: Object.freeze(live(64)) })).length, 64)
  // Built directly: 256 live entries.
  const entries = Array.from({ length: 256 }, (_, i) => Object.freeze({ text: `t${i}`, target: (i + 1).toString(16).padStart(64, '0'), until: null }))
  const full = Object.freeze({ ...start(), revocations: Object.freeze(entries) })
  assert.equal(refused(w.revoke(full, byRoot(DEL_ID), NOW)), 'full')
  assert.equal(w.revoke(full, byRoot(entries[0].target), NOW).ok, true, 'a target already held is accepted when full')
  const stale = Object.freeze({ ...full, revocations: Object.freeze(entries.map((e) => ({ ...e, until: NOW }))) })
  assert.equal(w.revoke(stale, byRoot(DEL_ID), NOW).held.revocations.length, 1, 'entries no longer kept do not count')
})

test('a foreign error opening a revocation (patched built-ins) is refused, never thrown', () => {
  const s = start()
  const text = byRoot(DEL_ID)
  const original = Uint8Array.prototype.fill
  Uint8Array.prototype.fill = function () { throw new Error('patched') }
  let out
  try { out = refused(w.revoke(s, text, NOW)) } catch (e) { out = 'threw ' + e } finally { Uint8Array.prototype.fill = original }
  assert.equal(out, 'envelope-encoding')
})

// Decision 12's quota: each live entry counts against one root — the root that signed it, or for a delegate's
// revocation of itself, the root of its delegation — and a root holds at most 12, so one stolen root cannot fill the
// 64 a head carries and stop heads for good.
test('a root holds at most 12 live revocations, its own and its delegates\' together; lapsed ones do not count', () => {
  const target = (i) => (i + 1).toString(16).padStart(64, '0')
  let h = start()
  for (let i = 0; i < 11; i++) h = w.revoke(h, byRoot(target(i)), NOW).held
  assert.deepEqual(h.revocations.map((x) => x.root), Array(11).fill(rootId('a')))
  // A delegate of a's revokes itself: the twelfth, counted against a.
  h = w.revoke(h, bySelf(), NOW, delegation()).held
  assert.equal(h.revocations.at(-1).root, rootId('a'))
  assert.equal(refused(w.revoke(h, byRoot(target(20)), NOW)), 'quota')
  const other = Uint8Array.from({ length: 32 }, (_, i) => 120 + i)
  assert.equal(refused(w.revoke(h, bySelf(hex(ed25519.getPublicKey(other)), other), NOW, delegation({ subject: other }))), 'quota')
  // A target already held is still accepted unchanged.
  assert.equal(w.revoke(h, byRoot(target(0)), NOW).held, h)
  // The head still carries all twelve.
  assert.equal(revokedIn(h).length, 12)
  // A root's revocation of a delegation id given with that delegation lapses with it, and then no longer counts.
  const d = delegation({ exp: NOW + 100 })
  let g = start()
  for (let i = 0; i < 11; i++) g = w.revoke(g, byRoot(target(i)), NOW).held
  g = w.revoke(g, byRoot(envelope.open(d, 'delegation').id), NOW, d).held
  assert.equal(refused(w.revoke(g, byRoot(target(30)), NOW)), 'quota')
  assert.equal(w.revoke(g, byRoot(target(30)), NOW + 100 + 60).ok, true)
})

test("one root's quota does not touch another's: b files its own 12 after a's", () => {
  const now = BASE + WINDOW + 10
  const settled = w.advance(w.advance(withM2(), BASE).held, BASE + WINDOW).held // {a, b} settled
  const target = (i) => (i + 1).toString(16).padStart(64, '0')
  let h = settled
  for (let i = 0; i < 12; i++) h = w.revoke(h, byRoot(target(i), 'a', now), now).held
  assert.equal(refused(w.revoke(h, byRoot(target(12), 'a', now), now)), 'quota')
  for (let i = 12; i < 23; i++) h = w.revoke(h, byRoot(target(i), 'b', now), now).held
  // b's delegate's self-revocation counts against b, not a.
  h = w.revoke(h, bySelf(SUBJECT, APP, now), now, delegation({ membership: mId(M2), root: 'b', nbf: now - 10, exp: now + 3600 })).held
  assert.equal(h.revocations.at(-1).root, rootId('b'))
  assert.equal(refused(w.revoke(h, byRoot(target(40), 'b', now), now)), 'quota')
  assert.equal(revokedIn(h, now).length, 24)
})

// Found by review (round 10): the quota counts only a root's own live entries, and a retired root's entries stay, so
// rotations could take the total past the 64 a head carries and stop heads for good. A revocation that would make a
// 65th live entry is refused instead: heads keep being signed, and the owner's fallback is to remove the root.
test('at most 64 live revocations in all, retired roots\' included: the 65th is refused, and heads keep being signed', () => {
  const entries = Array.from({ length: 64 }, (_, i) => Object.freeze({ text: `t${i}`, target: (i + 1).toString(16).padStart(64, '0'), until: null, root: `${i % 6}`.repeat(64) }))
  const full = Object.freeze({ ...start(), revocations: Object.freeze(entries) })
  assert.equal(refused(w.revoke(full, byRoot(DEL_ID), NOW)), 'full')
  assert.equal(revokedIn(full).length, 64)
  // One fewer: admitted.
  const room = Object.freeze({ ...start(), revocations: Object.freeze(entries.slice(1)) })
  assert.equal(w.revoke(room, byRoot(DEL_ID), NOW).ok, true)
})
