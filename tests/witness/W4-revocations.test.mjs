// R9 and decision 12 on the witness's side: which revocations it admits, and how long heads carry them. A revocation
// is admitted from a root with authority, or from a delegate for its own key with the delegation that makes it one,
// so no one else can add entries; it is kept while the membership current when it was admitted, or that one's
// successor while pending, has authority (R6 refuses every delegation under any other).
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

test('decision 12 (a): kept while the membership current at admission, or its pending successor, has authority', () => {
  const r = w.revoke(start(), byRoot(DEL_ID), NOW).held // under epoch 1
  const withM = admitAll(r, [['membership', signed('membership', M2, 'a')], ['root', rootText('b')], ['membership', signed('membership', M2, 'b')]])
  const pending = w.advance(withM, NOW).held
  assert.deepEqual(revokedIn(pending, NOW), [DEL_ID], 'kept while the successor is pending')
  const settled = w.advance(pending, NOW + WINDOW).held
  assert.equal(state(settled).epoch, 2)
  assert.deepEqual(revokedIn(settled, NOW + WINDOW), [], 'dropped once a later membership has settled: R6 refuses the old one')
  // Admitted while M2 was pending: it is M2's, so it stays after M2 settles.
  const late = w.advance(w.revoke(pending, byRoot(SUBJECT), NOW).held, NOW + WINDOW).held
  assert.deepEqual(revokedIn(late, NOW + WINDOW), [SUBJECT])
  assert.equal(w.revoke(late, byRoot(DEL_ID, 'b'), NOW + WINDOW).held.revocations.length, 2, 'entries no longer kept are dropped at the next admission')
  assert.deepEqual(mId(M2), state(late).settled)
})

test('while a change is pending, a delegation under either name serves, and a revocation then is carried at once', () => {
  const pending = w.advance(withM2(), BASE).held
  assert.equal(w.revoke(pending, bySelf(), NOW, delegation()).ok, true, 'under the settled membership')
  assert.equal(w.revoke(pending, bySelf(), NOW, delegation({ membership: mId(M2) })).ok, true, 'under the pending one')
  assert.deepEqual(revokedIn(w.revoke(pending, byRoot(DEL_ID), NOW).held), [DEL_ID], 'admitted while pending: kept while pending')
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
  let h = start()
  for (let i = 0; i < 65; i++) h = w.revoke(h, byRoot((i + 1).toString(16).padStart(64, '0')), NOW).held
  assert.equal(h.revocations.length, 65)
  assert.equal(w.head(h, NOW), undefined)
  // Built directly: 256 live entries.
  const entries = Array.from({ length: 256 }, (_, i) => Object.freeze({ text: `t${i}`, target: (i + 1).toString(16).padStart(64, '0'), under: IDENTITY }))
  const full = Object.freeze({ ...start(), revocations: Object.freeze(entries) })
  assert.equal(refused(w.revoke(full, byRoot(DEL_ID), NOW)), 'full')
  assert.equal(w.revoke(full, byRoot(entries[0].target), NOW).ok, true, 'a target already held is accepted when full')
  const stale = Object.freeze({ ...full, revocations: Object.freeze(entries.map((e) => ({ ...e, under: 'e'.repeat(64) }))) })
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
