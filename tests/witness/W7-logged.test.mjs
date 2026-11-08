// R10 on the witness's side: it logs a delegation only while it can verify and no kept revocation names it, so it
// knows every delegation that can verify; it keeps revocations for good (a delegation id given with its delegation,
// until that expires); a head carries only the kept revocations that name a logged delegation still live. Each head
// entry counts against the root that filed it (12), a head never holds more than 64, and revocations are admitted per
// root by a token bucket (12, one more a day).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { ed25519 } from '@noble/curves/ed25519.js'
import { envelope, verifier as verifierModule } from '../impl.mjs'
import { make } from '../assertion/helpers.mjs'
import { secretOf } from '../membership/translate.mjs'
import { w, IDENTITY, BASE, WINDOW, start, withM2, M2, mId, signed, rootId, rootText, admitAll, state, CONFIG } from './fixtures.mjs'

const hex = (b) => Buffer.from(b).toString('hex')
const refused = (r) => (r.ok ? 'accepted' : r.reason)
const NOW = BASE + 100
const DAY = 86_400
const key = (i) => Uint8Array.from({ length: 32 }, (_, j) => (i * 7 + j) % 256)
const subjectOf = (secret) => hex(ed25519.getPublicKey(secret))

function delegation ({ secret = key(1), membership = IDENTITY, root = 'a', nbf = NOW - 10, exp = NOW + 3600, identity = IDENTITY } = {}) {
  const body = { identity, membership, root: rootId(root), subject: subjectOf(secret), aud: 'https://app.example', scopes: ['post'], nbf, exp }
  const { payload, id } = envelope.seal('delegation', body)
  return { id, text: envelope.wrap(payload, { root: make({ covers: [id], secret: secretOf(root) }),
    subject: hex(ed25519.sign(Buffer.concat([Buffer.from('muid/v1/accept\n'), Buffer.from(id, 'hex')]), secret)) }) }
}
const byRoot = (target, letter = 'a', at = NOW) => signed('revocation', { identity: IDENTITY, target, at }, letter)
const revokedIn = (held, at = NOW) => {
  const t = w.head(held, at)
  return t === undefined ? undefined : Array.from(envelope.open(t, 'head').body.revoked)
}
const target = (i) => (i + 1).toString(16).padStart(64, '0')
// Logs each delegation, asserting it is logged.
function logAll (held, texts, now = NOW) {
  for (const t of texts) {
    const r = w.log(held, t, now)
    if (!r.ok) throw new Error(`log refused: ${r.reason}`)
    held = r.held
  }
  return held
}

test('a delegation that can verify is logged: the witness signs a logged record, and the verifier then accepts it', () => {
  const d = delegation()
  const r = w.log(start(), d.text, NOW)
  assert.equal(r.ok, true)
  const body = envelope.open(r.logged, 'logged').body
  assert.deepEqual({ ...body }, { at: NOW, delegation: d.id, identity: IDENTITY })
  assert.equal(r.fresh, true)
  const v = verifierModule.verifier({ rpId: CONFIG.rpId, origin: CONFIG.origin, audience: 'https://app.example', witnessKeys: CONFIG.witnessKeys,
    skew: 60, maxLifetime: CONFIG.maxLifetime, maxStaleness: 86_400, maxClaimAge: 300 })
  const records = { delegation: d.text, root: rootText('a'), head: w.head(r.held, NOW), logged: r.logged }
  assert.equal(v.verifyDelegation(records, { now: NOW, scope: 'post', revoked: [] }).ok, true)
  // Logged again: the same record, nothing new signed.
  const again = w.log(r.held, d.text, NOW + 5)
  assert.deepEqual([again.ok, again.logged, again.fresh, again.held], [true, r.logged, false, r.held])
})

test('logging refuses a delegation that cannot verify now, or is not this identity\'s under its current membership and authority', () => {
  const pending = w.advance(withM2(), BASE).held // M2 = {a, b} pending: only a has authority
  const cases = [
    ['not yet valid', start(), delegation({ nbf: NOW + 100, exp: NOW + 3600 }).text, 'not-yet'],
    ['expired', start(), delegation({ nbf: NOW - 3600, exp: NOW - 1 }).text, 'expired'],
    ['another identity', start(), delegation({ identity: 'f'.repeat(64) }).text, 'identity'],
    ['under a membership not current', start(), delegation({ membership: 'e'.repeat(64) }).text, 'membership'],
    ['from a root without authority', pending, delegation({ root: 'b', membership: mId(M2) }).text, 'authority'],
    ['not a delegation', start(), 'x', 'envelope-encoding'],
    ['a head, not a delegation', start(), w.head(start(), NOW), 'type'],
  ]
  for (const [name, held, text, reason] of cases) assert.equal(refused(w.log(held, text, NOW)), reason, name)
  assert.equal(w.log(pending, delegation({ membership: mId(M2) }).text, NOW).ok, true, 'from a root in both, under the pending name')
  assert.equal(w.log(pending, delegation({ secret: key(2) }).text, NOW).ok, true, 'and under the settled name')
  const pendingDead = w.advance(w.advance(admitAll(pending, [['contest', signed('contest', { identity: IDENTITY, record: mId(M2) }, 'a')]]), BASE + 1).held, BASE + WINDOW).held
  assert.equal(refused(w.log(pendingDead, delegation().text, NOW)), 'dead')
  assert.equal(refused(w.log(w.empty(IDENTITY), delegation().text, NOW)), 'unknown-identity')
  assert.throws(() => w.log(start(), delegation().text, -1), { name: 'TypeError', message: /now must be a non-negative integer/ })
})

// Review (round 9's C1): a delegation signed in advance and never shown to the witness must stay revoked, however
// late it is presented. It cannot verify unlogged, and the witness never logs what a kept revocation names.
test('a delegation revoked before it is logged is never logged: by id or by subject key, however late', () => {
  const later = delegation({ nbf: NOW + 40 * DAY, exp: NOW + 41 * DAY }) // pre-signed renewal
  let h = w.revoke(start(), byRoot(subjectOf(key(1))), NOW).held
  assert.deepEqual(revokedIn(h), [], 'no logged delegation names it: nothing in heads')
  assert.equal(refused(w.log(h, later.text, NOW + 40 * DAY)), 'revoked')
  h = w.revoke(start(), byRoot(later.id), NOW).held
  assert.equal(refused(w.log(h, later.text, NOW + 40 * DAY)), 'revoked', 'by id')
})

test('a head carries a kept revocation exactly while it names a logged delegation that is live', () => {
  const d = delegation({ exp: NOW + 1000 })
  let h = logAll(start(), [d.text])
  h = w.revoke(h, byRoot(d.id), NOW).held
  assert.deepEqual(revokedIn(h), [d.id])
  const k = w.revoke(h, byRoot(subjectOf(key(1))), NOW).held
  assert.deepEqual(revokedIn(k), [d.id, subjectOf(key(1))].sort(), 'by id and by subject key')
  assert.deepEqual(revokedIn(k, NOW + 1000 + 59), [d.id, subjectOf(key(1))].sort(), 'until its exp plus skew')
  assert.deepEqual(revokedIn(k, NOW + 1000 + 60), [], 'then it cannot verify')
  // Its root loses authority: M2 = {b} replaces a. While M2 is pending only roots in both have authority: none.
  const M = { ...M2, roots: [rootId('b')] }
  let r = admitAll(k, [['membership', signed('membership', M, 'a')], ['root', rootText('b')], ['membership', signed('membership', M, 'b')]])
  r = w.advance(r, NOW).held
  assert.equal(state(r).pending, true)
  assert.equal(w.head(r, NOW), undefined, 'no root with authority: no head at all (R9)')
  r = w.advance(r, NOW + WINDOW).held
  assert.deepEqual(revokedIn(r, NOW + WINDOW), [], "settled: a's delegations cannot verify, so their revocations leave heads")
  assert.deepEqual(r.revocations.map((x) => x.target).sort(), [d.id, subjectOf(key(1))].sort(), 'but are kept')
})

test('each head entry counts against the root that filed it: a 13th for one root is refused; other roots have their own', () => {
  const pending = w.advance(withM2(), BASE).held
  let h = w.advance(pending, BASE + WINDOW).held // {a, b} settled
  const now = BASE + WINDOW + 10
  const next = now + DAY // a's bucket has one more by then
  const ds = Array.from({ length: 30 }, (_, i) => delegation({ secret: key(10 + i), membership: mId(M2), root: i % 2 ? 'b' : 'a', nbf: now - 10, exp: now + 2 * DAY }))
  h = logAll(h, ds.map((d) => d.text), now)
  for (let i = 0; i < 12; i++) h = w.revoke(h, byRoot(ds[i].id, 'a', now), now).held
  assert.equal(refused(w.revoke(h, byRoot(ds[12].id, 'a', next), next)), 'full')
  // A revocation that names no logged delegation is not a head entry: it is kept, and not counted.
  const r = w.revoke(h, byRoot(target(0), 'a', next), next)
  assert.equal(r.ok, true)
  assert.equal(revokedIn(r.held, next).length, 12)
  for (let i = 12; i < 24; i++) h = w.revoke(h, byRoot(ds[i].id, 'b', now), now).held
  assert.equal(revokedIn(h, now).length, 24)
  // A delegate's revocation of itself counts against its delegation's root.
  const own = ds[25] // root b: already 12
  const self = (() => {
    const { payload } = envelope.seal('revocation', { identity: IDENTITY, target: subjectOf(key(35)), at: next })
    return envelope.wrap(payload, { signature: hex(ed25519.sign(envelope.signedBytes(payload), key(35))) })
  })()
  assert.equal(refused(w.revoke(h, self, next, own.text)), 'full')
})

test('a head never holds more than 64 entries: past them a revocation is refused, never a head', () => {
  // Built directly: 64 head entries over six roots (retired roots' entries stay while their delegations live).
  const d = delegation()
  const logged = w.log(start(), d.text, NOW)
  const entries = Array.from({ length: 64 }, (_, i) => Object.freeze({ text: `t${i}`, target: i === 0 ? d.id : target(i), until: null, root: `${i % 6}`.repeat(64) }))
  const many = Array.from({ length: 64 }, (_, i) => Object.freeze({ ...logged.held.logged[0], delegation: i === 0 ? d.id : target(i) }))
  const full = Object.freeze({ ...logged.held, logged: Object.freeze(many), revocations: Object.freeze(entries) })
  assert.equal(revokedIn(full).length, 64)
  const e = delegation({ secret: key(2) })
  const withE = logAll(full, [e.text])
  assert.equal(refused(w.revoke(withE, byRoot(e.id), NOW)), 'full')
  assert.equal(revokedIn(withE).length, 64)
})

test('revocations are admitted per root by a token bucket: 12 at once, then one more each day', () => {
  let h = start()
  for (let i = 0; i < 12; i++) h = w.revoke(h, byRoot(target(i)), NOW).held
  assert.equal(refused(w.revoke(h, byRoot(target(12)), NOW)), 'quota')
  assert.equal(refused(w.revoke(h, byRoot(target(12), 'a', NOW + DAY - 1), NOW + DAY - 1)), 'quota')
  h = w.revoke(h, byRoot(target(12), 'a', NOW + DAY), NOW + DAY).held
  assert.equal(refused(w.revoke(h, byRoot(target(13), 'a', NOW + DAY), NOW + DAY)), 'quota')
  // Ten days later: ten more, never past twelve.
  const later = NOW + 11 * DAY
  for (let i = 13; i < 23; i++) h = w.revoke(h, byRoot(target(i), 'a', later), later).held
  assert.equal(refused(w.revoke(h, byRoot(target(23), 'a', later), later)), 'quota')
  const much = NOW + 100 * DAY
  for (let i = 23; i < 35; i++) h = w.revoke(h, byRoot(target(i), 'a', much), much).held
  assert.equal(refused(w.revoke(h, byRoot(target(35), 'a', much), much)), 'quota', 'at most 12 saved up')
  // A clock that steps back gives nothing.
  assert.equal(refused(w.revoke(h, byRoot(target(35), 'a', NOW), NOW)), 'quota')
  // A target already kept is accepted unchanged, spending nothing.
  assert.equal(w.revoke(h, byRoot(target(0), 'a', much), much).held, h)
})

test('logged delegations that can no longer verify are dropped at the next logging; at most MAX_RECORDS live', () => {
  const d = delegation({ exp: NOW + 100 })
  let h = logAll(start(), [d.text])
  h = logAll(h, [delegation({ secret: key(3), exp: NOW + 3600 }).text], NOW + 100 + 60)
  assert.equal(h.logged.length, 1, 'the expired one is gone')
  const full = Object.freeze({ ...h, logged: Object.freeze(Array.from({ length: 256 }, () => h.logged[0])) })
  assert.equal(refused(w.log(full, delegation({ secret: key(4) }).text, NOW + 200)), 'full')
})

test('live means both: under the settled membership or its pending successor, and from a root with authority', () => {
  // {a, b} settled at epoch 2; a delegation from a under it, logged and revoked by b.
  let h = w.advance(w.advance(withM2(), BASE).held, BASE + WINDOW).held
  const now = BASE + WINDOW + 10
  const d = delegation({ membership: mId(M2), nbf: now - 10, exp: now + 10 * DAY })
  h = logAll(h, [d.text], now)
  h = w.revoke(h, byRoot(d.id, 'b', now), now).held
  assert.deepEqual(revokedIn(h, now), [d.id])
  // A change removing a is pending: M2 is still settled, but only b, in both, has authority. a's delegation cannot
  // verify, so its revocation leaves heads.
  const without = { ...M2, epoch: 3, prev: mId(M2), roots: [rootId('b'), rootId('c')].sort() }
  let p = admitAll(h, [['membership', signed('membership', without, 'a')], ['membership', signed('membership', without, 'b')], ['root', rootText('c')],
    ['membership', signed('membership', without, 'c')]])
  p = w.advance(p, now).held
  assert.equal(state(p).pending, true)
  assert.deepEqual(revokedIn(p, now), [], 'its root lost authority')
  // Instead a change keeping a settles: a keeps authority, but M2 is no longer current, so the delegation cannot
  // verify, and its revocation leaves heads.
  const keeping = { ...M2, epoch: 3, prev: mId(M2), roots: [rootId('a'), rootId('b'), rootId('c')].sort() }
  let k = admitAll(h, [['membership', signed('membership', keeping, 'a')], ['membership', signed('membership', keeping, 'b')], ['root', rootText('c')],
    ['membership', signed('membership', keeping, 'c')]])
  k = w.advance(k, now).held
  assert.deepEqual(revokedIn(k, now), [d.id], 'while pending, M2 is still current and a is in both')
  k = w.advance(k, now + WINDOW).held
  assert.equal(state(k).settled, mId(keeping))
  assert.ok(state(k).authority.includes(rootId('a')))
  assert.deepEqual(revokedIn(k, now + WINDOW), [], 'its membership is no longer current')
})

test('a delegation under the pending successor, logged and revoked while it is pending, is in heads', () => {
  const pending = w.advance(withM2(), BASE).held // M2 = {a, b} pending; a, in both, has authority
  const d = delegation({ membership: mId(M2) })
  let h = logAll(pending, [d.text])
  h = w.revoke(h, byRoot(d.id), NOW).held
  assert.deepEqual(revokedIn(h), [d.id])
})

test("a root's revocation given with the delegation it names is in heads until that delegation expires", () => {
  const d = delegation({ exp: NOW + 1000 })
  let h = logAll(start(), [d.text])
  h = w.revoke(h, byRoot(d.id), NOW, d.text).held
  assert.equal(h.revocations[0].until, NOW + 1000 + 60)
  assert.deepEqual(revokedIn(h), [d.id])
  assert.deepEqual(revokedIn(h, NOW + 1000 + 59), [d.id])
})

test('a foreign error opening a delegation to log (patched built-ins) is refused, never thrown', () => {
  const s = start()
  const text = delegation().text
  const original = Uint8Array.prototype.fill
  Uint8Array.prototype.fill = function () { throw new Error('patched') }
  let out
  try { out = refused(w.log(s, text, NOW)) } catch (e) { out = 'threw ' + e } finally { Uint8Array.prototype.fill = original }
  assert.equal(out, 'envelope-encoding')
})

test("each root has its own bucket: one root's revocations leave another's as they were", () => {
  let h = w.advance(w.advance(withM2(), BASE).held, BASE + WINDOW).held // {a, b} settled
  const now = BASE + WINDOW + 10
  for (let i = 0; i < 12; i++) h = w.revoke(h, byRoot(target(i), 'a', now), now).held
  h = w.revoke(h, byRoot(target(12), 'b', now), now).held
  assert.equal(refused(w.revoke(h, byRoot(target(13), 'a', now), now)), 'quota', "a's bucket is still empty")
  assert.deepEqual(h.buckets.map((x) => [x.root, x.tokens]), [[rootId('a'), 0], [rootId('b'), 11]])
})
