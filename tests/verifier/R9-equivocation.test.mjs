// R9 and decision 10: a relying party that passes the last head it accepted for the identity (`lastHead`) refuses a
// head the witness could not honestly have signed after it: an older one (stale), one whose settled epoch is lower,
// or equal with another settled membership or another pending successor, or one more with another settled membership
// than the pending successor (equivocation).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { ed25519 } from '@noble/curves/ed25519.js'
import { verifier as verifierModule, envelope, root as rootModule } from '../impl.mjs'
import { make, KEY, RP_ID, ORIGIN } from '../assertion/helpers.mjs'

const { verifier } = verifierModule
const hex = (b) => Buffer.from(b).toString('hex')
const NOW = 1_800_000_100
const OLD = Uint8Array.from({ length: 32 }, (_, i) => 11 + i)
const NEW = Uint8Array.from({ length: 32 }, (_, i) => 51 + i)
const key = (s) => hex(ed25519.getPublicKey(s))
const APP = Uint8Array.from({ length: 32 }, (_, i) => 60 + i)
const AUD = 'https://app.example'
// The witness rotated keys: the old one's window ended 20 s ago, the new one's began 30 s ago.
const CONFIG = Object.freeze({ rpId: RP_ID, origin: ORIGIN, audience: AUD,
  witnessKeys: [{ key: key(OLD), nbf: 0, exp: NOW - 20 }, { key: key(NEW), nbf: NOW - 30, exp: 1_900_000_000 }],
  skew: 60, maxLifetime: 2_592_000, maxStaleness: 86_400, maxClaimAge: 300 })
const v = verifier(CONFIG)

const rootText = envelope.wrap(envelope.seal('root', { pub: KEY, rp_id: RP_ID }).payload)
const ROOT = rootModule.checkRoot(rootText, { rpId: RP_ID }).id
const I = rootModule.identityOf(ROOT)
const P = '1'.repeat(64) // a pending successor of the identity's first membership
const Q = '2'.repeat(64) // a rival of P
const R = '3'.repeat(64) // a successor of P
const X = 'f'.repeat(64) // another root, sorted after ROOT
const WIDE = [ROOT, X].sort()

function delegation (membership) {
  const { payload, id } = envelope.seal('delegation', { identity: I, membership, root: ROOT, subject: key(APP), aud: AUD,
    scopes: ['post'], nbf: NOW - 10, exp: NOW + 86_000 })
  const subject = hex(ed25519.sign(Buffer.concat([Buffer.from('muid/v1/accept\n'), Buffer.from(id, 'hex')]), APP))
  return envelope.wrap(payload, { root: make({ covers: [id] }), subject })
}
const DEL = { [I]: delegation(I), [P]: delegation(P), [Q]: delegation(Q), [R]: delegation(R) }
// R10: each delegation's logged record, signed by the current witness key.
function loggedOf (text) {
  const { payload } = envelope.seal('logged', { identity: I, delegation: envelope.open(text, 'delegation').id, at: NOW - 10 })
  return envelope.wrap(payload, { signature: hex(ed25519.sign(envelope.signedBytes(payload), NEW)), witness: key(NEW) })
}

function head (epoch, memberships, at, { secret = at < NOW - 20 ? OLD : NEW, identity = I, authority = [ROOT], revoked = [] } = {}) {
  const { payload } = envelope.seal('head', { identity, epoch, memberships, authority, revoked, at })
  return envelope.wrap(payload, { signature: hex(ed25519.sign(envelope.signedBytes(payload), secret)), witness: key(secret) })
}

// The head presented, under a delegation whose membership it carries, with or without the relying party's last head.
function verify (presented, lastHead, membership) {
  const call = { now: NOW, scope: 'post', revoked: [], ...(lastHead === undefined ? {} : { lastHead }) }
  const r = v.verifyDelegation({ delegation: DEL[membership], root: rootText, head: presented, logged: loggedOf(DEL[membership]) }, call)
  return r.ok ? { ok: true } : { ...r }
}
const refused = (reason) => ({ ok: false, reason })

test('an honest witness\'s later heads are accepted after any earlier one', () => {
  const cases = [
    ['the same head again', head(1, [I], NOW - 10), head(1, [I], NOW - 10), I],
    ['a later head of the same state', head(1, [I], NOW - 10), head(1, [I], NOW - 50), I],
    ['a successor becomes pending', head(1, [I, P], NOW - 10), head(1, [I], NOW - 50), I],
    ['the pending successor stays pending', head(1, [I, P], NOW - 10), head(1, [I, P], NOW - 50), P],
    ['the pending successor settles', head(2, [P], NOW - 10), head(1, [I, P], NOW - 50), P],
    ['it settles and the next is pending', head(2, [P, R], NOW - 10), head(1, [I, P], NOW - 50), R],
    ['two epochs later', head(3, [R], NOW - 10), head(1, [I], NOW - 50), R],
    ['one epoch on, the last head having seen nothing pending', head(2, [P], NOW - 10), head(1, [I], NOW - 50), P],
    ['two epochs on from a pending successor', head(3, [R], NOW - 10), head(1, [I, P], NOW - 50), R],
    ['a successor becomes pending: authority shrinks to the shared roots', head(1, [I, P], NOW - 10, { authority: [ROOT] }),
      head(1, [I], NOW - 50, { authority: WIDE }), I],
    ['it settles: authority grows to the successor\'s roots', head(2, [P], NOW - 10, { authority: WIDE }), head(1, [I, P], NOW - 50), P],
    ['it settles and the next is pending: authority is the new shared roots', head(2, [P, R], NOW - 10),
      head(1, [I, P], NOW - 50, { authority: WIDE }), P],
    ['the same head again, at the same time', head(1, [I, P], NOW - 10), head(1, [I, P], NOW - 10), I],
    ['one epoch on, unseen while pending: authority may shrink', head(2, [P], NOW - 10), head(1, [I], NOW - 50, { authority: WIDE }), P],
    ['two epochs on from a pending successor: authority may shrink', head(3, [R], NOW - 10),
      head(1, [I, P], NOW - 50, { authority: WIDE }), R],
  ]
  for (const [name, presented, last, membership] of cases) {
    assert.deepEqual(verify(presented, last, membership), { ok: true }, name)
  }
})

test('equivocation: a lower settled epoch, another settled membership, or another pending successor', () => {
  const cases = [
    ['a lower settled epoch', head(1, [I, P], NOW - 10), head(2, [P], NOW - 50), P],
    ['the same epoch, another settled membership', head(2, [Q], NOW - 10), head(2, [P], NOW - 50), P],
    ['the pending successor gone', head(1, [I], NOW - 10), head(1, [I, P], NOW - 50), I],
    ['a rival pending successor', head(1, [I, Q], NOW - 10), head(1, [I, P], NOW - 50), I],
    ['the next epoch settles another than the pending successor', head(2, [Q], NOW - 10), head(1, [I, P], NOW - 50), Q],
    ['a settled membership again at a later epoch', head(3, [P], NOW - 10), head(2, [P], NOW - 50), P],
    ['the pending successor settled two epochs on', head(3, [P], NOW - 10), head(1, [I, P], NOW - 50), P],
    ['a membership pending at another epoch than it settled', head(2, [Q, P], NOW - 10), head(2, [P], NOW - 50), Q],
    ['the same memberships, more authority', head(1, [I], NOW - 10, { authority: WIDE }), head(1, [I], NOW - 50), I],
    ['the same memberships, less authority', head(1, [I], NOW - 10), head(1, [I], NOW - 50, { authority: WIDE }), I],
    ['a successor becomes pending and authority grows', head(1, [I, P], NOW - 10, { authority: WIDE }), head(1, [I], NOW - 50), I],
    ['it settles and authority shrinks', head(2, [P], NOW - 10), head(1, [I, P], NOW - 50, { authority: WIDE }), P],
    ['the settled epoch falls with a pending successor', head(1, [I, P], NOW - 10), head(2, [P], NOW - 50), P],
    ['at the same time, inconsistent in either order', head(1, [I, Q], NOW - 10), head(1, [I, P], NOW - 10), I],
  ]
  for (const [name, presented, last, membership] of cases) {
    assert.deepEqual(verify(presented, last, membership), refused('equivocation'), name)
  }
})

test('stale, not equivocation: at the same time, a head the witness could have signed before the last one', () => {
  // A change and its anchor can fall in the same second, so an honest witness signs both heads with one `at`.
  assert.deepEqual(verify(head(1, [I], NOW - 10), head(1, [I, P], NOW - 10), I), refused('stale'), 'before the successor was pending')
  assert.deepEqual(verify(head(1, [I, P], NOW - 10), head(2, [P], NOW - 10), P), refused('stale'), 'before it settled')
  assert.deepEqual(verify(head(1, [I], NOW - 10, { authority: WIDE }), head(1, [I, P], NOW - 10), I), refused('stale'),
    'before authority shrank to the shared roots')
})

test('stale: a head older than the last one accepted, even a consistent one', () => {
  assert.deepEqual(verify(head(1, [I], NOW - 19), head(1, [I], NOW - 10), I), refused('stale'))
  assert.deepEqual(verify(head(1, [I], NOW - 11), head(1, [I], NOW - 10), I), refused('stale'), 'one second older')
})

test('identity: a head for another identity than the last head\'s is refused, never thrown', () => {
  const other = rootModule.identityOf('f'.repeat(64))
  assert.deepEqual(verify(head(1, [I], NOW - 10), head(1, [other], NOW - 50, { identity: other }), I), refused('identity'))
})

test('the last head is checked at its own time, so it stays usable after the witness rotates keys', () => {
  const last = head(1, [I], NOW - 50) // signed by the old key, whose window has ended
  assert.deepEqual(verify(head(1, [I], NOW - 10), last, I), { ok: true })
  assert.deepEqual(verify(last, undefined, I), refused('head'), 'presented now, the same head is refused')
})

test('a last head that is not a pinned head is a programming error', () => {
  const unpinned = Uint8Array.from({ length: 32 }, (_, i) => 200 - i)
  for (const lastHead of ['x', null, 1, head(1, [I], NOW - 50, { secret: unpinned }), DEL[I], head(0, [I], NOW - 50)]) {
    assert.throws(() => verify(head(1, [I], NOW - 10), lastHead, I), { name: 'TypeError' }, String(lastHead).slice(0, 40))
  }
})

test('F3: a last head only removes trust, over every pair of a pool of heads', () => {
  const pool = [head(1, [I], NOW - 50), head(1, [I], NOW - 10), head(1, [I, P], NOW - 40), head(1, [I, Q], NOW - 5),
    head(2, [P], NOW - 30), head(2, [P, R], NOW - 3), head(2, [Q], NOW - 25), head(3, [R], NOW - 1)]
  let refusedByLast = 0
  for (const presented of pool) {
    for (const last of pool) {
      for (const membership of [I, P, R]) {
        const without = verify(presented, undefined, membership)
        const withLast = verify(presented, last, membership)
        if (withLast.ok) assert.ok(without.ok, 'an accept with a last head is an accept without one')
        if (without.ok && !withLast.ok) refusedByLast++
      }
    }
  }
  assert.ok(refusedByLast > 10, 'the last head refuses some heads accepted without it')
})

// Heads of one second are ordered by what they revoke as well: the witness only adds revocations within a second (an
// entry lapses with time), so a head of the same `at` that drops one the last head carried was signed before it.
test('at the same time, a head without a revocation the last head carried is stale; one with more follows it', () => {
  const T = NOW - 10
  const [x, y, z] = ['7'.repeat(64), '8'.repeat(64), '9'.repeat(64)]
  const at = (revoked) => head(1, [I], T, { revoked })
  assert.deepEqual(verify(at([]), at([x]), I), refused('stale'), 'the revocation dropped')
  assert.deepEqual(verify(at([x]), at([x, y]), I), refused('stale'), 'one of several dropped')
  assert.deepEqual(verify(at([x, y, z]), at([x]), I), { ok: true }, 'several added in one second')
  assert.deepEqual(verify(at([x]), at([]), I), { ok: true }, 'the honest order')
  assert.deepEqual(verify(at([y]), at([x]), I), refused('equivocation'), 'each without one the other carries')
  // A second later the revocation may have lapsed: no order is implied.
  assert.deepEqual(verify(head(1, [I], T + 1), at([x]), I), { ok: true }, 'a later head without it')
})

test('the delegation itself: revoked by id or by subject key in a head, then presented under an earlier head of that second', () => {
  const T = NOW - 10
  const id = envelope.open(DEL[I], 'delegation').id
  for (const target of [id, key(APP)]) {
    const revoking = head(1, [I], T, { revoked: [target] })
    assert.deepEqual(verify(revoking, undefined, I), refused('revoked'))
    assert.deepEqual(verify(head(1, [I], T), revoking, I), refused('stale'), target === id ? 'by id' : 'by subject key')
  }
})

// R10: a head carries only revocations naming a live logged delegation, so one leaves with its membership or its
// root's authority. Within one second, revocations are ordered only between heads of the same memberships.
test('at the same time, a revocation may leave with a membership change: no order is implied by it', () => {
  const T = NOW - 10
  const x = '7'.repeat(64)
  const turning = head(1, [I], T, { authority: WIDE, revoked: [x] })
  assert.deepEqual(verify(head(1, [I, P], T), turning, I), { ok: true }, 'a successor turns pending: X loses authority')
  const pending = head(1, [I, P], T, { revoked: [x] })
  assert.deepEqual(verify(head(2, [P], T), pending, P), { ok: true }, 'the successor settles: the first membership goes')
  // The control: the same memberships, the same second, a revocation dropped.
  assert.deepEqual(verify(head(1, [I, P], T), pending, I), refused('stale'), 'under the same memberships')
})
