// F5's time and revocation rules against an executable model written from the spec (model/timing.mjs): the
// delegation's window and lifetime (D1, D2), the head's key window and freshness (R9, minHeadAt, lastHead), heads of
// one second (decision 10), revocation in the head, the call or the last head, and the logged record's windows
// (R10). A verifier with small windows (skew 2 s, lifetime 12 s, staleness 8 s, two witness keys whose windows
// overlap) puts every boundary within reach of generated times; verifyDelegation must refuse with the model's reason
// or accept as it does, and verifyHead must agree with the model's head checks.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import fc from 'fast-check'
import { ed25519 } from '@noble/curves/ed25519.js'
import { verifier as verifierModule, envelope, root as rootModule } from '../impl.mjs'
import { make, KEY, RP_ID, ORIGIN } from '../assertion/helpers.mjs'
import { decide, headReason, follows } from '../../model/timing.mjs'
import { runs } from '../runs.mjs'

const { verifier } = verifierModule
const hex = (b) => Buffer.from(b).toString('hex')
const PINNED = 20261109
const SEED = Number(process.env.FC_SEED ?? PINNED)
const USUAL = 600
const RUNS = runs(USUAL)

const B = 1_800_000_000
const SECRETS = [Uint8Array.from({ length: 32 }, (_, i) => 140 + i), Uint8Array.from({ length: 32 }, (_, i) => 170 + i)]
// Model keys, in model time; the pinned keys are the same windows from B.
const KEYS = [{ nbf: 0, exp: 20 }, { nbf: 15, exp: 1000 }]
const MODEL = { skew: 2, maxLifetime: 12, maxStaleness: 8 }
const AUD = 'https://app.example'
const v = verifier({ rpId: RP_ID, origin: ORIGIN, audience: AUD, maxClaimAge: 300, ...MODEL,
  witnessKeys: KEYS.map((k, i) => ({ key: hex(ed25519.getPublicKey(SECRETS[i])), nbf: B + k.nbf, exp: B + k.exp })) })

const rootText = envelope.wrap(envelope.seal('root', { pub: KEY, rp_id: RP_ID }).payload)
const ROOT = rootModule.checkRoot(rootText, { rpId: RP_ID }).id
const IDENTITY = rootModule.identityOf(ROOT)
const APP = Uint8Array.from({ length: 32 }, (_, i) => 60 + i)
const SUBJECT = hex(ed25519.getPublicKey(APP))
const OTHER = 'e'.repeat(64)

const memo = new Map()
const once = (k, f) => { if (!memo.has(k)) memo.set(k, f()); return memo.get(k) }

const delegation = ({ nbf, exp }) => once(`d ${nbf} ${exp}`, () => {
  const body = { agent: 'worker', identity: IDENTITY, membership: IDENTITY, root: ROOT, subject: SUBJECT, aud: AUD, scopes: ['post'], nbf: B + nbf, exp: B + exp }
  const { payload, id } = envelope.seal('delegation', body)
  const subject = hex(ed25519.sign(Buffer.concat([Buffer.from('muid/v1/accept\n'), Buffer.from(id, 'hex')]), APP))
  return { text: envelope.wrap(payload, { root: make({ covers: [id] }), subject }), id }
})
const signed = (type, body, k) => once(`${type} ${JSON.stringify(body)} ${k}`, () => {
  const { payload } = envelope.seal(type, body)
  return envelope.wrap(payload, { signature: hex(ed25519.sign(envelope.signedBytes(payload), SECRETS[k])), witness: hex(ed25519.getPublicKey(SECRETS[k])) })
})
const real = (list, d) => [...new Set(list.map((x) => (x === 'D' ? d.id : x === 'S' ? SUBJECT : OTHER)))].sort()
const headText = (h, d) => signed('head', { identity: IDENTITY, epoch: 1, memberships: [IDENTITY], authority: [ROOT], revoked: real(h.revoked, d), at: B + h.at }, h.k)

// A key whose window holds t (the relying party's last head was signed in its key's window), or none.
const keyAt = (t) => KEYS.findIndex((k) => k.nbf <= t && t < k.exp)

const revokedList = fc.oneof({ arbitrary: fc.constant([]), weight: 3 }, { arbitrary: fc.subarray(['D', 'S', 'X']), weight: 2 })
const call = fc.integer({ min: 4, max: 36 }).chain((now) => fc.record({
  now: fc.constant(now),
  d: fc.tuple(fc.integer({ min: -14, max: 4 }), fc.integer({ min: -1, max: 14 })).map(([a, len]) => ({ nbf: now + a, exp: now + a + len })),
  head: fc.record({ at: fc.integer({ min: now - 10, max: now + 4 }), k: fc.nat(1), revoked: revokedList }),
  logged: fc.option(fc.record({ dt: fc.integer({ min: -4, max: 16 }), k: fc.nat(1) }), { freq: 6 }),
  revoked: revokedList,
  minHeadAt: fc.option(fc.integer({ min: -3, max: 1 }), { freq: 2 }),
  // The last head: often of the head's own second, with revocations, so that heads of one second meet.
  last: fc.option(fc.record({ dt: fc.integer({ min: -2, max: 1 }), revoked: fc.subarray(['D', 'S', 'X']) }), { freq: 2 }),
})).map((c) => {
  const head = { ...c.head, key: KEYS[c.head.k] }
  const logged = c.logged && { at: c.d.nbf + c.logged.dt, k: c.logged.k, key: KEYS[c.logged.k] }
  const lastAt = head.at + (c.last?.dt ?? 0)
  const last = c.last && keyAt(lastAt) >= 0 ? { at: lastAt, k: keyAt(lastAt), revoked: c.last.revoked } : undefined
  return { ...c, head, logged, minHeadAt: c.minHeadAt === null ? undefined : head.at + c.minHeadAt, last }
})

function impl (c) {
  const d = delegation(c.d)
  const records = { delegation: d.text, root: rootText, head: headText(c.head, d) }
  if (c.logged) records.logged = signed('logged', { identity: IDENTITY, delegation: d.id, at: B + c.logged.at }, c.logged.k)
  const ctx = { now: B + c.now, scope: 'post', revoked: real(c.revoked, d) }
  if (c.minHeadAt !== undefined) ctx.minHeadAt = Math.max(0, B + c.minHeadAt)
  if (c.last) ctx.lastHead = headText(c.last, d)
  const r = v.verifyDelegation(records, ctx)
  const h = v.verifyHead(records.head, ctx)
  return { reason: r.ok ? 'ok' : r.reason, head: h.ok ? null : h.reason }
}

test('verifyDelegation gives the model\'s answer, and verifyHead its head checks', () => {
  fc.assert(fc.property(call, (c) => {
    const got = impl(c)
    assert.equal(got.reason, decide(MODEL, c), JSON.stringify(c))
    assert.equal(got.head, headReason(MODEL, c), JSON.stringify(c))
  }), { seed: SEED, numRuns: RUNS })
})

// The generator, sampled at the usual count from the pinned seed and decided by the model alone (so it holds at any
// FC_RUNS): it reaches acceptance and every reason the model gives.
test('the generator reaches acceptance and every reason (anti-vacuity)', () => {
  const reached = new Set(fc.sample(call, { seed: PINNED, numRuns: USUAL }).map((c) => decide(MODEL, c)))
  assert.deepEqual([...reached].sort(), ['equivocation', 'expired', 'head', 'lifetime', 'logged', 'not-yet', 'ok', 'revoked', 'stale'])
})

// Traces: an honest witness signs heads as time passes, revoking the delegation's id, its subject key or another
// entry, and dropping a revocation of the id once the delegation has expired by more than `skew` (decision 12 (b));
// the delegate presents any head signed so far (an attacker may replay an old one), and the relying party remembers
// the newest head that verifies alone (F6, §7). At every presentation verifyDelegation gives the model's answer and
// verifyHead its head checks; once the memory holds a head revoking the delegation, nothing is accepted again; and an
// honest witness's heads are never refused as equivocation.
const TRACES = 150
const D0 = { nbf: 4, exp: 16 }
const LOGGED = { at: 4, k: 0, key: KEYS[0] }
const traceStep = fc.record({ dt: fc.nat(3), act: fc.constantFrom('sign', 'present', 'present', 'revoke'), what: fc.constantFrom('D', 'S', 'X'), pick: fc.nat() })

function trace (steps, check, reached = new Set()) {
  let now = 4
  let revoked = []
  const heads = []
  let last
  let revokedSeen = false
  const sign = () => {
    const k = keyAt(now)
    if (k < 0) return
    if (now > D0.exp + MODEL.skew) revoked = revoked.filter((x) => x !== 'D')
    heads.push({ at: now, k, key: KEYS[k], revoked: [...revoked].sort() })
  }
  sign()
  for (const { dt, act, what, pick } of steps) {
    now += dt
    if (act === 'revoke') { if (!revoked.includes(what)) revoked = [...revoked, what]; sign(); continue }
    if (act === 'sign') { sign(); continue }
    const head = heads[pick % heads.length]
    const c = { now, d: D0, head, logged: LOGGED, revoked: [], minHeadAt: undefined, last }
    const want = decide(MODEL, c)
    check(c, want)
    reached.add(want)
    if (revokedSeen) reached.add('after a remembered revocation')
    if (revokedSeen) assert.notEqual(want, 'ok', `accepted after the memory held a revocation: ${JSON.stringify(c)}`)
    assert.notEqual(want, 'equivocation', `an honest witness's head refused as equivocation: ${JSON.stringify(c)}`)
    if (headReason(MODEL, c) === null && (!last || follows(head, last))) {
      last = { at: head.at, k: head.k, revoked: head.revoked }
      if (last.revoked.includes('D') || last.revoked.includes('S')) revokedSeen = true
    }
  }
}

test('traces: the verifier agrees with the model at every presentation, and a remembered revocation holds', () => {
  fc.assert(fc.property(fc.array(traceStep, { minLength: 1, maxLength: 16 }), (steps) => trace(steps, (c, want) => {
    const got = impl(c)
    assert.equal(got.reason, want, JSON.stringify(c))
    assert.equal(got.head, headReason(MODEL, c), JSON.stringify(c))
  })), { seed: SEED, numRuns: runs(TRACES) })
})

// The trace generator, sampled at the usual count from the pinned seed and decided by the model alone.
test('the trace generator reaches acceptance, staleness, expiry, revocation and a remembered revocation (anti-vacuity)', () => {
  const reached = new Set()
  for (const steps of fc.sample(fc.array(traceStep, { minLength: 1, maxLength: 16 }), { seed: PINNED, numRuns: TRACES })) trace(steps, () => {}, reached)
  for (const r of ['ok', 'stale', 'head', 'expired', 'revoked', 'after a remembered revocation']) assert.ok(reached.has(r), r)
})
