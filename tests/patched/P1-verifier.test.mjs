// §4 residual, systematically (tests/patched/sweep.mjs): code that patches a built-in after the core has loaded
// cannot make the verifier accept what it refuses. A battery of record sets that must be refused, and two valid ones,
// is verified under each patched built-in: none may be accepted; a valid set may fail closed.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { ed25519 } from '@noble/curves/ed25519.js'
import { verifier as verifierModule, envelope, root as rootModule } from '../impl.mjs'
import { make, KEY, RP_ID, ORIGIN } from '../assertion/helpers.mjs'
import { sweep, TARGETS } from './sweep.mjs'

const hex = (b) => Buffer.from(b).toString('hex')
const NOW = 1_800_000_100
const W = Uint8Array.from({ length: 32 }, (_, i) => 140 + i)
const STRANGER = Uint8Array.from({ length: 32 }, (_, i) => 90 + i)
const WITNESS = hex(ed25519.getPublicKey(W))
const AUD = 'https://app.example'
const URL_ = 'https://app.example/posts'
const v = verifierModule.verifier({ rpId: RP_ID, origin: ORIGIN, audience: AUD, witnessKeys: [{ key: WITNESS, nbf: 0, exp: 1_900_000_000 }],
  skew: 60, maxLifetime: 2_592_000, maxStaleness: 86_400, maxClaimAge: 300 })

const rootText = envelope.wrap(envelope.seal('root', { pub: KEY, rp_id: RP_ID }).payload)
const ROOT = rootModule.checkRoot(rootText, { rpId: RP_ID }).id
const IDENTITY = rootModule.identityOf(ROOT)
const APP = Uint8Array.from({ length: 32 }, (_, i) => 60 + i)
const SUBJECT = hex(ed25519.getPublicKey(APP))

const signedBy = (type, body, secret = W) => {
  const { payload } = envelope.seal(type, body)
  return envelope.wrap(payload, { signature: hex(ed25519.sign(envelope.signedBytes(payload), secret)), witness: hex(ed25519.getPublicKey(secret)) })
}
function delegation (over = {}, { consentBy = APP, rootSecret } = {}) {
  const body = { agent: 'worker', identity: IDENTITY, membership: IDENTITY, root: ROOT, subject: SUBJECT, aud: AUD, scopes: ['post'],
    nbf: NOW - 10, exp: NOW + 86_000, ...over }
  const { payload, id } = envelope.seal('delegation', body)
  const consent = hex(ed25519.sign(Buffer.concat([Buffer.from('muid/v1/accept\n'), Buffer.from(id, 'hex')]), consentBy))
  return { text: envelope.wrap(payload, { root: make({ covers: [id], ...(rootSecret ? { secret: rootSecret } : {}) }), subject: consent }), id }
}
const head = (over = {}, secret) => signedBy('head', { identity: IDENTITY, epoch: 1, memberships: [IDENTITY], authority: [ROOT], revoked: [], at: NOW - 100, ...over }, secret)
const logged = (d, over = {}) => signedBy('logged', { identity: IDENTITY, delegation: d.id, at: NOW - 5, ...over })
const claimOf = (d, over = {}, secret = APP) => {
  const { payload } = envelope.seal('claim', { delegation: d.id, scope: 'post', htm: 'POST', htu: URL_, at: NOW - 5, data: { text: 'x' }, ...over })
  return envelope.wrap(payload, { signature: hex(ed25519.sign(envelope.signedBytes(payload), secret)) })
}

const D = delegation()
const CALL = { now: NOW, scope: 'post', revoked: [] }
const CLAIM_CALL = { ...CALL, method: 'POST', url: URL_ }
const set = (over = {}) => ({ delegation: D.text, root: rootText, head: head(), logged: logged(D), ...over })
const tamper = (text) => text.replace('"exp\\":', '"exp\\":1')

// [name, 'delegation' | 'claim', records, call, must be refused]
const BATTERY = [
  ['valid', 'delegation', set(), CALL, false],
  ['valid claim', 'claim', { ...set(), claim: claimOf(D) }, CLAIM_CALL, false],
  ['consent by another key', 'delegation', (() => { const d = delegation({}, { consentBy: STRANGER }); return set({ delegation: d.text, logged: logged(d) }) })(), CALL, true],
  ['root assertion by another passkey', 'delegation', (() => { const d = delegation({}, { rootSecret: Uint8Array.from({ length: 32 }, (_, i) => 7 + i) }); return set({ delegation: d.text, logged: logged(d) }) })(), CALL, true],
  ['tampered payload', 'delegation', set({ delegation: tamper(D.text) }), CALL, true],
  ['revoked by id in the head', 'delegation', set({ head: head({ revoked: [D.id] }) }), CALL, true],
  ['revoked by subject key in the call', 'delegation', set(), { ...CALL, revoked: [SUBJECT] }, true],
  ['revoked by agent in the head', 'delegation', set({ head: head({ revoked: [rootModule.agentIdOf(IDENTITY, 'worker')] }) }), CALL, true],
  ['expired', 'delegation', set({ head: head({ at: NOW + 86_000 }) }), { ...CALL, now: NOW + 86_010 }, true],
  ['not yet valid', 'delegation', (() => { const d = delegation({ nbf: NOW + 1000, exp: NOW + 5000 }); return set({ delegation: d.text, logged: logged(d, { at: NOW + 1000 }) }) })(), CALL, true],
  ['stale head', 'delegation', set({ head: head({ at: NOW - 90_000 }) }), CALL, true],
  ['head by an unpinned key', 'delegation', set({ head: head({}, STRANGER) }), CALL, true],
  ['head for another identity', 'delegation', set({ head: head({ identity: 'ab'.repeat(32) }) }), CALL, true],
  ['root without authority', 'delegation', set({ head: head({ authority: ['cd'.repeat(32)] }) }), CALL, true],
  ['another audience', 'delegation', (() => { const d = delegation({ aud: 'https://other.example' }); return set({ delegation: d.text, logged: logged(d) }) })(), CALL, true],
  ['a scope not granted', 'delegation', set(), { ...CALL, scope: 'admin' }, true],
  ['not logged', 'delegation', set({ logged: logged(delegation({ scopes: ['read'] })) }), CALL, true],
  ['claim by another key', 'claim', { ...set(), claim: claimOf(D, {}, STRANGER) }, CLAIM_CALL, true],
  ['claim for another URL', 'claim', { ...set(), claim: claimOf(D) }, { ...CLAIM_CALL, url: URL_ + '/x' }, true],
  ['claim too old', 'claim', { ...set(), claim: claimOf(D, { at: NOW - 400 }) }, CLAIM_CALL, true],
]

const CASES = BATTERY.map(([name, kind, records, call]) => ({ name, run: () => (kind === 'claim' ? v.verifyClaim(records, call) : v.verifyDelegation(records, call)) }))
const describe = (r) => (r !== null && typeof r === 'object' && r.ok === true ? 'accepted' : 'refused')

test('no patched built-in makes the verifier accept a record set it refuses; a valid one may fail closed', () => {
  assert.ok(TARGETS.length > 250, `${TARGETS.length} built-ins`)
  const { base, changed, failedClosed } = sweep(CASES, describe, (r) => r === 'refused')
  for (const [i, [name, , , , refuse]] of BATTERY.entries()) assert.equal(base[i], refuse ? 'refused' : 'accepted', `unpatched: ${name}`)
  assert.deepEqual(changed, [])
  // Anti-vacuity: patches do reach the verifier's libraries (noble does not capture its built-ins), and make a valid
  // set fail closed.
  assert.ok(failedClosed >= 50, `only ${failedClosed} results failed closed`)
})
