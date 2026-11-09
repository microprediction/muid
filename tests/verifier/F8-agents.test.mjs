// Decision 13, Part A: a delegation names its agent, a light identity whose id is derived from the identity and the
// name. The verifier reports that id, and a head's, the call's or the last head's `revoked` naming it refuses every
// delegation with that name, whatever its key or window: a retired name is never reissued.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { ed25519 } from '@noble/curves/ed25519.js'
import { verifier as verifierModule, envelope, root as rootModule } from '../impl.mjs'
import { make, KEY, RP_ID, ORIGIN } from '../assertion/helpers.mjs'

const { verifier } = verifierModule
const hex = (b) => Buffer.from(b).toString('hex')
const NOW = 1_800_000_100
const W = Uint8Array.from({ length: 32 }, (_, i) => 140 + i)
const WITNESS = hex(ed25519.getPublicKey(W))
const AUD = 'https://app.example'
const URL_ = 'https://app.example/posts'
const v = verifier({ rpId: RP_ID, origin: ORIGIN, audience: AUD, witnessKeys: [{ key: WITNESS, nbf: 0, exp: 1_900_000_000 }],
  skew: 60, maxLifetime: 2_592_000, maxStaleness: 86_400, maxClaimAge: 300 })

const rootText = envelope.wrap(envelope.seal('root', { pub: KEY, rp_id: RP_ID }).payload)
const ROOT = rootModule.checkRoot(rootText, { rpId: RP_ID }).id
const IDENTITY = rootModule.identityOf(ROOT)
// Computed here from the specified bytes, not by the implementation.
const agentId = (identity, agent) => createHash('sha256').update(Buffer.concat([Buffer.from('muid-agent\n'), Buffer.from(identity, 'hex'), Buffer.from(agent)])).digest('hex')

const signedBy = (type, body) => {
  const { payload } = envelope.seal(type, body)
  return envelope.wrap(payload, { signature: hex(ed25519.sign(envelope.signedBytes(payload), W)), witness: WITNESS })
}
// A delegation to a fresh key under `agent`, with its logged record.
function delegation (agent, seed = 1, over = {}) {
  const secret = Uint8Array.from({ length: 32 }, (_, i) => (seed * 31 + i) % 256)
  const body = { agent, identity: IDENTITY, membership: IDENTITY, root: ROOT, subject: hex(ed25519.getPublicKey(secret)), aud: AUD,
    scopes: ['post'], nbf: NOW - 10, exp: NOW + 86_000, ...over }
  const { payload, id } = envelope.seal('delegation', body)
  const consent = hex(ed25519.sign(Buffer.concat([Buffer.from('muid/v1/accept\n'), Buffer.from(id, 'hex')]), secret))
  return { text: envelope.wrap(payload, { root: make({ covers: [id] }), subject: consent }), id, secret,
    logged: signedBy('logged', { identity: IDENTITY, delegation: id, at: NOW - 5 }) }
}
const head = (revoked = [], at = NOW - 100) => signedBy('head', { identity: IDENTITY, epoch: 1, memberships: [IDENTITY], authority: [ROOT], revoked: [...revoked].sort(), at })
const CALL = Object.freeze({ now: NOW, scope: 'post', revoked: [] })
const verify = (d, h = head(), call = {}) => v.verifyDelegation({ delegation: d.text, root: rootText, head: h, logged: d.logged }, { ...CALL, ...call })
const reason = (r) => (r.ok ? 'ok' : r.reason)

test('the verifier reports the agent\'s light identity id, for a delegation and for a claim under it', () => {
  const d = delegation('forecaster')
  const r = verify(d)
  assert.equal(r.ok, true, JSON.stringify(r))
  assert.equal(r.agent, agentId(IDENTITY, 'forecaster'))
  assert.equal(r.body.agent, 'forecaster')
  assert.deepEqual(Object.keys(r), ['ok', 'id', 'body', 'agent'])
  const { payload } = envelope.seal('claim', { delegation: d.id, scope: 'post', htm: 'POST', htu: URL_, at: NOW - 5, data: {} })
  const claim = envelope.wrap(payload, { signature: hex(ed25519.sign(envelope.signedBytes(payload), d.secret)) })
  const c = v.verifyClaim({ claim, delegation: d.text, root: rootText, head: head(), logged: d.logged }, { ...CALL, method: 'POST', url: URL_ })
  assert.equal(c.ok, true, JSON.stringify(c))
  assert.equal(c.delegation.agent, agentId(IDENTITY, 'forecaster'))
  assert.deepEqual(Object.keys(c.delegation), ['id', 'body', 'agent'])
})

test('two delegations with one name are one light identity, whatever their keys and windows', () => {
  const a = verify(delegation('forecaster', 1))
  const b = verify(delegation('forecaster', 2, { nbf: NOW - 50, exp: NOW + 3_600 }))
  assert.equal(a.ok && b.ok, true)
  assert.notEqual(a.id, b.id)
  assert.equal(a.agent, b.agent)
  assert.notEqual(verify(delegation('scorer', 1)).agent, a.agent)
})

test('a retired name: refused in the head, the call or the last head, for every delegation under it', () => {
  const retired = agentId(IDENTITY, 'forecaster')
  const old = delegation('forecaster', 1)
  const fresh = delegation('forecaster', 9, { nbf: NOW - 1 }) // a new key, signed after the retirement
  for (const d of [old, fresh]) {
    assert.equal(reason(verify(d, head([retired]))), 'revoked', 'in the head')
    assert.equal(reason(verify(d, head(), { revoked: [retired] })), 'revoked', 'in the call')
    // The relying party's last head retired it; a later head that no longer lists it does not revive it.
    assert.equal(reason(verify(d, head([], NOW - 50), { lastHead: head([retired], NOW - 60) })), 'revoked', 'in the last head')
  }
  assert.equal(reason(verify(delegation('scorer'), head([retired]))), 'ok', 'another name is not retired')
  assert.equal(reason(verify(old, head([agentId('ab'.repeat(32), 'forecaster')]))), 'ok', 'the same name under another identity is another agent')
})
