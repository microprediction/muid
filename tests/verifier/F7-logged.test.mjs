// R10 and F5's `logged`: a delegation verifies only with the witness's logged record naming it, as a browser accepts
// a certificate only with a log's signed timestamp. Checked after `revoked` and before `audience`.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { ed25519 } from '@noble/curves/ed25519.js'
import { verifier as verifierModule, envelope, root as rootModule } from '../impl.mjs'
import { make, KEY, RP_ID, ORIGIN } from '../assertion/helpers.mjs'

const { verifier } = verifierModule
const hex = (b) => Buffer.from(b).toString('hex')
const NOW = 1_800_000_100
const W = Uint8Array.from({ length: 32 }, (_, i) => 140 + i)
const OTHER = Uint8Array.from({ length: 32 }, (_, i) => 30 + i)
const WITNESS = hex(ed25519.getPublicKey(W))
const APP = Uint8Array.from({ length: 32 }, (_, i) => 60 + i)
const AUD = 'https://app.example'
// The witness key's window opened at NOW - 500.
const CONFIG = Object.freeze({ rpId: RP_ID, origin: ORIGIN, audience: AUD, witnessKeys: [{ key: WITNESS, nbf: NOW - 500, exp: 1_900_000_000 }],
  skew: 60, maxLifetime: 2_592_000, maxStaleness: 86_400, maxClaimAge: 300 })
const v = verifier(CONFIG)

const rootText = envelope.wrap(envelope.seal('root', { pub: KEY, rp_id: RP_ID }).payload)
const ROOT = rootModule.checkRoot(rootText, { rpId: RP_ID }).id
const IDENTITY = rootModule.identityOf(ROOT)

function delegation (over = {}) {
  const body = { identity: IDENTITY, membership: IDENTITY, root: ROOT, subject: hex(ed25519.getPublicKey(APP)), aud: AUD,
    scopes: ['post'], nbf: NOW - 10, exp: NOW + 86_000, ...over }
  const { payload, id } = envelope.seal('delegation', body)
  const subject = hex(ed25519.sign(Buffer.concat([Buffer.from('muid/v1/accept\n'), Buffer.from(id, 'hex')]), APP))
  return { text: envelope.wrap(payload, { root: make({ covers: [id] }), subject }), id }
}
const D = delegation()

function signedBy (type, body, secret = W) {
  const { payload } = envelope.seal(type, body)
  return envelope.wrap(payload, { signature: hex(ed25519.sign(envelope.signedBytes(payload), secret)), witness: hex(ed25519.getPublicKey(secret)) })
}
const logged = (over = {}, secret, type = 'logged') => signedBy(type, { identity: IDENTITY, delegation: D.id, at: NOW - 5, ...over }, secret)
const head = (revoked = []) => signedBy('head', { identity: IDENTITY, epoch: 1, memberships: [IDENTITY], authority: [ROOT], revoked, at: NOW - 100 })

const verify = (records, call = {}) => {
  const r = v.verifyDelegation({ delegation: D.text, root: rootText, head: head(), logged: logged(), ...records }, { now: NOW, scope: 'post', revoked: [], ...call })
  return r.ok ? { ok: true } : { ...r }
}
const refused = (reason) => ({ ok: false, reason })

test('with the logged record naming it, the delegation is accepted', () => {
  assert.deepEqual(verify({}), { ok: true })
})

test('logged: missing, or not the witness\'s logged record of this identity and this delegation', () => {
  const cases = [
    ['missing', undefined],
    ['not a text', 7],
    ['not an envelope', 'logged'],
    ['a head, not a logged record', logged({}, W, 'head')],
    ['another delegation', logged({ delegation: delegation({ scopes: ['read'] }).id })],
    ['another identity', logged({ identity: 'f'.repeat(64) })],
    ['an extra key', logged({ x: 1 })],
    ['no time', signedBy('logged', { identity: IDENTITY, delegation: D.id })],
    ['a time that is not a number', logged({ at: '1' })],
    ['an unpinned key', logged({}, OTHER)],
    ['before the key\'s window', logged({ at: NOW - 501 })],
    ['after the key\'s window', logged({ at: 1_900_000_000 })],
  ]
  for (const [name, text] of cases) assert.deepEqual(verify({ logged: text }), refused('logged'), name)
  // A forged signature: the witness's key named, another key's signature.
  const { payload } = envelope.seal('logged', { identity: IDENTITY, delegation: D.id, at: NOW - 5 })
  const forged = envelope.wrap(payload, { signature: hex(ed25519.sign(envelope.signedBytes(payload), OTHER)), witness: WITNESS })
  assert.deepEqual(verify({ logged: forged }), refused('logged'), 'forged')
  // At the key's window's edges: its first second counts.
  assert.deepEqual(verify({ logged: logged({ at: NOW - 500 }) }), { ok: true })
})

test('order: after revoked, before audience', () => {
  assert.deepEqual(verify({ head: head([D.id]), logged: undefined }), refused('revoked'))
  const elsewhere = delegation({ aud: 'https://other.example' })
  assert.deepEqual(verify({ delegation: elsewhere.text, logged: undefined }), refused('logged'))
  assert.deepEqual(verify({ delegation: elsewhere.text, logged: logged({ delegation: elsewhere.id }) }), refused('audience'))
})

test('the logged record is read once from the records', () => {
  let reads = 0
  const records = { delegation: D.text, root: rootText, head: head(), get logged () { reads++; return logged() } }
  assert.equal(v.verifyDelegation(records, { now: NOW, scope: 'post', revoked: [] }).ok, true)
  assert.equal(reads, 1)
})
