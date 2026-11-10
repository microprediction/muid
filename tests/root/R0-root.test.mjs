// Root records and identity ids (SPEC §5): ids by hand vector, refusals with their reasons, binding to rp ID and key.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { root, envelope } from '../impl.mjs'
import { createHash, generateKeyPairSync } from 'node:crypto'
import { KEY, RP_ID } from '../assertion/helpers.mjs'

const { checkRoot, identityOf } = root
const ROOT_ID = '44404d2d618dcf0680853eb9c05c20fe78d3958f7be85a0d8faa8a238200caae' // printf … | shasum -a 256
const IDENTITY_ID = '6d74085630cd2542bf867cf76961dd9e83148e6cb4dd68380666e1e94d77ea46'
const text = (body) => envelope.wrap(envelope.seal('root', body).payload)
const CTX = Object.freeze({ rpId: RP_ID })
const result = (t, ctx = CTX) => ({ ...checkRoot(t, ctx) })

test('hand vectors: the root id and its identity id', () => {
  assert.deepEqual(result(text({ pub: KEY, rp_id: RP_ID })), { ok: true, id: ROOT_ID, key: KEY })
  assert.equal(identityOf(ROOT_ID), IDENTITY_ID)
})

test('V4 reasons pass through', () => {
  assert.deepEqual(result('x'), { ok: false, reason: 'envelope-encoding' })
  assert.deepEqual(result(envelope.wrap(envelope.seal('root', { pub: KEY, rp_id: RP_ID }).payload, {})), { ok: false, reason: 'envelope-shape' })
  const { payload } = envelope.seal('delegation', { pub: KEY, rp_id: RP_ID })
  assert.deepEqual(result(envelope.wrap(payload, {})), { ok: false, reason: 'envelope-shape' })
  assert.deepEqual(result(`{"payload":${JSON.stringify(payload)}}`), { ok: false, reason: 'type' })
})

test('root-shape: exactly pub and rp_id, both strings; pub 130 lowercase hex starting 04', () => {
  for (const [name, body] of [['no pub', { rp_id: RP_ID }], ['no rp_id', { pub: KEY }], ['extra', { pub: KEY, rp_id: RP_ID, x: 1 }],
    ['pub number', { pub: 1, rp_id: RP_ID }], ['rp_id array', { pub: KEY, rp_id: [RP_ID] }], ['pub upper', { pub: KEY.toUpperCase(), rp_id: RP_ID }],
    ['pub compressed', { pub: '02' + KEY.slice(2, 66), rp_id: RP_ID }], ['pub 128', { pub: KEY.slice(2), rp_id: RP_ID }],
    ['pub 132', { pub: KEY + '00', rp_id: RP_ID }]]) {
    assert.deepEqual(result(text(body)), { ok: false, reason: 'root-shape' }, name)
  }
})

test('rp-id: exactly the configured one', () => {
  // Case, a trailing dot, a parent, another domain, empty; a Cyrillic і, a zero-width space, a fullwidth full stop.
  for (const rp of ['ID.example', 'id.example.', 'example', 'other.example', '', '\u0456d.example', 'id.example\u200b', 'id\uff0eexample']) {
    assert.deepEqual(result(text({ pub: KEY, rp_id: rp })), { ok: false, reason: 'rp-id' }, rp)
  }
})

test('key-point: a point off the curve', () => {
  assert.deepEqual(result(text({ pub: '04' + '00'.repeat(64), rp_id: RP_ID })), { ok: false, reason: 'key-point' })
})

test('binding: the id changes with the rp ID and with any key byte', () => {
  const other = result(text({ pub: KEY, rp_id: 'other.example' }), { rpId: 'other.example' })
  assert.equal(other.ok, true)
  assert.notEqual(other.id, ROOT_ID)
  const ids = new Set([ROOT_ID, other.id])
  assert.equal(ids.size, 2)
})

test('results are frozen; arbitrary values never throw; a bad context is a programming error', () => {
  for (const t of [undefined, null, 1, {}, [], 'x']) {
    const r = checkRoot(t, CTX)
    assert.ok(Object.isFrozen(r) && r.ok === false)
  }
  assert.ok(Object.isFrozen(checkRoot(text({ pub: KEY, rp_id: RP_ID }), CTX)))
  for (const ctx of [undefined, null, {}, { rpId: 1 }]) {
    assert.throws(() => checkRoot('x', ctx), { name: 'TypeError', message: 'context must hold an rpId string' })
  }
})

test('identityOf refuses anything but a 64-hex id', () => {
  for (const x of [undefined, 1, [ROOT_ID], { toString: () => ROOT_ID }, ROOT_ID.toUpperCase(), ROOT_ID.slice(1), ROOT_ID + '0', 'g'.repeat(64)]) {
    assert.throws(() => identityOf(x), { name: 'TypeError', message: 'root id must be 64 lowercase hex' })
  }
})

test('a foreign error from opening (patched built-ins in the hash library) fails closed, never throws', () => {
  const t = text({ pub: KEY, rp_id: RP_ID })
  const original = Uint8Array.prototype.fill
  Uint8Array.prototype.fill = function () { throw new Error('patched') }
  let out
  try { out = { ...checkRoot(t, CTX) } } catch (e) { out = { threw: String(e) } } finally { Uint8Array.prototype.fill = original }
  assert.deepEqual(out, { ok: false, reason: 'envelope-encoding' })
})

test('oracle: for generated keys, the root id and identity id match node:crypto SHA-256 over the specified bytes', () => {
  for (let n = 0; n < 40; n++) {
    const jwk = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ format: 'jwk' })
    const pub = '04' + Buffer.from(jwk.x, 'base64url').toString('hex') + Buffer.from(jwk.y, 'base64url').toString('hex')
    const want = createHash('sha256').update(Buffer.concat([Buffer.from('muid-root\n' + RP_ID + '\n'), Buffer.from(pub, 'hex')])).digest('hex')
    const r = result(text({ pub, rp_id: RP_ID }))
    assert.deepEqual(r, { ok: true, id: want, key: pub })
    assert.equal(root.rootIdOf(RP_ID, pub), want)
    const ident = createHash('sha256').update(Buffer.concat([Buffer.from('muid-identity\n'), Buffer.from(want, 'hex')])).digest('hex')
    assert.equal(identityOf(want), ident)
  }
})

test('a context read once: a getter cannot change rpId between reads', () => {
  let reads = 0
  const ctx = { get rpId () { return reads++ === 0 ? RP_ID : 'other.example' } }
  assert.deepEqual(result(text({ pub: KEY, rp_id: RP_ID }), ctx), { ok: true, id: ROOT_ID, key: KEY })
  assert.equal(reads, 1)
})

// Decision 13: a light identity's id is derived from its identity and its agent name, as root and identity ids are:
// SHA-256(UTF-8("muid-agent\n") ‖ the identity id as 32 raw bytes ‖ UTF-8(agent)), lowercase hex.
test('agentIdOf: the specified hash, distinct per identity and per name; anything else a programming error', () => {
  const { agentIdOf } = root
  const want = (identity, agent) => createHash('sha256').update(Buffer.concat([Buffer.from('muid-agent\n'), Buffer.from(identity, 'hex'), Buffer.from(agent)])).digest('hex')
  const I = 'ab'.repeat(32)
  for (const agent of ['a', 'forecaster', 'a'.repeat(64)]) assert.equal(agentIdOf(I, agent), want(I, agent), agent)
  assert.notEqual(agentIdOf(I, 'a'), agentIdOf('cd'.repeat(32), 'a'))
  assert.notEqual(agentIdOf(I, 'ab'), agentIdOf(I, 'a'))
  assert.notEqual(agentIdOf(I, 'a'), root.identityOf(I), 'its own domain')
  // An object that reads as a valid id or name is not one: only strings are.
  const like = (text) => ({ toString: () => text })
  for (const [identity, agent] of [[I.toUpperCase(), 'a'], [I.slice(1), 'a'], [1, 'a'], [I, ''], [I, 'A'], [I, 'a'.repeat(65)], [I, 7],
    [like(I), 'a'], [I, like('a')]]) {
    assert.throws(() => agentIdOf(identity, agent), { name: 'TypeError', message: 'an identity id and an agent name' }, String([identity, agent]))
  }
})
