// SPEC §6 C2 (proposal): a receipt, signed by a pinned service key and included in a cosigned checkpoint, keeps an
// accepted claim attributable after its delegation expires. Each refusal, in the order the rule lists them.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { ed25519 } from '@noble/curves/ed25519.js'
import { receipt as receiptModule, envelope } from '../impl.mjs'
import { receiptText, logged, BODY, CTX, NOW, SERVICE, SERVICE_KEY, id } from './helpers.mjs'

const { verifyReceipt } = receiptModule
const plain = (r) => JSON.parse(JSON.stringify(r))
const refused = (reason) => ({ ok: false, reason })
const OTHERS = ['other entry 1', 'other entry 2', 'other entry 3', 'other entry 4']

function given (text = receiptText(), at = 2, times) {
  const entries = [...OTHERS.slice(0, at), text, ...OTHERS.slice(at)]
  const { checkpoint, proof, index } = logged(entries, at, times)
  return { receipt: text, checkpoint, proof, index }
}

test('a logged receipt from a pinned service is accepted, with the time the quorum vouches for', () => {
  assert.deepEqual(plain(verifyReceipt(given(), CTX)), { ok: true, service: SERVICE, identity: id('1'), delegation: id('2'), claim: id('3'), at: NOW - 100, existedBy: NOW - 40 })
  for (const at of [0, 4]) assert.equal(verifyReceipt(given(undefined, at), CTX).ok, true, `at index ${at}`)
  assert.equal(verifyReceipt(given(undefined, 2, [NOW - 50, NOW - 40]), CTX).ok, true, 'exactly the quorum')
})

test('envelope reasons first', () => {
  assert.deepEqual(plain(verifyReceipt({ ...given(), receipt: 'x' }, CTX)), refused('envelope-encoding'))
  const head = envelope.wrap(envelope.seal('head', { a: 1 }).payload, { signature: 'x' })
  assert.deepEqual(plain(verifyReceipt({ ...given(), receipt: head }, CTX)), refused('type'))
})

test('receipt-shape: the five fields and the signature object', () => {
  const key = SERVICE_KEY
  for (const [name, body, sig] of [
    ['an extra field', { ...BODY, x: 1 }], ['no claim', { ...BODY, claim: undefined }], ['identity not an id', { ...BODY, identity: 'x' }],
    ['delegation in upper case', { ...BODY, delegation: id('A') }], ['claim of 63', { ...BODY, claim: '3'.repeat(63) }],
    ['identity of 65', { ...BODY, identity: '1'.repeat(65) }], ['identity with a prefix', { ...BODY, identity: 'x' + id('1') }],
    ['identity as a list', { ...BODY, identity: [id('1')] }],
    ['service not canonical', { ...BODY, service: SERVICE + '/' }], ['service http', { ...BODY, service: 'http://forecasts.example' }],
    ['at negative', { ...BODY, at: -1 }], ['at a string', { ...BODY, at: '1' }],
    ['a signature with another key name', BODY, { witness: key, signature: 'a'.repeat(128) }],
    ['a signature with an extra key', BODY, { service: key, signature: 'a'.repeat(128), x: 'y' }],
    ['a signature of 127', BODY, { service: key, signature: 'a'.repeat(127) }], ['a service key of 63', BODY, { service: key.slice(1), signature: 'a'.repeat(128) }],
    ['a signature of 129', BODY, { service: key, signature: 'a'.repeat(129) }], ['a signature with a prefix', BODY, { service: key, signature: 'x' + 'a'.repeat(128) }],
    ['a service key of 65', BODY, { service: key + '0', signature: 'a'.repeat(128) }],
  ]) {
    const b = JSON.parse(JSON.stringify(body))
    assert.deepEqual(plain(verifyReceipt(given(receiptText(b, { sig })), CTX)), refused('receipt-shape'), name)
  }
})

test('service: the key must be pinned for that origin, with a window holding the receipt time', () => {
  const other = Uint8Array.from({ length: 32 }, (_, i) => 90 + i)
  assert.deepEqual(plain(verifyReceipt(given(receiptText(BODY, { secret: other })), CTX)), refused('service'), 'an unpinned key')
  const elsewhere = { ...CTX, services: [{ origin: 'https://other.example', key: SERVICE_KEY, nbf: 0, exp: NOW + 1000 }] }
  assert.deepEqual(plain(verifyReceipt(given(), elsewhere)), refused('service'), 'pinned for another origin')
  for (const [nbf, exp, ok] of [[NOW - 100, NOW - 100, true], [NOW - 99, NOW, false], [0, NOW - 101, false]]) {
    const w = { ...CTX, services: [{ origin: SERVICE, key: SERVICE_KEY, nbf, exp }] }
    assert.equal(verifyReceipt(given(), w).ok, ok, `window [${nbf}, ${exp}]`)
  }
})

test('signature: K5 reasons under the service key', () => {
  const t = receiptText()
  // The third hex digit of S: a low-order byte, so S stays canonical and only the equation fails.
  const forged = t.replace(/("signature":"[0-9a-f]{66})([0-9a-f])/, (_, head, c) => head + (c === '0' ? '1' : '0'))
  assert.deepEqual(plain(verifyReceipt(given(forged), CTX)), refused('sig-invalid'))
})

test('checkpoint: one that does not verify, or without the cosigner quorum, is refused', () => {
  assert.deepEqual(plain(verifyReceipt({ ...given(), checkpoint: 'x' }, CTX)), refused('checkpoint'))
  assert.deepEqual(plain(verifyReceipt(given(undefined, 2, [NOW - 50]), CTX)), refused('checkpoint'), 'one cosigner of two')
  assert.deepEqual(plain(verifyReceipt(given(), { ...CTX, log: { ...CTX.log, origin: 'log.example/other' } })), refused('checkpoint'), 'another log')
})

test('inclusion: the receipt must be the entry at index in that tree', () => {
  const g = given()
  assert.deepEqual(plain(verifyReceipt({ ...g, index: 3 }, CTX)), refused('inclusion'))
  assert.deepEqual(plain(verifyReceipt({ ...g, proof: g.proof.slice(1) }, CTX)), refused('inclusion'))
  assert.deepEqual(plain(verifyReceipt({ ...g, proof: 'x' }, CTX)), refused('inclusion'))
  const unlogged = receiptText({ ...BODY, at: NOW - 101 })
  assert.deepEqual(plain(verifyReceipt({ ...g, receipt: unlogged }, CTX)), refused('inclusion'), 'a receipt that is not in the log')
})

test('receipt-time: a receipt cannot say it was accepted after the quorum saw it logged', () => {
  const late = (at, times) => verifyReceipt(given(receiptText({ ...BODY, at }), 2, times), CTX)
  assert.equal(late(NOW - 40 + 60, [NOW - 50, NOW - 40]).ok, true, 'within skew of the quorum time')
  assert.deepEqual(plain(late(NOW - 40 + 61, [NOW - 50, NOW - 40])), refused('receipt-time'))
  assert.deepEqual(plain(late(NOW - 40 + 61, [NOW - 50, NOW - 40, NOW + 50])), refused('receipt-time'), 'the quorum time, not the latest')
})

test('claim: when the claim is given, it must be the one the receipt names', () => {
  const sk = Uint8Array.from({ length: 32 }, (_, i) => 70 + i)
  const { payload, id: claimId } = envelope.seal('claim', { delegation: id('2'), scope: 'post', request: 'POST /x', at: NOW - 101, data: {} })
  const claim = envelope.wrap(payload, { signature: Buffer.from(ed25519.sign(envelope.signedBytes(payload), sk)).toString('hex') })
  const named = receiptText({ ...BODY, claim: claimId })
  assert.equal(verifyReceipt({ ...given(named), claim }, CTX).ok, true)
  assert.deepEqual(plain(verifyReceipt({ ...given(), claim }, CTX)), refused('claim'), 'another claim')
  assert.deepEqual(plain(verifyReceipt({ ...given(named), claim: 'x' }, CTX)), refused('claim'), 'not a claim')
})

test('configuration errors are programming errors', () => {
  const g = given()
  for (const [name, ctx, message] of [
    ['quorum 0', { ...CTX, log: { ...CTX.log, quorum: 0 } }, /at least one cosigner/], ['no services', { ...CTX, services: undefined }, /services/],
    ['a service key of 63', { ...CTX, services: [{ origin: SERVICE, key: SERVICE_KEY.slice(1), nbf: 0, exp: 1 }] }, /services/],
    ['a service origin not canonical', { ...CTX, services: [{ origin: SERVICE + '/', key: SERVICE_KEY, nbf: 0, exp: 1 }] }, /services/],
    ['a negative window', { ...CTX, services: [{ origin: SERVICE, key: SERVICE_KEY, nbf: -1, exp: 1 }] }, /services/],
    ['a null service', { ...CTX, services: [null] }, /services/], ['a string service', { ...CTX, services: ['x'] }, /services/],
    ['no log', { ...CTX, log: undefined }, /log/], ['a null log', { ...CTX, log: null }, /log configuration/],
    ['a malformed log key', { ...CTX, log: { ...CTX.log, log: 'x' } }, /verifier key/], ['no now', { ...CTX, now: undefined }, /now and skew/],
  ]) {
    assert.throws(() => verifyReceipt(g, ctx), (e) => e instanceof TypeError && message.test(e.message), name)
  }
  for (const x of [null, undefined, 'x']) assert.throws(() => verifyReceipt(x, CTX), /given must be an object/)
  for (const x of [null, undefined, 'x']) assert.throws(() => verifyReceipt(g, x), /context must be an object/)
  // Checked before the receipt, so a refusal of what is presented cannot hide a configuration error.
  assert.throws(() => verifyReceipt({ ...g, receipt: 'x' }, { ...CTX, log: { ...CTX.log, log: 'x' } }), /verifier key/)
  const one = verifyReceipt(g, { ...CTX, log: { ...CTX.log, quorum: 1 } })
  assert.deepEqual([one.ok, one.existedBy], [true, NOW - 50], 'quorum 1: the earliest cosignature')
})

// The configuration's key IDs are hashed before the receipt is opened, so the patch is made from a getter on the
// presented receipt: after the configuration is read, before the receipt is opened.
test('a foreign error from opening (patched built-ins in the hash library) fails closed, never throws', () => {
  const g = given()
  const original = Uint8Array.prototype.fill
  const presented = { ...g, get receipt () { Uint8Array.prototype.fill = function () { throw new Error('patched') }; return g.receipt } }
  let out
  try { out = plain(verifyReceipt(presented, CTX)) } catch (e) { out = { threw: String(e) } } finally { Uint8Array.prototype.fill = original }
  assert.deepEqual(out, refused('envelope-encoding'))
})
