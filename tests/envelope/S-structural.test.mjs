// The bytes verified are the bytes received (TESTING.md §3.4).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { env, envelopeText, payloadText, PREFIX } from './helpers.mjs'

test('the returned payload is the received payload text, and signedBytes is the prefix plus its UTF-8', () => {
  const payload = payloadText('delegation', '{"n":"é\u{1F600}"}')
  const text = envelopeText(payload, '{}')
  const r = env.open(text, 'delegation')
  assert.equal(r.payload, JSON.parse(text).payload)
  assert.deepEqual(Buffer.from(env.signedBytes(r.payload)), Buffer.concat([Buffer.from(PREFIX), Buffer.from(payload, 'utf8')]))
})

test('signedBytes returns a new array each call; mutating one changes nothing else', () => {
  const payload = env.seal('delegation', { a: 1 }).payload
  const x = env.signedBytes(payload)
  const y = env.signedBytes(payload)
  assert.notEqual(x, y)
  x.fill(0)
  assert.equal(Buffer.from(y).toString('utf8'), PREFIX + payload)
  assert.equal(env.seal('delegation', { a: 1 }).id, env.open(envelopeText(payload, '{}'), 'delegation').id)
})

test('wrap builds canonical envelopes and refuses a payload that is not a string', () => {
  const { payload } = env.seal('delegation', {})
  assert.equal(env.wrap(payload, { b: 1, a: 2 }), `{"payload":${JSON.stringify(payload)},"sig":{"a":2,"b":1}}`)
  assert.equal(env.wrap(payload), `{"payload":${JSON.stringify(payload)}}`)
  assert.throws(() => env.wrap(1, {}), { name: 'TypeError', message: 'payload must be a string' })
})

test('seal refuses a body that is not an object, as a programming error', () => {
  for (const body of [null, [], 'x', 1, true, undefined]) {
    assert.throws(() => env.seal('delegation', body), { name: 'TypeError', message: 'body must be an object' }, String(body))
  }
})

test('signedBytes accepts only well-formed strings', () => {
  const lone = String.fromCharCode(0xd800)
  for (const bad of [lone, 'a' + lone, 5, null, undefined, {}, { toString () { throw new Error('x') } }]) {
    assert.throws(() => env.signedBytes(bad), { name: 'TypeError', message: 'payload must be a well-formed string' }, String(typeof bad))
  }
})

test('seal turns a revoked proxy body into its own TypeError', () => {
  const { proxy, revoke } = Proxy.revocable({}, {})
  revoke()
  assert.throws(() => env.seal('delegation', proxy), { name: 'TypeError', message: 'body must be an object' })
})
