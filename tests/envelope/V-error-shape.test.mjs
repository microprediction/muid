// A refusal is an EnvelopeError: frozen class, reason own and read-only, message free of the refused data.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { env, envelopeText, payloadText } from './helpers.mjs'

function caught (fn) {
  try { fn() } catch (e) { return e }
  assert.fail('expected a refusal')
}

test('the error is an Error named EnvelopeError with message "envelope refused: <reason>"', () => {
  const e = caught(() => env.open(envelopeText(payloadText('attestation'), '{}'), 'delegation'))
  assert.ok(e instanceof env.EnvelopeError && e instanceof Error)
  assert.equal(e.name, 'EnvelopeError')
  assert.equal(e.message, 'envelope refused: type')
  assert.deepEqual(Object.getOwnPropertyDescriptor(e, 'reason'), { value: 'type', writable: false, enumerable: true, configurable: false })
})

test('the class is frozen and its brand cannot be forged', () => {
  assert.ok(Object.isFrozen(env.EnvelopeError) && Object.isFrozen(env.EnvelopeError.prototype))
  assert.equal(env.EnvelopeError.isRefusal(Object.create(env.EnvelopeError.prototype, { reason: { value: 'type' } })), false)
  for (const v of [null, undefined, 0, 'x', {}, new Error('x')]) assert.equal(env.EnvelopeError.isRefusal(v), false)
})

test('the message never contains the refused data', () => {
  const secret = 'do-not-log-this'
  for (const text of [`{"payload":"${secret}","sig":{}}`, envelopeText(payloadText('delegation', `{"a":"${secret}"}`, '2'), '{}'), secret]) {
    const e = caught(() => env.open(text, 'delegation'))
    assert.ok(!e.message.includes(secret) && !String(e.stack).split('\n')[0].includes(secret))
  }
})
