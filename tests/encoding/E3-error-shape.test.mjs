// E3: a refusal is an EncodingError named as such, whose message states the reason and never the refused data.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { encode, decode, EncodingError } from './helpers.mjs'

function caught (fn) {
  try { fn() } catch (e) { return e }
  assert.fail('expected a refusal')
}

test('the error is an Error named EncodingError, with message "encoding refused: <reason>"', () => {
  const e = caught(() => encode({ a: 1.5 }))
  assert.ok(e instanceof EncodingError)
  assert.ok(e instanceof Error)
  assert.equal(e.name, 'EncodingError')
  assert.equal(e.reason, 'float')
  assert.equal(e.message, 'encoding refused: float')
})

test('reason is an own, enumerable, read-only property; name is inherited', () => {
  const e = caught(() => encode({ a: null }))
  assert.deepEqual(Object.getOwnPropertyDescriptor(e, 'reason'),
    { value: 'null', writable: false, enumerable: true, configurable: false })
  assert.throws(() => { e.reason = 'float' }, TypeError)
  assert.equal(Object.hasOwn(e, 'name'), false)
  assert.equal(String(e), 'EncodingError: encoding refused: null')
})

test('the class and its prototype are frozen, so refusals cannot be forged or the brand test replaced', () => {
  assert.ok(Object.isFrozen(EncodingError))
  assert.ok(Object.isFrozen(EncodingError.prototype))
  assert.throws(() => { EncodingError.isRefusal = () => true }, TypeError)
  assert.throws(() => { EncodingError.prototype.name = 'Other' }, TypeError)
  // Something that merely looks like a refusal is not one.
  const fake = Object.create(EncodingError.prototype, { reason: { value: 'float' } })
  assert.equal(EncodingError.isRefusal(fake), false)
  assert.equal(EncodingError.isRefusal(caught(() => encode({ a: 1.5 }))), true)
  for (const v of [null, undefined, 0, 'x', {}]) assert.equal(EncodingError.isRefusal(v), false)
})

test('the message never contains the data being refused', () => {
  const secret = 'do-not-log-this-value'
  for (const fn of [
    () => encode({ a: secret, b: null }),
    () => encode({ [secret.replace(/-/g, '_')]: 1.5 }),
    () => decode(`{"a":"${secret}","b":null}`),
    () => decode(`{"a":"${secret}"} `),
  ]) {
    const e = caught(fn)
    assert.ok(!e.message.includes('do-not-log') && !e.message.includes('do_not_log'), e.message)
    assert.ok(!String(e.stack).split('\n')[0].includes('do-not-log'), 'first stack line')
  }
})
