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
