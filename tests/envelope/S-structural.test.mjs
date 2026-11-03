// The bytes verified are the bytes received (TESTING.md §3.4).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, existsSync } from 'node:fs'
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

test('src/envelope.js calls encode only inside seal, so open never re-serialises what it verifies', () => {
  const path = new URL('../../src/envelope.js', import.meta.url)
  assert.ok(existsSync(path), 'src/envelope.js exists')
  const src = readFileSync(path, 'utf8').replace(/\/\/.*$/gm, '')
  const sealAt = src.indexOf('export function seal')
  assert.ok(sealAt >= 0, 'seal is declared as `export function seal`')
  const sealEnd = src.indexOf('\n}\n', sealAt)
  const outside = src.slice(0, sealAt) + src.slice(sealEnd)
  assert.deepEqual(outside.match(/\bencode\s*\(/g) ?? [], [])
})

test('wrap builds canonical envelopes and refuses a payload that is not a string', () => {
  const { payload } = env.seal('delegation', {})
  assert.equal(env.wrap(payload, { b: 1, a: 2 }), `{"payload":${JSON.stringify(payload)},"sig":{"a":2,"b":1}}`)
  assert.equal(env.wrap(payload), `{"payload":${JSON.stringify(payload)}}`)
  assert.throws(() => env.wrap(1, {}), TypeError)
})
