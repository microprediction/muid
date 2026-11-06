// V1, V2, V4: each refusal carries its reason, and with several faults the first in V4 order.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { env, envelopeText, payloadText, refuses, TYPES } from './helpers.mjs'

const P = payloadText('delegation')
const ok = envelopeText(P, '{}')

test('the base case opens, so every refusal below is caused by its one change', () => {
  assert.equal(env.open(ok, 'delegation').type, 'delegation')
  assert.equal(env.open(envelopeText(payloadText('root')), 'root').type, 'root')
})

const CASES = [
  ['not a string', 42, 'envelope-encoding'],
  ['a leading space', ' ' + ok, 'envelope-encoding'],
  ['a trailing newline', ok + '\n', 'envelope-encoding'],
  ['keys out of order', `{"sig":{},"payload":${JSON.stringify(P)}}`, 'envelope-encoding'],
  ['a duplicate key', `{"payload":${JSON.stringify(P)},"payload":${JSON.stringify(P)},"sig":{}}`, 'envelope-encoding'],
  ['a top-level array', '[1]', 'envelope-encoding'],
  ['an extra key', `{"payload":${JSON.stringify(P)},"sig":{},"x":1}`, 'envelope-shape'],
  ['payload missing', '{"sig":{}}', 'envelope-shape'],
  ['two keys, the second misnamed', `{"payload":${JSON.stringify(P)},"sih":{}}`, 'envelope-shape'],
  ['two keys, the first misnamed', `{"pay":${JSON.stringify(P)},"sig":{}}`, 'envelope-shape'],
  ['payload a number', '{"payload":1,"sig":{}}', 'envelope-shape'],
  ['payload an object', `{"payload":${P},"sig":{}}`, 'envelope-shape'],
  ['sig an array', envelopeText(P, '[]'), 'envelope-shape'],
  ['sig a string', envelopeText(P, '"x"'), 'envelope-shape'],
  ['sig a number', envelopeText(P, '1'), 'envelope-shape'],
  ['a non-root without sig', envelopeText(P), 'envelope-shape'],
  ['payload not canonical (space)', envelopeText(P.replace(',', ', '), '{}'), 'payload-encoding'],
  ['payload keys out of order', envelopeText('{"type":"delegation","body":{},"v":1}', '{}'), 'payload-encoding'],
  ['payload not JSON', envelopeText('x', '{}'), 'payload-encoding'],
  ['payload an array', envelopeText('[1]', '{}'), 'payload-encoding'],
  ['payload with null', envelopeText(payloadText('delegation', '{"a":null}'), '{}'), 'payload-encoding'],
  ['payload with an extra key', envelopeText('{"body":{},"type":"delegation","v":1,"x":1}', '{}'), 'payload-shape'],
  ['payload without body', envelopeText('{"type":"delegation","v":1}', '{}'), 'payload-shape'],
  ['payload without v', envelopeText('{"body":{},"type":"delegation"}', '{}'), 'payload-shape'],
  ['payload without type', envelopeText('{"body":{},"v":1}', '{}'), 'payload-shape'],
  ['payload with v misnamed', envelopeText('{"body":{},"type":"delegation","w":1}', '{}'), 'payload-shape'],
  ['payload with body misnamed', envelopeText('{"bod":{},"type":"delegation","v":1}', '{}'), 'payload-shape'],
  ['payload with type misnamed', envelopeText('{"body":{},"typf":"delegation","v":1}', '{}'), 'payload-shape'],
  ['body an array', envelopeText(payloadText('delegation', '[]'), '{}'), 'payload-shape'],
  ['body a string', envelopeText(payloadText('delegation', '"x"'), '{}'), 'payload-shape'],
  ['v 0', envelopeText(payloadText('delegation', '{}', '0'), '{}'), 'version'],
  ['v 2', envelopeText(payloadText('delegation', '{}', '2'), '{}'), 'version'],
  ['v "1"', envelopeText(payloadText('delegation', '{}', '"1"'), '{}'), 'version'],
  ['v true', envelopeText(payloadText('delegation', '{}', 'true'), '{}'), 'version'],
  ['another type', envelopeText(payloadText('attestation'), '{}'), 'type'],
  ['type differing in case', envelopeText(payloadText('Delegation'), '{}'), 'type'],
  ['type with a trailing space', envelopeText(payloadText('delegation '), '{}'), 'type'],
  ['type not a string', envelopeText(payloadText('delegation').replace('"delegation"', '1'), '{}'), 'type'],
]

for (const [name, text, reason] of CASES) {
  test(`${name} → ${reason}`, () => refuses(() => env.open(text, 'delegation'), reason, name))
}

test('a root envelope with its one key misnamed is refused for its shape', () => {
  refuses(() => env.open(`{"pay":${JSON.stringify(payloadText('root'))}}`, 'root'), 'envelope-shape', 'root key misnamed')
})

test('a root opens without a sig key at all', () => {
  const r = env.open(envelopeText(payloadText('root')), 'root')
  assert.equal(Object.hasOwn(r, 'sig'), false)
  assert.deepEqual(Object.keys(r), ['id', 'type', 'body', 'payload'])
  assert.deepEqual(Object.keys(env.open(ok, 'delegation')), ['id', 'type', 'body', 'sig', 'payload'])
})

test('a root with sig is refused for its shape', () => {
  refuses(() => env.open(envelopeText(payloadText('root'), '{}'), 'root'), 'envelope-shape', 'root with sig')
})

test('a root opened as another type, and another type opened as a root', () => {
  refuses(() => env.open(envelopeText(payloadText('root')), 'delegation'), 'envelope-shape', 'no sig, non-root expected')
  refuses(() => env.open(envelopeText(payloadText('root'), '{}'), 'delegation'), 'type', 'root payload with sig')
  refuses(() => env.open(ok, 'root'), 'envelope-shape', 'sig present, root expected')
})

test('payload-size comes after envelope-shape and before payload-encoding', () => {
  const big = 'x'.repeat(49153)
  refuses(() => env.open(envelopeText(big, '[]'), 'delegation'), 'envelope-shape', 'shape first')
  refuses(() => env.open(envelopeText(big, '{}'), 'delegation'), 'payload-size', 'size before encoding')
  refuses(() => env.open(envelopeText('x'.repeat(49152), '{}'), 'delegation'), 'payload-encoding', 'at the limit, encoding is checked')
})

test('several faults at once: the first in V4 order wins', () => {
  const bad = envelopeText(payloadText('attestation', '[]', '2'), '[]')
  refuses(() => env.open(bad, 'delegation'), 'envelope-shape', 'shape before payload')
  refuses(() => env.open(envelopeText(payloadText('attestation', '[]', '2'), '{}'), 'delegation'), 'payload-shape', 'shape before version')
  refuses(() => env.open(envelopeText(payloadText('attestation', '{}', '2'), '{}'), 'delegation'), 'version', 'version before type')
})

test('every V2 type opens as itself and is refused as each other type', () => {
  assert.equal(TYPES.length, 13)
  for (const t of TYPES) {
    const text = envelopeText(payloadText(t), t === 'root' ? undefined : '{}')
    assert.equal(env.open(text, t).type, t)
    for (const u of TYPES.filter((x) => x !== 'root')) {
      if (u !== t && t !== 'root') refuses(() => env.open(text, u), 'type', `${t} as ${u}`)
    }
  }
})

test('asking for a type outside the closed list is a programming error, not a refusal', () => {
  for (const t of ['unknown', '', 'Root', undefined, 1]) {
    assert.throws(() => env.open(ok, t), { name: 'TypeError', message: 'unknown record type' }, String(t))
    assert.throws(() => env.seal(t, {}), { name: 'TypeError', message: 'unknown record type' }, String(t))
  }
})
