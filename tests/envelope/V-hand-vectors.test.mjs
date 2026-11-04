// Record ids computed outside the project (printf … | shasum -a 256) and typed here as literals.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { env, envelopeText, PREFIX } from './helpers.mjs'

const BS = String.fromCharCode(92) // a backslash, built so that no tool can rewrite an escape in this file

const VECTORS = [
  {
    name: 'empty body',
    type: 'delegation',
    body: {},
    payload: '{"body":{},"type":"delegation","v":1}',
    id: '4af672ff21bc5e39dd3917aae838bfcfa2c3cba1d6ba17a6d6f15f7167071b4c',
  },
  {
    name: 'non-ASCII text and an escaped control character',
    type: 'attestation',
    body: { note: 'é' },
    payload: `{"body":{"note":"é${BS}u0001"},"type":"attestation","v":1}`,
    id: '0ba39249564a0cc3281770dcefac0031d82ce6bab75e41d0babcb554a4511180',
  },
  {
    name: 'a payload of exactly MAX_PAYLOAD bytes inside the envelope',
    type: 'root',
    body: { s: 'x'.repeat(49103) },
    payload: `{"body":{"s":"${'x'.repeat(49103)}"},"type":"root","v":1}`,
    id: 'e9ab8cb12f4b2a6924f4d0855b12e315475e78e49c2ab4209c59938a789388e4',
  },
]
VECTORS[1].body.note += String.fromCharCode(1)

test('the vectors themselves are what the comment says', () => {
  assert.equal(Buffer.from(VECTORS[1].payload, 'utf8').toString('hex').includes('c3a95c7530303031'), true)
  assert.equal(Buffer.byteLength(JSON.stringify(VECTORS[2].payload)) - 2, 49152)
})

for (const { name, type, body, payload, id } of VECTORS) {
  test(`seal: ${name}`, () => {
    const sealed = env.seal(type, body)
    assert.equal(sealed.payload, payload)
    assert.equal(sealed.id, id)
  })

  test(`open: ${name}`, () => {
    const sig = type === 'root' ? undefined : '{}'
    const r = env.open(envelopeText(payload, sig), type)
    assert.equal(r.id, id)
    assert.equal(r.payload, payload)
    assert.equal(r.type, type)
    assert.deepEqual({ ...r.body }, body)
  })

  test(`signedBytes: ${name}`, () => {
    assert.deepEqual(Buffer.from(env.signedBytes(payload)), Buffer.from(PREFIX + payload, 'utf8'))
  })
}

test('one byte past MAX_PAYLOAD, the payload is refused by open and by seal', () => {
  const payload = VECTORS[2].payload.replace('"s":"x', '"s":"xx')
  assert.throws(() => env.open(envelopeText(payload), 'root'), (e) => e.reason === 'payload-size')
  assert.throws(() => env.seal('root', { s: 'x'.repeat(49104) }), (e) => env.EnvelopeError.isRefusal(e) && e.reason === 'payload-size')
})

test('escapes count: a payload is measured as it sits in the envelope', () => {
  // A '"' is 2 bytes in the payload (\") and 4 inside the envelope (\\\"). For a root, the framing is 37 payload
  // bytes holding 12 quotes, so 49 envelope bytes: 49 + 4 * 12000 + 1103 = 49152.
  const body = (extra) => ({ s: '"'.repeat(12000) + 'x'.repeat(1103 + extra) })
  const sealed = env.seal('root', body(0))
  assert.equal(Buffer.byteLength(JSON.stringify(sealed.payload)) - 2, 49152)
  assert.equal(env.open(env.wrap(sealed.payload), 'root').id, sealed.id)
  assert.throws(() => env.seal('root', body(1)), (e) => e.reason === 'payload-size')
  assert.throws(() => env.seal('attestation', { a: String.fromCharCode(1).repeat(10000) }), (e) => e.reason === 'payload-size')
})

test('whatever seal returns can be wrapped with a 16,000-byte sig and opened', () => {
  // For a delegation the framing is 43 payload bytes, 55 in the envelope: 55 + 4 * 12000 + 1097 = 49152.
  const { payload, id } = env.seal('delegation', { s: '"'.repeat(12000) + 'x'.repeat(1097) })
  assert.equal(Buffer.byteLength(JSON.stringify(payload)) - 2, 49152)
  const sig = { blob: 'x'.repeat(16000) }
  assert.equal(env.open(env.wrap(payload, sig), 'delegation').id, id)
})
