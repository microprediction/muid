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
    name: 'an envelope of exactly MAX_BYTES',
    type: 'root',
    body: { s: 'x'.repeat(65473) },
    payload: `{"body":{"s":"${'x'.repeat(65473)}"},"type":"root","v":1}`,
    id: '8e122ff52dbb476dfb6c46003e0dac740fe9cd1d532f6073c21067e548c702ce',
  },
]
VECTORS[1].body.note += String.fromCharCode(1)

test('the vectors themselves are what the comment says', () => {
  assert.equal(Buffer.from(VECTORS[1].payload, 'utf8').toString('hex').includes('c3a95c7530303031'), true)
  assert.equal(Buffer.byteLength(envelopeText(VECTORS[2].payload)), 65536)
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

test('one byte past MAX_BYTES, the envelope is refused', () => {
  const payload = VECTORS[2].payload.replace('"s":"x', '"s":"xx')
  assert.throws(() => env.open(envelopeText(payload), 'root'), (e) => e.reason === 'envelope-encoding')
})
