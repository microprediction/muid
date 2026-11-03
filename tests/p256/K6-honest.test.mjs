// Node-signed messages are accepted, with either S; any changed byte is rejected; Node agrees on every accept.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPairSync, sign as nodeSign } from 'node:crypto'
import fc from 'fast-check'
import { result, nodeAccepts, vectors, bytes, hex, der, parseDer, N } from './helpers.mjs'

const SEED = Number(process.env.FC_SEED ?? 20261103)
const RUNS = Number(process.env.FC_RUNS ?? 200)

const keys = Array.from({ length: 6 }, () => {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
  const jwk = publicKey.export({ format: 'jwk' })
  return { privateKey, pub: '04' + hex(Buffer.from(jwk.x, 'base64url')) + hex(Buffer.from(jwk.y, 'base64url')) }
})

test('whatever we accept among the vectors, Node accepts too', () => {
  let accepted = 0
  for (const g of vectors().testGroups) {
    for (const t of g.tests) {
      if (result(bytes(t.sig), bytes(t.msg), g.publicKey.uncompressed).ok) {
        accepted++
        assert.ok(nodeAccepts(bytes(t.sig), bytes(t.msg), g.publicKey.uncompressed), `tcId ${t.tcId}`)
      }
    }
  }
  assert.equal(accepted, 174)
})

test('honest signatures verify with S and with n - S', () => {
  let high = 0
  fc.assert(fc.property(fc.integer({ min: 0, max: 5 }), fc.uint8Array({ maxLength: 200 }), (i, msg) => {
    const sig = nodeSign('sha256', msg, { key: keys[i].privateKey, dsaEncoding: 'der' })
    assert.deepEqual(result(new Uint8Array(sig), msg, keys[i].pub), { ok: true })
    const { r, s } = parseDer(sig)
    if (s > N / 2n) high++
    const flipped = der(r, N - s)
    assert.deepEqual(result(flipped, msg, keys[i].pub), { ok: true }, 'n - S')
    assert.ok(nodeAccepts(flipped, msg, keys[i].pub), 'Node accepts n - S too')
  }), { seed: SEED, numRuns: RUNS })
  assert.ok(high > 0, 'some signatures had high S')
})

test('one changed byte of signature, message or key is rejected', () => {
  fc.assert(fc.property(fc.integer({ min: 0, max: 5 }), fc.uint8Array({ minLength: 1, maxLength: 100 }),
    fc.constantFrom('sig', 'msg', 'key'), fc.nat(), fc.integer({ min: 1, max: 255 }), (i, msg, which, at, x) => {
      const sig = Buffer.from(nodeSign('sha256', msg, { key: keys[i].privateKey, dsaEncoding: 'der' }))
      const m = Buffer.from(msg)
      const key = Buffer.from(keys[i].pub, 'hex')
      const target = { sig, msg: m, key }[which]
      const j = which === 'key' ? 1 + (at % 64) : at % target.length // the 04 prefix is tested separately
      target[j] ^= x
      assert.equal(result(new Uint8Array(sig), new Uint8Array(m), hex(key)).ok, false, `${which} byte ${j}`)
    }), { seed: SEED, numRuns: RUNS })
})
