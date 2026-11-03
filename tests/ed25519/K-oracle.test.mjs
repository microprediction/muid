// Differential and honest-signature properties against Node's Ed25519 (OpenSSL, independent of noble).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPairSync, sign as nodeSign } from 'node:crypto'
import fc from 'fast-check'
import { checkEd25519, nodeAccepts, vector, bytes, hex } from './helpers.mjs'

const SEED = Number(process.env.FC_SEED ?? 20261103)
const RUNS = Number(process.env.FC_RUNS ?? 200)

test('whatever we accept among the vectors, Node also accepts', () => {
  const file = vector('wycheproof/ed25519_test.json')
  const cases = [
    ...file.testGroups.flatMap((g) => g.tests.map((t) => [t.sig, t.msg, g.publicKey.pk])),
    ...vector('ed25519-speccheck/cases.json').map((c) => [c.signature, c.message, c.pub_key]),
  ]
  let accepted = 0
  for (const [sig, msg, key] of cases) {
    if (checkEd25519(sig, bytes(msg), key).ok) {
      accepted++
      assert.ok(nodeAccepts(sig, bytes(msg), key), `we accept but Node rejects: ${sig}`)
    }
  }
  assert.equal(accepted, 117)
})

const keys = Array.from({ length: 8 }, () => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519')
  return { privateKey, pub: hex(publicKey.export({ format: 'der', type: 'spki' }).subarray(12)) }
})

test('honest Node signatures over generated messages are accepted', () => {
  fc.assert(fc.property(fc.integer({ min: 0, max: 7 }), fc.uint8Array({ maxLength: 300 }), (i, msg) => {
    const sig = hex(nodeSign(null, msg, keys[i].privateKey))
    assert.deepEqual({ ...checkEd25519(sig, msg, keys[i].pub) }, { ok: true })
  }), { seed: SEED, numRuns: RUNS })
})

test('one changed byte of signature, message or key is rejected, and Node agrees', () => {
  fc.assert(fc.property(fc.integer({ min: 0, max: 7 }), fc.uint8Array({ minLength: 1, maxLength: 100 }),
    fc.constantFrom('sig', 'msg', 'key'), fc.nat(), fc.integer({ min: 1, max: 255 }), (i, msg, which, at, x) => {
      let sig = Buffer.from(nodeSign(null, msg, keys[i].privateKey))
      let key = Buffer.from(keys[i].pub, 'hex')
      const m = Buffer.from(msg)
      const target = { sig, msg: m, key }[which]
      target[at % target.length] ^= x
      if (which === 'sig') sig = target
      if (which === 'key') key = target
      const r = checkEd25519(hex(sig), m, hex(key))
      assert.equal(r.ok, false, `${which} byte ${at % target.length}`)
      assert.equal(nodeAccepts(hex(sig), m, hex(key)), false)
    }), { seed: SEED, numRuns: RUNS })
})
