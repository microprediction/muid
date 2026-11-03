// Wycheproof ECDSA P-256 / SHA-256 / DER: all 484 verdicts match; valid includes high S (lowS: false, SPEC §2).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { vectors, result, bytes } from './helpers.mjs'

const file = vectors()
const cases = file.testGroups.flatMap((g) => g.tests.map((t) => ({ ...t, key: g.publicKey.uncompressed })))

test('484 cases: 174 valid, 310 invalid', () => {
  assert.equal(file.numberOfTests, 484)
  assert.equal(cases.length, 484)
  assert.equal(cases.filter((c) => c.result === 'valid').length, 174)
})

test('every verdict matches', () => {
  const wrong = []
  for (const c of cases) {
    const r = result(bytes(c.sig), bytes(c.msg), c.key)
    if (r.ok !== (c.result === 'valid')) wrong.push(`tcId ${c.tcId} ${c.result} ${c.comment}: ${JSON.stringify(r)}`)
  }
  assert.deepEqual(wrong, [])
})

test('every malformed-encoding case is refused as sig-encoding', () => {
  const enc = cases.filter((c) => c.result === 'invalid' && c.flags.some((f) => /Ber|InvalidEncoding|ModifiedInteger|IntegerOverflow|MissingZero/.test(f)))
  assert.ok(enc.length > 50, `found ${enc.length}`)
  const off = enc.map((c) => [c.tcId, result(bytes(c.sig), bytes(c.msg), c.key).reason]).filter(([, r]) => r !== 'sig-encoding')
  assert.deepEqual(off, [])
})

test('valid cases with high S are accepted', () => {
  const high = cases.filter((c) => c.result === 'valid' && c.flags.includes('SignatureMalleabilityP256'))
  assert.ok(high.length > 0)
  for (const c of high) assert.equal(result(bytes(c.sig), bytes(c.msg), c.key).ok, true, `tcId ${c.tcId}`)
})
