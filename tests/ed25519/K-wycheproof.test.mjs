// Wycheproof ed25519_test.json: 117 valid verify; 64 invalid and all 29 acceptable are rejected (K1, K4, K5).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { checkEd25519, vector, bytes } from './helpers.mjs'

const file = vector('wycheproof/ed25519_test.json')
const cases = file.testGroups.flatMap((g) => g.tests.map((t) => ({ ...t, key: g.publicKey.pk })))

test('the file holds 210 cases: 117 valid, 64 invalid, 29 acceptable', () => {
  assert.equal(file.numberOfTests, 210)
  assert.equal(cases.length, 210)
  const n = (r) => cases.filter((c) => c.result === r).length
  assert.deepEqual([n('valid'), n('invalid'), n('acceptable')], [117, 64, 29])
})

test('every valid case verifies; every invalid and acceptable case is rejected', () => {
  const wrong = []
  for (const c of cases) {
    const r = checkEd25519(c.sig, bytes(c.msg), c.key)
    if (r.ok !== (c.result === 'valid')) wrong.push(`tcId ${c.tcId} (${c.result}, ${c.comment}): ${JSON.stringify(r)}`)
  }
  assert.deepEqual(wrong, [])
})

test('the acceptable cases are rejected for their key (all carry a mixed-order public key)', () => {
  const reasons = new Set(cases.filter((c) => c.result === 'acceptable').map((c) => checkEd25519(c.sig, bytes(c.msg), c.key).reason))
  assert.ok([...reasons].every((r) => r.startsWith('key-') || r.startsWith('sig-r-')), [...reasons].join(', '))
})
