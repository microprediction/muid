// Whatever is presented in place of each field — any value at all — is refused or accepted, never thrown on.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import fc from 'fast-check'
import { receipt as receiptModule } from '../impl.mjs'
import { receiptText, logged, CTX } from './helpers.mjs'
import { runs } from '../runs.mjs'

const { verifyReceipt } = receiptModule
const SEED = Number(process.env.FC_SEED ?? 20261103)
const RUNS = runs(200)
const text = receiptText()
const GOOD = { receipt: text, ...logged(['a', text, 'b'], 1) }

test('any value in any presented field is refused, not thrown on; the genuine set is accepted', () => {
  assert.equal(verifyReceipt(GOOD, CTX).ok, true)
  fc.assert(fc.property(fc.constantFrom('receipt', 'checkpoint', 'proof', 'index', 'claim'), fc.anything({ withTypedArray: true, withNullPrototype: true }), (field, x) => {
    const r = verifyReceipt({ ...GOOD, [field]: x }, CTX)
    assert.equal(typeof r.ok, 'boolean')
    if (field !== 'claim' && field !== 'index') assert.equal(r.ok, false, field)
  }), { seed: SEED, numRuns: RUNS })
})
