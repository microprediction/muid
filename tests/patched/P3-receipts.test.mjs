// §4 residual for receipts (tests/patched/sweep.mjs): under any one patched built-in, verifyReceipt accepts no receipt
// it refuses, and gives an accepted one's result unchanged or fails closed. The cases: a logged receipt; one signed
// by another key; one at the wrong index; one in a checkpoint cosigned below the quorum; one by an unpinned service;
// one from the future; and one whose claim is another.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { receipt as receiptModule } from '../impl.mjs'
import { receiptText, logged, BODY, CTX, NOW, id } from '../receipt/helpers.mjs'
import { sweep } from './sweep.mjs'

const OTHERS = ['other entry 1', 'other entry 2', 'other entry 3', 'other entry 4']
function given (text = receiptText(), at = 2, times) {
  const entries = [...OTHERS.slice(0, at), text, ...OTHERS.slice(at)]
  const { checkpoint, proof, index } = logged(entries, at, times)
  return { receipt: text, checkpoint, proof, index }
}
const SETS = [
  ['logged', given(), CTX],
  ['signed by another key', given(receiptText(BODY, { secret: Uint8Array.from({ length: 32 }, (_, i) => 99 + i) })), CTX],
  ['the wrong index', { ...given(), index: 3 }, CTX],
  ['below the quorum', given(undefined, 2, [NOW - 50]), CTX],
  ['an unpinned service', given(), { ...CTX, services: [{ ...CTX.services[0], key: 'ab'.repeat(32) }] }],
  ['from the future', given(receiptText({ ...BODY, at: NOW + 500 })), CTX],
  ['another claim named', { ...given(), claim: 'x' }, CTX],
]
const CASES = SETS.map(([name, input, ctx]) => ({ name, run: () => receiptModule.verifyReceipt(input, ctx) }))
const stringify = JSON.stringify // captured: describe runs while JSON.stringify may be the patched built-in
const CLAIM = id('3') // made before any patch
const describe = (r) => (r !== null && typeof r === 'object' && r.ok === true ? `accepted ${r.existedBy} ${r.at} ${r.claim === CLAIM}` : 'refused')

test('no patched built-in makes verifyReceipt accept a receipt it refuses, or change what it accepts', () => {
  const { base, changed, failedClosed } = sweep(CASES, describe, (r) => r === 'refused')
  assert.deepEqual(base, ['accepted 1799999960 1799999900 true', ...Array(SETS.length - 1).fill('refused')], stringify(base))
  assert.deepEqual(changed, [])
  assert.ok(failedClosed >= 20, `only ${failedClosed} results failed closed`)
})
