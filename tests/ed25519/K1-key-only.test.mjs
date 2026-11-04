// checkEd25519Key: K5's key checks alone, agreeing with checkEd25519's key stage on every vector key.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { ed25519 } from '../impl.mjs'
import { vector, SMALL_ORDER } from './helpers.mjs'

const { checkEd25519Key, checkEd25519 } = ed25519
const keyStage = (key) => {
  const r = checkEd25519('', new Uint8Array(0), key)
  return r.reason === 'sig-encoding' ? { ok: true } : { ...r }
}

test('agrees with checkEd25519 on every Wycheproof and speccheck key, and on hand-picked keys', () => {
  const keys = [
    ...vector('wycheproof/ed25519_test.json').testGroups.map((g) => g.publicKey.pk),
    ...vector('ed25519-speccheck/cases.json').map((c) => c.pub_key),
    ...SMALL_ORDER, 'zz', '', undefined, 'ed' + 'ff'.repeat(30) + '7f',
  ]
  const seen = new Set()
  for (const k of keys) {
    const r = checkEd25519Key(k)
    assert.ok(Object.isFrozen(r))
    assert.deepEqual({ ...r }, keyStage(k), String(k))
    seen.add(r.ok ? 'ok' : r.reason)
  }
  assert.deepEqual([...seen].sort(), ['key-encoding', 'key-mixed-order', 'key-point', 'key-small-order', 'ok'])
})
