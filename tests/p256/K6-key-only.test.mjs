// checkP256Key: K6's key checks alone, agreeing with checkP256's key stage on every vector key and hand-picked keys.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { p256 } from '../impl.mjs'
import { vectors } from './helpers.mjs'

const { checkP256Key, checkP256 } = p256
const keyStage = (key) => {
  const r = checkP256(new Uint8Array(0), new Uint8Array(0), key)
  return r.reason === 'sig-encoding' ? { ok: true } : { ...r }
}

test('agrees with checkP256 on every Wycheproof key and on hand-picked keys', () => {
  const keys = [...vectors().testGroups.map((g) => g.publicKey.uncompressed), '04' + '00'.repeat(64), 'zz', undefined, 1]
  const seen = new Set()
  for (const k of keys) {
    const r = checkP256Key(k)
    assert.ok(Object.isFrozen(r))
    assert.deepEqual({ ...r }, keyStage(k), String(k))
    seen.add(r.ok ? 'ok' : r.reason)
  }
  assert.deepEqual([...seen].sort(), ['key-encoding', 'key-point', 'ok'])
})
