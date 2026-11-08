// K6 key encodings, and K2: no value of sig or key makes checkP256 throw; captured built-ins.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import fc from 'fast-check'
import { checkP256, rejects, result, vectors, bytes, REASONS } from './helpers.mjs'
import { runs } from '../runs.mjs'

const SEED = Number(process.env.FC_SEED ?? 20261103)
const RUNS = runs(300)
const g = vectors().testGroups[0]
const KEY = g.publicKey.uncompressed
const valid = g.tests.find((t) => t.result === 'valid')
const SIG = bytes(valid.sig)
const MSG = bytes(valid.msg)
const P = 'ffffffff00000001000000000000000000000000ffffffffffffffffffffffff'

test('the control case verifies', () => assert.deepEqual(result(SIG, MSG, KEY), { ok: true }))

test('key encodings other than lowercase uncompressed hex are refused', () => {
  const x = KEY.slice(2, 66)
  const odd = (parseInt(KEY.slice(-2), 16) & 1) === 1
  for (const k of [(odd ? '03' : '02') + x, '06' + KEY.slice(2), '07' + KEY.slice(2), KEY.toUpperCase(), KEY.slice(2),
    KEY + '00', KEY.slice(0, -2), '', '05' + KEY.slice(2)]) {
    rejects(SIG, MSG, k, 'key-encoding', k.slice(0, 8))
  }
  for (const v of [undefined, null, 1, {}, [KEY], { toString: () => KEY }, new String(KEY), bytes(KEY)]) {
    rejects(SIG, MSG, v, 'key-encoding', typeof v)
  }
})

test('points not on the curve are refused as key-point', () => {
  rejects(SIG, MSG, KEY.slice(0, -2) + (KEY.slice(-2) === '00' ? '01' : '00'), 'key-point', 'y changed')
  rejects(SIG, MSG, '04' + '00'.repeat(64), 'key-point', 'zeros')
  rejects(SIG, MSG, '04' + P + KEY.slice(66), 'key-point', 'x = p')
  rejects(SIG, MSG, '04' + KEY.slice(2, 66) + P, 'key-point', 'y = p')
})

test('a signature that is not a Uint8Array is refused as sig-encoding', () => {
  for (const v of [undefined, null, 'x', valid.sig, [...SIG], SIG.buffer, new DataView(SIG.buffer)]) {
    rejects(v, MSG, KEY, 'sig-encoding', typeof v)
  }
})

test('a message that is not a Uint8Array is a programming error', () => {
  for (const m of ['', [], null, undefined, MSG.buffer]) {
    assert.throws(() => checkP256(SIG, m, KEY), { name: 'TypeError', message: 'message must be a Uint8Array' })
  }
})

test('arbitrary values never throw and give a K6 reason', () => {
  const any = fc.oneof(fc.anything(), fc.uint8Array({ maxLength: 80 }), fc.stringMatching(/^04[0-9a-f]{128}$/))
  fc.assert(fc.property(any, any, fc.uint8Array({ maxLength: 40 }), (sig, key, msg) => {
    const r = checkP256(sig, msg, key)
    assert.ok(Object.isFrozen(r))
    if (!r.ok) assert.ok(REASONS.includes(r.reason))
  }), { seed: SEED, numRuns: RUNS })
})

function patched (obj, name, replacement, fn) {
  const original = obj[name]
  obj[name] = replacement
  try { return fn() } catch (e) { return { threw: String(e) } } finally { obj[name] = original }
}
const thrower = function () { throw new Error('patched') }

test('own built-ins are captured at load; those of the library can only make it fail closed', () => {
  const BAD = Uint8Array.from(SIG); BAD[BAD.length - 1] ^= 1
  const cases = [[SIG, KEY], [BAD, KEY], [SIG, 'zz']]
  const expected = cases.map(([s, k]) => result(s, MSG, k))
  for (const [obj, name, fn] of [[RegExp.prototype, 'exec', () => []], [String.prototype, 'charCodeAt', () => 48],
    [Reflect, 'apply', thrower], [Object, 'freeze', (x) => x], [String.prototype, 'slice', () => '']]) {
    assert.deepEqual(patched(obj, name, fn, () => cases.map(([s, k]) => result(s, MSG, k))), expected, name)
  }
  for (const [obj, name] of [[Uint8Array.prototype, 'subarray'], [Uint8Array.prototype, 'set'], [WeakMap.prototype, 'get'],
    [Array.prototype, 'push'], [globalThis, 'BigInt'], [globalThis, 'Uint8Array']]) {
    const got = patched(obj, name, thrower, () => cases.map(([s, k]) => result(s, MSG, k)))
    assert.ok(Array.isArray(got), `${name}: ${JSON.stringify(got)}`)
    got.forEach((r, i) => assert.ok(r.ok === false || expected[i].ok, `${name}: case ${i} became an accept`))
  }
})
