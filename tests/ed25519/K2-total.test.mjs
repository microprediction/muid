// K2, K5: for any sig and key value the result is a frozen { ok, reason? } with a K5 reason — never a throw. Hex must
// be exactly lowercase, of the exact length.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import fc from 'fast-check'
import { checkEd25519, REASONS, rejects } from './helpers.mjs'

const SEED = Number(process.env.FC_SEED ?? 20261103)
const RUNS = Number(process.env.FC_RUNS ?? 300)
const KEY = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a' // RFC 8032 TEST 1
const SIG = 'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b'
const EMPTY = new Uint8Array(0)

function shaped (r) {
  assert.ok(Object.isFrozen(r))
  if (r.ok) assert.deepEqual(Object.keys(r), ['ok'])
  else {
    assert.deepEqual(Object.keys(r), ['ok', 'reason'])
    assert.ok(REASONS.includes(r.reason), r.reason)
  }
}

test('the RFC vector is the control', () => assert.deepEqual({ ...checkEd25519(SIG, EMPTY, KEY) }, { ok: true }))

test('arbitrary values as sig and key give a well-shaped result, never a throw', () => {
  const any = fc.oneof(fc.string(), fc.hexaString?.() ?? fc.string(), fc.anything(), fc.uint8Array(),
    fc.stringMatching(/^[0-9a-f]{64}$/), fc.stringMatching(/^[0-9a-f]{128}$/))
  fc.assert(fc.property(any, any, fc.uint8Array({ maxLength: 64 }), (sig, key, msg) => {
    shaped(checkEd25519(sig, msg, key))
  }), { seed: SEED, numRuns: RUNS })
})

test('random well-formed hex keys and signatures are rejected with a K5 reason, never a throw', () => {
  let keyStage = 0
  fc.assert(fc.property(fc.stringMatching(/^[0-9a-f]{128}$/), fc.stringMatching(/^[0-9a-f]{64}$/), (sig, key) => {
    const r = checkEd25519(sig, EMPTY, key)
    shaped(r)
    assert.equal(r.ok, false)
    if (r.reason.startsWith('key-')) keyStage++
  }), { seed: SEED, numRuns: RUNS })
  assert.ok(keyStage < RUNS, 'some random keys get past the key checks')
})

test('hex that is not exactly lowercase of the right length is an encoding refusal', () => {
  const bad = (h) => [h.toUpperCase(), h.slice(1), h + '0', h + '00', '0x' + h.slice(2), ' ' + h.slice(1), h.slice(0, -1) + 'g', '']
  for (const k of bad(KEY)) rejects(SIG, EMPTY, k, 'key-encoding', JSON.stringify(k))
  for (const s of bad(SIG)) rejects(s, EMPTY, KEY, 'sig-encoding', JSON.stringify(s))
  for (const v of [undefined, null, 1, {}, [], new Uint8Array(32)]) {
    rejects(SIG, EMPTY, v, 'key-encoding', String(v))
    rejects(v, EMPTY, KEY, 'sig-encoding', String(v))
  }
  // Values that turn into valid hex when converted to a string are still not strings.
  const like = (h) => [[h], { toString: () => h }, new String(h)]
  for (const k of like(KEY)) rejects(SIG, EMPTY, k, 'key-encoding', 'key-like ' + typeof k)
  for (const s of like(SIG)) rejects(s, EMPTY, KEY, 'sig-encoding', 'sig-like ' + typeof s)
})

test('a message that is not a Uint8Array is a programming error', () => {
  for (const m of ['', [], null, undefined, Buffer.from('').buffer]) {
    assert.throws(() => checkEd25519(SIG, m, KEY), { name: 'TypeError', message: 'message must be a Uint8Array' }, String(m))
  }
})

test('key checks come before signature checks', () => {
  rejects('not hex', EMPTY, 'not hex', 'key-encoding', 'both bad')
  rejects('not hex', EMPTY, '0100000000000000000000000000000000000000000000000000000000000000', 'key-small-order', 'bad sig, small key')
})

// Patch a built-in for the duration of fn; results are compared after restoring.
function patched (obj, name, replacement, fn) {
  const original = obj[name]
  obj[name] = replacement
  try { return fn() } catch (e) { return { threw: String(e) } } finally { obj[name] = original }
}
const thrower = function () { throw new Error('patched') }

test('a throw from inside the library becomes a reason, never escapes (K2)', () => {
  // The library's Point prototype is frozen; it still calls shared built-ins. WeakMap#get is reached only through
  // the point checks, Uint8Array#fill only inside verify (its hash).
  const point = patched(WeakMap.prototype, 'get', thrower, () => ({ ...checkEd25519(SIG, EMPTY, KEY) }))
  // Array#push is reached only after decoding, in the order checks.
  const order = patched(Array.prototype, 'push', thrower, () => ({ ...checkEd25519(SIG, EMPTY, KEY) }))
  assert.deepEqual(order, { ok: false, reason: 'key-point' })
  const verify = patched(Uint8Array.prototype, 'fill', thrower, () => ({ ...checkEd25519(SIG, EMPTY, KEY) }))
  assert.deepEqual(point, { ok: false, reason: 'key-point' })
  assert.deepEqual(verify, { ok: false, reason: 'sig-invalid' })
  assert.deepEqual({ ...checkEd25519(SIG, EMPTY, KEY) }, { ok: true }, 'restored')
})

test('built-ins this module uses are captured at load: patching them later changes no result (E7)', () => {
  const BAD = SIG.slice(0, 127) + (SIG[127] === '0' ? '1' : '0')
  const cases = [[SIG, KEY, 'ok'], [BAD, KEY, 'sig-invalid'], ['zz', KEY, 'sig-encoding'], [SIG, 'zz', 'key-encoding']]
  const expected = cases.map(([s, k]) => ({ ...checkEd25519(s, EMPTY, k) }))
  const G = globalThis
  const patches = [
    [String.prototype, 'charCodeAt', function () { return 48 }],
    [RegExp.prototype, 'exec', function () { return [] }],
    [RegExp.prototype, 'test', function () { return true }],
    [Reflect, 'apply', thrower],
    [Object, 'freeze', (x) => x],
    [Object, 'create', thrower],
  ]
  for (const [obj, name, replacement] of patches) {
    const got = patched(obj, name, replacement, () => cases.map(([s, k]) => ({ ...checkEd25519(s, EMPTY, k) })))
    assert.deepEqual(got, expected, `after patching ${name}`)
  }
  assert.equal(expected[0].ok, true)
  assert.equal(expected[1].reason, 'sig-invalid')

  // Built-ins the library itself calls can only make it fail closed: never a throw, never a new accept.
  for (const [obj, name] of [[Uint8Array.prototype, 'subarray'], [Uint8Array.prototype, 'fill'],
    [Uint8Array.prototype, 'set'], [WeakMap.prototype, 'get'], [Array.prototype, 'push'], [G, 'BigInt'],
    [G, 'Uint8Array']]) {
    const got = patched(obj, name, thrower, () => cases.map(([s, k]) => ({ ...checkEd25519(s, EMPTY, k) })))
    assert.ok(Array.isArray(got), `${name}: ${JSON.stringify(got)}`)
    got.forEach((r, i) => assert.ok(r.ok === false || expected[i].ok === true, `${name}: case ${i} became an accept`))
  }
})
