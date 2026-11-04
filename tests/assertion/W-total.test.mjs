// K2 for assertions: no sig value throws; built-ins captured at load.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import fc from 'fast-check'
import { checkRootAssertion, make, result, REASONS, CTX } from './helpers.mjs'

const SEED = Number(process.env.FC_SEED ?? 20261103)
const RUNS = Number(process.env.FC_RUNS ?? 300)
const ok = make()

test('arbitrary values and mutated assertions never throw and give a W6 reason', () => {
  const field = fc.oneof(fc.string(), fc.base64String(), fc.anything())
  const mutated = fc.record({ k: fc.constantFrom('covers', 'authenticator_data', 'client_data_json', 'signature'), v: field })
    .map(({ k, v }) => ({ ...ok, [k]: v }))
  fc.assert(fc.property(fc.oneof(fc.anything(), mutated), (sig) => {
    const r = checkRootAssertion(sig, CTX)
    assert.ok(Object.isFrozen(r))
    if (!r.ok) assert.ok(REASONS.includes(r.reason), r.reason)
  }), { seed: SEED, numRuns: RUNS })
})

test('a proxy or accessor in sig cannot throw or be read twice into different answers', () => {
  const p = new Proxy(ok, { get () { throw new Error('trap') }, ownKeys () { throw new Error('trap') } })
  assert.equal(result(p).ok, false)
  let reads = 0
  const flip = { ...ok }
  Object.defineProperty(flip, 'client_data_json', { enumerable: true, get () { return reads++ ? 'AAAA' : ok.client_data_json } })
  assert.equal(result(flip).ok, false)
})

function patched (obj, name, replacement, fn) {
  const original = obj[name]
  obj[name] = replacement
  try { return fn() } catch (e) { return { threw: String(e) } } finally { obj[name] = original }
}

test('built-ins the module uses are captured at load: patching them later changes no result', () => {
  const bad = { ...ok, covers: ['b'.repeat(64)] }
  const expected = [result(ok), result(bad)]
  for (const [obj, name, fn] of [
    [String.prototype, 'startsWith', () => true], [String.prototype, 'charCodeAt', () => 65], [String.prototype, 'slice', () => ''],
    [Array.prototype, 'includes', () => true],
    [JSON, 'parse', () => ({})], [RegExp.prototype, 'exec', () => []],
    [TextDecoder.prototype, 'decode', () => ''], [TextEncoder.prototype, 'encode', () => new Uint8Array(0)],
  ]) {
    assert.deepEqual(patched(obj, name, fn, () => [result(ok), result(bad)]), expected, name)
  }
  // Built-ins the libraries call (Array.isArray among them) can only make it fail closed.
  for (const [obj, name, fn] of [[Object, 'keys', () => []], [Array, 'isArray', () => true], [Array, 'isArray', () => false], [Uint8Array.prototype, 'subarray', () => { throw new Error('x') }]]) {
    const got = patched(obj, name, fn, () => [result(ok), result(bad)])
    assert.ok(Array.isArray(got), `${name}: ${JSON.stringify(got)}`)
    assert.equal(got[1].ok, false, `${name}: a refusal became an accept`)
    for (const r of got) if (!r.ok) assert.ok(REASONS.includes(r.reason))
    if (name === 'subarray') assert.deepEqual(got[0], { ok: false, reason: 'sig-invalid' }, 'a hash failure is a refusal')
  }
})
