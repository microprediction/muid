// Shared byte helpers of the core: lowercase hex both ways, byte snapshots, and frozen verdicts.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import vm from 'node:vm'
import fc from 'fast-check'
import { bytes } from '../impl.mjs'
import { runs } from '../runs.mjs'

const { fromHex, toHex, snapshot, refuse, accept, verdict } = bytes
const SEED = Number(process.env.FC_SEED ?? 20261103)
const RUNS = runs(300)

test('fromHex and toHex agree with Buffer for every byte value and for generated arrays', () => {
  const all = Uint8Array.from({ length: 256 }, (_, i) => i)
  assert.equal(toHex(all), Buffer.from(all).toString('hex'))
  assert.deepEqual(Buffer.from(fromHex(Buffer.from(all).toString('hex'))), Buffer.from(all))
  fc.assert(fc.property(fc.uint8Array({ maxLength: 100 }), (b) => {
    const h = Buffer.from(b).toString('hex')
    assert.equal(toHex(b), h)
    assert.deepEqual(Buffer.from(fromHex(h)), Buffer.from(b))
    assert.ok(fromHex(h) instanceof Uint8Array)
  }), { seed: SEED, numRuns: RUNS })
})

test('snapshot copies a live Uint8Array from its internal slots, and refuses everything else', () => {
  const src = Uint8Array.from([1, 2, 3])
  const copy = snapshot(src)
  assert.deepEqual([...copy], [1, 2, 3])
  src[0] = 9
  assert.equal(copy[0], 1, 'a copy, not a view')
  class Liar extends Uint8Array { get length () { return 99 } }
  assert.equal(snapshot(new Liar([1, 2])).length, 2)
  assert.equal(Object.getPrototypeOf(snapshot(new Liar([1]))), Uint8Array.prototype)
  assert.deepEqual([...snapshot(vm.runInNewContext('new Uint8Array([7])'))], [7])
  const detached = new Uint8Array(4)
  structuredClone(detached.buffer, { transfer: [detached.buffer] })
  for (const x of [detached, [1], 'ab', null, undefined, new Uint16Array(2), new DataView(new ArrayBuffer(2)), { length: 1 },
    Object.create(Uint8Array.prototype)].entries()) {
    assert.equal(snapshot(x[1]), undefined, `case ${x[0]}`)
  }
})

test('refuse and accept build frozen, null-prototype verdicts', () => {
  const no = refuse('why')
  assert.deepEqual({ ...no }, { ok: false, reason: 'why' })
  assert.deepEqual(Object.keys(no), ['ok', 'reason'])
  const yes = accept({ id: 'x', body: 1 })
  assert.deepEqual({ ...yes }, { ok: true, id: 'x', body: 1 })
  assert.deepEqual(Object.keys(yes), ['ok', 'id', 'body'])
  assert.deepEqual(Object.keys(accept()), ['ok'])
  assert.deepEqual({ ...verdict(undefined) }, { ok: true })
  assert.deepEqual({ ...verdict('r') }, { ok: false, reason: 'r' })
  assert.ok(Object.isFrozen(verdict()) && Object.isFrozen(verdict('r')))
  for (const v of [no, yes]) {
    assert.ok(Object.isFrozen(v))
    assert.equal(Object.getPrototypeOf(v), null)
  }
})

test('built-ins are captured at load: patching them later changes no result', () => {
  const h = 'ff00a5'
  const b = Uint8Array.from([255, 0, 165])
  const run = () => [toHex(b), [...fromHex(h)], [...snapshot(b)], { ...refuse('r') }]
  const expected = run()
  for (const [obj, name, fn] of [[String.prototype, 'charCodeAt', () => 48], [globalThis, 'Uint8Array', function () { throw new Error('x') }],
    [Object, 'freeze', (x) => x], [Object, 'create', () => ({ poisoned: true })], [Reflect, 'apply', () => 'x'],
    [Number.prototype, 'toString', () => 'z']]) {
    const original = obj[name]
    obj[name] = fn
    let got
    try { got = run() } catch (e) { got = String(e) } finally { obj[name] = original }
    assert.deepEqual(got, expected, name)
  }
})

// Found by review: accept copied fields with for-in, so properties inherited from a polluted Object.prototype were
// copied into every verdict, and a polluted `ok` overwrote it.
test('accept copies only the fields given, never inherited ones', () => {
  Object.prototype.until = 1 // eslint-disable-line no-extend-native
  Object.prototype.ok = false // eslint-disable-line no-extend-native
  try {
    const yes = accept({ id: 'x' })
    assert.deepEqual(Object.keys(yes), ['ok', 'id'])
    assert.equal(yes.ok, true)
    assert.equal(Object.getPrototypeOf(yes), null)
    assert.deepEqual(Object.keys(accept()), ['ok'])
  } finally {
    delete Object.prototype.until
    delete Object.prototype.ok
  }
})
