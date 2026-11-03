// P5 (E3): a record with one out-of-domain value planted anywhere is always refused with an EncodingError carrying a
// defined reason — never returned, never another kind of error.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { fc, record } from './arbitraries.mjs'
import { encode, EncodingError, REASONS } from './helpers.mjs'

const BAD = {
  null: () => null,
  undefined: () => undefined,
  float: () => 1.5,
  negativeZero: () => -0,
  nan: () => NaN,
  infinity: () => Infinity,
  unsafe: () => 2 ** 53,
  bigint: () => 10n,
  symbol: () => Symbol('x'),
  function: () => () => 1,
  date: () => new Date(0),
  map: () => new Map(),
  loneSurrogate: () => '\ud800',
  badKey: null, // planted as a key, not a value
}
const KINDS = Object.keys(BAD)

// Walks into v by `picks`, then plants the bad thing in the container reached.
function plant (v, kind, picks) {
  let at = v
  for (const p of picks) {
    const children = Object.values(at).filter((x) => x !== null && typeof x === 'object')
    if (children.length === 0) break
    at = children[p % children.length]
  }
  if (kind === 'badKey') {
    if (Array.isArray(at)) at.push({ Bad: 1 })
    else at.Bad = 1
  } else if (Array.isArray(at)) {
    at.push(BAD[kind]())
  } else {
    at.zzz_planted = BAD[kind]()
  }
  return v
}

test('refusal is total', () => {
  const seen = new Set()
  fc.assert(fc.property(record, fc.constantFrom(...KINDS), fc.array(fc.nat(), { maxLength: 4 }), (v, kind, picks) => {
    seen.add(kind)
    const bad = plant(v, kind, picks)
    let returned
    try {
      returned = encode(bad)
    } catch (e) {
      assert.ok(e instanceof EncodingError, `${kind}: non-EncodingError ${e?.constructor?.name}: ${e?.message}`)
      assert.ok(REASONS.includes(e.reason), `${kind}: undefined reason ${e.reason}`)
      return
    }
    assert.fail(`${kind}: encode returned ${JSON.stringify(returned)}`)
  }))
  assert.deepEqual([...seen].sort(), [...KINDS].sort(), 'every kind of bad value was planted')
})
