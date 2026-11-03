// Generators for the encoding properties. Imports nothing from the implementation.
import fc from 'fast-check'

// Fixed seed in CI; FC_SEED / FC_RUNS override it (mutation testing lowers the run count).
fc.configureGlobal({
  seed: Number(process.env.FC_SEED ?? 20261102),
  numRuns: Number(process.env.FC_RUNS ?? 500),
})

export { fc }

export const key = fc.stringMatching(/^[a-z][a-z0-9_]{0,31}$/)

const special = fc.constantFrom(
  '\u0000', '\u0001', '\u000f', '\u001f', '\b', '\f', '\n', '\r', '\t', '"', '\\', '/', '\u007f', '\u0080',
  ' ', ' ', '﻿', 'é', '\u{1F600}', '</script>', 'a',
)
export const str = fc.oneof(
  fc.string({ unit: 'binary', maxLength: 12 }),
  fc.string({ unit: special, maxLength: 6 }),
  fc.string({ maxLength: 8 }),
).filter((s) => s.isWellFormed())

export const int = fc.oneof(
  fc.maxSafeInteger(),
  fc.integer({ min: -1000, max: 1000 }),
  fc.constantFrom(0, 1, -1, 2 ** 53 - 1, -(2 ** 53 - 1), 2 ** 31, -(2 ** 31), 2 ** 32),
).filter((n) => !Object.is(n, -0))

const leaf = fc.oneof(str, int, fc.boolean())

// In-domain records: plain objects at the top, nesting at most 6 deep (well inside MAX_DEPTH), small enough to stay
// far below MAX_BYTES.
export const { record } = fc.letrec((tie) => ({
  node: fc.oneof({ maxDepth: 5, depthIdentifier: 'rec' }, leaf, tie('array'), tie('object')),
  array: fc.array(tie('node'), { maxLength: 3, depthIdentifier: 'rec' }),
  object: fc.dictionary(key, tie('node'), { maxKeys: 3, noNullPrototype: true, depthIdentifier: 'rec' }),
  record: fc.dictionary(key, tie('node'), { maxKeys: 4, noNullPrototype: true }),
}))

// Shape statistics, so a property can assert its inputs were not trivial.
export function shape (v, depth = 1, acc = { depth: 0, nonAscii: false, containers: 0 }) {
  if (v !== null && typeof v === 'object') {
    acc.containers++
    acc.depth = Math.max(acc.depth, depth)
    for (const [k, x] of Object.entries(v)) {
      if (/[^\x00-\x7f]/.test(k)) acc.nonAscii = true
      shape(x, depth + 1, acc)
    }
  } else if (typeof v === 'string' && /[^\x00-\x7f]/.test(v)) {
    acc.nonAscii = true
  }
  return acc
}

// A copy of v with keys inserted in a different order at every level, chosen by `seed`.
export function reorder (v, seed) {
  let s = seed >>> 0
  const next = () => (s = (Math.imul(s, 1664525) + 1013904223) >>> 0)
  const walk = (x) => {
    if (Array.isArray(x)) return x.map(walk)
    if (x !== null && typeof x === 'object') {
      const keys = Object.keys(x)
      for (let i = keys.length - 1; i > 0; i--) {
        const j = next() % (i + 1)
        ;[keys[i], keys[j]] = [keys[j], keys[i]]
      }
      const out = {}
      for (const k of keys) out[k] = walk(x[k])
      return out
    }
    return x
  }
  return walk(v)
}
