// §4 residual, systematically (TESTING.md §4g): code that patches a built-in after the core has loaded cannot turn a
// result into another, except by failing closed. `sweep` replaces every function on the standard prototypes and
// namespaces, one at a time, by a hostile stand-in (one that throws, one that answers true, one that returns its
// receiver), runs each case under it, and lists every case whose result changed other than to a refusal or a throw.
//
// While a built-in is patched nothing here uses it: results are written by index into an array made beforehand and
// compared once everything is restored; the two property functions are captured first.
const { defineProperty, getOwnPropertyDescriptor } = Object

const HOLDERS = [
  ['Array.prototype', Array.prototype], ['String.prototype', String.prototype], ['RegExp.prototype', RegExp.prototype],
  ['Object.prototype', Object.prototype], ['Number.prototype', Number.prototype], ['Uint8Array.prototype', Uint8Array.prototype],
  ['TypedArray.prototype', Object.getPrototypeOf(Uint8Array.prototype)], ['ArrayBuffer.prototype', ArrayBuffer.prototype],
  ['DataView.prototype', DataView.prototype], ['Map.prototype', Map.prototype], ['Set.prototype', Set.prototype],
  ['TextEncoder.prototype', TextEncoder.prototype], ['TextDecoder.prototype', TextDecoder.prototype],
  ['BigInt.prototype', BigInt.prototype], ['Error.prototype', Error.prototype],
  ['Object', Object], ['Array', Array], ['String', String], ['Number', Number], ['Math', Math], ['JSON', JSON],
  ['Reflect', Reflect], ['BigInt', BigInt], ['Uint8Array', Uint8Array], ['ArrayBuffer', ArrayBuffer],
]
export const TARGETS = HOLDERS.flatMap(([name, holder]) => Reflect.ownKeys(holder)
  .filter((k) => k !== 'constructor' && typeof k === 'string')
  .filter((k) => { const d = getOwnPropertyDescriptor(holder, k); return d && typeof d.value === 'function' && (d.writable || d.configurable) })
  .map((k) => [`${name}.${k}`, holder, k]))

const HOSTILE = [
  ['throws', () => function () { throw new Error('patched') }],
  ['true', () => function () { return true }],
  ['receiver', () => function () { return this }],
]

export const THREW = 'threw'

// The cases run under one patch: each case's `run()` result passed through `describe` (which must give a string),
// or THREW.
function under (holder, key, replacement, cases, describe) {
  const results = new Array(cases.length)
  const saved = getOwnPropertyDescriptor(holder, key)
  defineProperty(holder, key, { configurable: saved.configurable, enumerable: saved.enumerable, writable: saved.writable, value: replacement })
  try {
    for (let i = 0; i < cases.length; i++) {
      try {
        results[i] = describe(cases[i].run())
      } catch {
        results[i] = THREW
      }
    }
  } finally {
    defineProperty(holder, key, saved)
  }
  return results
}

// { base, changed, failedClosed }: the unpatched results; every 'built-in how: case → result' that is neither the
// unpatched result nor closed (closed(result) true, or a throw); and how many results failed closed instead.
export function sweep (cases, describe, closed) {
  const base = under(Object, 'keys', Object.keys, cases, describe) // the same function: a patch that changes nothing
  const changed = []
  let failedClosed = 0
  for (const [name, holder, key] of TARGETS) {
    for (const [how, make] of HOSTILE) {
      const r = under(holder, key, make(), cases, describe)
      for (let i = 0; i < cases.length; i++) {
        if (r[i] === base[i]) continue
        if (r[i] === THREW || closed(r[i])) failedClosed++
        else changed.push(`${name} ${how}: ${cases[i].name} → ${r[i]} (unpatched ${base[i]})`)
      }
    }
  }
  return { base, changed, failedClosed }
}
