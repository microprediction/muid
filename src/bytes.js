// Byte and verdict helpers shared by the core, built only from built-ins captured at load (E7).
const { apply } = Reflect
const { create, freeze, getOwnPropertyDescriptor, getPrototypeOf, keys } = Object
const { charCodeAt } = String.prototype
const Bytes = Uint8Array
const tagOf = getOwnPropertyDescriptor(getPrototypeOf(Uint8Array.prototype), Symbol.toStringTag).get
const HEX = freeze(Array.from({ length: 256 }, (_, i) => (i < 16 ? '0' : '') + i.toString(16)))

// Lowercase hex of an even length, already checked by the caller.
export function fromHex (text) {
  const out = new Bytes(text.length / 2)
  // Stryker disable next-line EqualityOperator: equivalent; a write past the end of a typed array is ignored
  for (let i = 0; i < out.length; i++) {
    let byte = 0
    for (let j = 0; j < 2; j++) {
      const c = apply(charCodeAt, text, [2 * i + j])
      byte = byte * 16 + (c <= 57 ? c - 48 : c - 87)
    }
    out[i] = byte
  }
  return out
}

export function toHex (bytes) {
  let out = ''
  for (let i = 0; i < bytes.length; i++) out += HEX[bytes[i]]
  return out
}

// A copy made from the internal slots, so a subclass cannot change what is checked while it is being checked.
// Undefined for anything that is not a live Uint8Array (a detached buffer, a lookalike).
export function snapshot (x) {
  // Stryker disable next-line ArrayDeclaration: equivalent; a getter takes no arguments
  if (apply(tagOf, x, []) !== 'Uint8Array') return undefined
  try {
    return new Bytes(x)
  } catch { /* detached */ }
  return undefined
}

export function refuse (reason) {
  const out = create(null)
  out.ok = false
  out.reason = reason
  return freeze(out)
}

// { ok: true } and any fields given, in their order: their own, never inherited (a polluted prototype adds nothing).
export function accept (fields) {
  const out = create(null)
  out.ok = true
  const ks = fields === undefined ? [] : keys(fields)
  for (let i = 0; i < ks.length; i++) out[ks[i]] = fields[ks[i]]
  return freeze(out)
}

// { ok: true } for no reason, else the refusal.
export const verdict = (reason) => (reason === undefined ? accept() : refuse(reason))
