// Broken twin: JSON.stringify with sorted keys and no domain checks at all (TESTING.md §2.4, twin 1).
export const MAX_BYTES = 65536
export const MAX_DEPTH = 16

export class EncodingError extends Error {
  constructor (reason) {
    super(reason)
    this.reason = reason
  }
}

const sortKeys = (v) => Array.isArray(v) ? v.map(sortKeys)
  : v && typeof v === 'object' ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, sortKeys(v[k])])) : v

export function encode (value) {
  return JSON.stringify(sortKeys(value))
}

export function decode (text) {
  return JSON.parse(text)
}
