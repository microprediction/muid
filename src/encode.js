// Canonical encoding (SPEC §3): RFC 8785 (JCS) over a restricted value domain.
//
// E1 INJECTIVE         distinct values encode to distinct bytes.
// E2 CANONICAL INPUT   decode(t) succeeds only if encode(decode(t)) === t, byte for byte.
// E3 TOTAL OR REFUSED  a value outside the domain throws EncodingError; nothing is dropped or converted.
// E4 BOUNDED           at most MAX_BYTES of UTF-8 and MAX_DEPTH levels; encoding stops as soon as either is exceeded.
// E5 ONE REASON        a refusal carries exactly one reason, found in the order SPEC §3 defines.
//
// Domain: plain objects (keys ^[a-z][a-z0-9_]{0,31}$), dense plain arrays, well-formed strings, safe integers (no -0),
// true, false. No null, no floats. The top level is a plain object.

export const MAX_BYTES = 65536
export const MAX_DEPTH = 16

const KEY = /^[a-z][a-z0-9_]{0,31}$/

export class EncodingError extends Error {
  constructor (reason) {
    super(`encoding refused: ${reason}`) // the message never carries the data being refused
    this.name = 'EncodingError'
    this.reason = reason
  }
}

function fail (reason) {
  throw new EncodingError(reason)
}

// UTF-8 length of a string. A lone surrogate (only possible in decode input) counts as 3 bytes.
function utf8Length (s) {
  let n = 0
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c < 0x80) n += 1
    else if (c < 0x800) n += 2
    else if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
      const d = s.charCodeAt(i + 1)
      if (d >= 0xdc00 && d <= 0xdfff) { n += 4; i++ } else n += 3
    } else n += 3
  }
  return n
}

function isPlainObject (v) {
  if (v === null || typeof v !== 'object' || Array.isArray(v)) return false
  const proto = Object.getPrototypeOf(v)
  return proto === Object.prototype || proto === null
}

// Reads one own data property. Accessors are refused without being invoked.
function dataValue (container, key) {
  const d = Object.getOwnPropertyDescriptor(container, key)
  if ('get' in d || 'set' in d) fail('accessor')
  if (!d.enumerable) fail('non-enumerable')
  return d.value
}

class Writer {
  constructor () {
    this.parts = []
    this.bytes = 0
    this.path = new Set()
  }

  emit (s) {
    this.bytes += utf8Length(s)
    if (this.bytes > MAX_BYTES) fail('size')
    this.parts.push(s)
  }

  value (x, depth) {
    switch (typeof x) {
      case 'string':
        if (!x.isWellFormed()) fail('surrogate')
        if (x.length > MAX_BYTES) fail('size') // its encoding alone would exceed the limit
        this.emit(JSON.stringify(x))
        return
      case 'number':
        if (!Number.isFinite(x)) fail('non-finite')
        if (Object.is(x, -0)) fail('negative-zero')
        if (!Number.isInteger(x)) fail('float')
        if (!Number.isSafeInteger(x)) fail('unsafe-integer')
        this.emit(String(x))
        return
      case 'boolean':
        this.emit(x ? 'true' : 'false')
        return
      case 'undefined':
        fail('undefined')
        return
      case 'object':
        if (x === null) fail('null')
        this.container(x, depth + 1)
        return
      default: // bigint, symbol, function
        fail('type')
    }
  }

  container (v, depth) {
    if (this.path.has(v)) fail('cycle')
    if (depth > MAX_DEPTH) fail('depth')
    this.path.add(v)
    if (Array.isArray(v)) this.array(v, depth)
    else this.object(v, depth)
    this.path.delete(v)
  }

  array (a, depth) {
    if (Object.getPrototypeOf(a) !== Array.prototype) fail('non-plain')
    // Own keys must be exactly the indices 0..length-1 plus "length": no holes, no extra or symbol properties.
    if (Reflect.ownKeys(a).length !== a.length + 1) fail('array-shape')
    for (let i = 0; i < a.length; i++) if (!Object.hasOwn(a, i)) fail('array-shape')
    this.emit('[')
    for (let i = 0; i < a.length; i++) {
      if (i > 0) this.emit(',')
      this.value(dataValue(a, i), depth)
    }
    this.emit(']')
  }

  object (o, depth) {
    if (!isPlainObject(o)) fail('non-plain')
    if (Object.getOwnPropertySymbols(o).length > 0) fail('symbol-key')
    // Every own string key, enumerable or not, in UTF-16 code-unit order (RFC 8785 §3.2.3).
    const keys = Object.getOwnPropertyNames(o).sort()
    this.emit('{')
    for (let i = 0; i < keys.length; i++) {
      const k = keys[i]
      if (!KEY.test(k)) fail('key')
      const x = dataValue(o, k)
      if (i > 0) this.emit(',')
      this.emit('"' + k + '":') // the key grammar is ASCII with nothing to escape
      this.value(x, depth)
    }
    this.emit('}')
  }
}

export function encode (value) {
  if (!isPlainObject(value)) fail('top-level')
  const w = new Writer()
  w.container(value, 1)
  return w.parts.join('')
}

function deepFreeze (v) {
  if (v !== null && typeof v === 'object') {
    for (const x of Object.values(v)) deepFreeze(x)
    Object.freeze(v)
  }
  return v
}

export function decode (text) {
  if (typeof text !== 'string') fail('type')
  if (text.length > MAX_BYTES || utf8Length(text) > MAX_BYTES) fail('size')
  let value
  try {
    value = JSON.parse(text)
  } catch {
    fail('syntax')
  }
  if (encode(value) !== text) fail('non-canonical')
  return deepFreeze(value)
}
