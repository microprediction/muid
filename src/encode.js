// Canonical encoding (SPEC §3): RFC 8785 (JCS) over a restricted value domain.
//
// E1 INJECTIVE         distinct values encode to distinct bytes.
// E2 CANONICAL INPUT   decode(t) succeeds only if encode(decode(t)) === t, byte for byte.
// E3 TOTAL OR REFUSED  a value outside the domain throws EncodingError; nothing is dropped or converted, and nothing
//                      but an EncodingError ever leaves encode or decode.
// E4 BOUNDED           at most MAX_BYTES of UTF-8 and MAX_DEPTH levels; work stops as soon as either is exceeded,
//                      and no container or string is enumerated or copied past what the limit allows.
// E5 ONE REASON        a refusal carries exactly one reason, found in the order SPEC §3 defines.
// E6 READ ONCE         every property descriptor, prototype, key list and array length is read exactly once.
// E7 OWN INTRINSICS    only built-ins captured when this module loaded are used; later patching changes nothing.
// E8 NULL PROTOTYPES   decoded objects and arrays have null prototypes and are deeply frozen.
//
// Domain (SPEC §3): plain objects (keys ^[a-z][a-z0-9_]{0,31}$), dense plain arrays, well-formed strings, safe
// integers (no -0), true, false; the top level is a plain object. "Plain": prototype Object.prototype or null
// (Array.prototype or null for arrays), no internal slots. A Proxy can choose only what is encoded, as any caller can.

// E7: captured at load. Object.defineProperty and setPrototypeOf throw on failure; Reflect's return false silently.
const { apply, ownKeys, getPrototypeOf } = Reflect
const { getOwnPropertyDescriptor, hasOwn, is, freeze, create, defineProperty, setPrototypeOf } = Object
const { isArray } = Array
const { isFinite, isInteger, isSafeInteger } = Number
const { isView } = ArrayBuffer
const stringify = JSON.stringify
const parse = JSON.parse
const ObjectPrototype = Object.prototype
const ArrayPrototype = Array.prototype
const sort = Array.prototype.sort
const charCodeAt = String.prototype.charCodeAt
const isWellFormed = String.prototype.isWellFormed
const exec = RegExp.prototype.exec
const SetCtor = Set
const setHas = Set.prototype.has
const setAdd = Set.prototype.add
const setDelete = Set.prototype.delete
// Every function applied with NO_ARGS ignores its arguments.
// Stryker disable next-line ArrayDeclaration: equivalent; see the line above.
const NO_ARGS = freeze([])

// Internal slots (E3). Object.prototype.toString reports the slot of a Number, String or Boolean wrapper, Date, RegExp,
// Error or arguments object whatever its prototype, and isView finds typed arrays and DataView. toString first reads
// Symbol.toStringTag, which page code can define (an accessor would run), so an object that can reach one is not
// shown plain. Other slots need brand checks that throw, about a thousand times slower on every plain object (SPEC §3,
// residual; pinned by tests/encoding/H3-exotic-objects.test.mjs).
const toString = Object.prototype.toString
const toStringTag = Symbol.toStringTag

export const MAX_BYTES = 65536
export const MAX_DEPTH = 16

const KEY = /^[a-z][a-z0-9_]{0,31}$/

// A refusal is recognised by an unforgeable private brand, never by instanceof or a property. The class and its
// prototype are frozen, so neither the brand test nor the name can be replaced.
export class EncodingError extends Error {
  #refusal
  static isRefusal (e) {
    return typeof e === 'object' && e !== null && #refusal in e
  }

  constructor (reason) {
    super(`encoding refused: ${reason}`) // the message never carries the data being refused
    defineProperty(this, 'reason', { __proto__: null, value: reason, enumerable: true }) // read-only
  }
}
defineProperty(EncodingError.prototype, 'name', { __proto__: null, value: 'EncodingError' })
freeze(EncodingError)
freeze(EncodingError.prototype)

function fail (reason) {
  throw new EncodingError(reason)
}

// UTF-8 length of a string, or with `json` of its JSON escaping: `"`, `\\`, \b \t \n \f \r take 2 bytes, other controls 6.
// A lone surrogate (only possible in decode input) counts as 3 bytes. Past the end of the string charCodeAt returns
// NaN, which fails the low-surrogate range test, so a final high surrogate counts as 3.
function utf8Length (s, json) {
  let n = 0
  for (let i = 0; i < s.length; i++) {
    const c = apply(charCodeAt, s, [i])
    if (c < 0x80) n += !json || (c >= 0x20 && c !== 0x22 && c !== 0x5c) ? 1 : c === 0x22 || c === 0x5c || (c > 7 && c < 14 && c !== 11) ? 2 : 6
    else if (c < 0x800) n += 2
    else if (c >= 0xd800 && c <= 0xdbff) {
      const d = apply(charCodeAt, s, [i + 1])
      if (d >= 0xdc00 && d <= 0xdfff) { n += 4; i++ } else n += 3
    } else n += 3
  }
  return n
}

function hasInternalSlot (v, proto) {
  if (hasOwn(v, toStringTag) || (proto !== null && hasOwn(ObjectPrototype, toStringTag))) return true
  return isView(v) || apply(toString, v, NO_ARGS) !== '[object Object]'
}

// The value of a property, from its one descriptor read. Accessors are refused without being invoked: a descriptor
// is a data descriptor exactly when it has its own `value`.
// A key listed by ownKeys yet without a descriptor (only a Proxy can do this) makes hasOwn throw: refused as exotic.
function dataValue (d) {
  if (!hasOwn(d, 'value')) fail('accessor')
  if (!d.enumerable) fail('non-enumerable')
  return d.value
}

class Writer {
  constructor () {
    this.out = ''
    this.bytes = 0
    this.path = new SetCtor()
  }

  emit (s, n = utf8Length(s)) { // n: the UTF-8 length of s, when already measured
    this.bytes += n
    if (this.bytes > MAX_BYTES) fail('size')
    this.out += s
  }

  value (x, depth) {
    switch (typeof x) {
      case 'string': {
        if (!apply(isWellFormed, x, NO_ARGS)) fail('surrogate')
        // Stryker disable next-line ArithmeticOperator: bounds the scan below (quotes, a byte after); weaker only defers.
        if (this.bytes + x.length + 3 > MAX_BYTES) fail('size')
        const n = utf8Length(x, true) + 2 // its JSON text, quotes included, measured before the text is built
        if (this.bytes + n + 1 > MAX_BYTES) fail('size')
        this.emit(stringify(x), n)
        return
      }
      case 'number':
        if (!isFinite(x)) fail('non-finite')
        if (is(x, -0)) fail('negative-zero')
        if (!isInteger(x)) fail('float')
        if (!isSafeInteger(x)) fail('unsafe-integer')
        this.emit('' + x)
        return
      case 'boolean':
        this.emit(x ? 'true' : 'false')
        return
      case 'undefined':
        fail('undefined')
        return
      case 'object':
        if (x === null) fail('null')
        this.container(x, depth + 1, false)
        return
      default: // bigint, symbol, function
        fail('type')
    }
  }

  // E5 order on entry: cycle, depth, plainness, width, shape; then members.
  container (v, depth, top) {
    if (apply(setHas, this.path, [v])) fail('cycle')
    if (depth > MAX_DEPTH) fail('depth')
    apply(setAdd, this.path, [v])
    const array = isArray(v)
    const proto = getPrototypeOf(v)
    const plain = proto === null || proto === (array ? ArrayPrototype : ObjectPrototype)
    if (array && top) fail('top-level')
    if (!plain || (!array && hasInternalSlot(v, proto))) fail(top ? 'top-level' : 'non-plain')
    if (array) this.array(v, depth)
    else this.object(v, depth)
    apply(setDelete, this.path, [v])
  }

  array (a, depth) {
    const length = a.length
    if (!isSafeInteger(length) || length < 0) fail('exotic')
    // At least one byte per element, the commas between them and the brackets (2L + 1 for L ≥ 1, 2 for L = 0),
    // then at least one byte after the array.
    // Stryker disable next-line ArithmeticOperator: a weaker bound only defers the refusal to emit().
    if (this.bytes + 2 * length + 2 > MAX_BYTES) fail('size')
    // Own keys must be exactly the indices 0..length-1 plus "length": no holes, no extra or symbol properties.
    if (ownKeys(a).length !== length + 1) fail('array-shape')
    // Stryker disable next-line ArrayDeclaration: every index of the array is assigned below before it is read.
    const descriptors = []
    for (let i = 0; i < length; i++) {
      const d = getOwnPropertyDescriptor(a, i)
      if (d === undefined) fail('array-shape')
      descriptors[i] = d
    }
    this.emit('[')
    for (let i = 0; i < length; i++) {
      if (i > 0) this.emit(',')
      this.value(dataValue(descriptors[i]), depth)
    }
    this.emit(']')
  }

  object (o, depth) {
    const keys = ownKeys(o) // every own key, enumerable or not, strings and symbols, in one read
    // At least `"a":0` per member, the commas between them and the braces. The bound is never attained for more than
    // 26 keys, which cannot all be one letter, so > and >= (or ±1) cannot be told apart by any value.
    // Stryker disable next-line EqualityOperator,ArithmeticOperator: equivalent; see the line above.
    if (6 * keys.length + 1 > MAX_BYTES) fail('size')
    // Stryker disable next-line EqualityOperator: reading one past the end yields undefined, which is not a symbol.
    for (let i = 0; i < keys.length; i++) if (typeof keys[i] === 'symbol') fail('symbol-key')
    apply(sort, keys, NO_ARGS) // UTF-16 code-unit order (RFC 8785 §3.2.3)
    this.emit('{')
    for (let i = 0; i < keys.length; i++) {
      const k = keys[i]
      if (apply(exec, KEY, [k]) === null) fail('key')
      const x = dataValue(getOwnPropertyDescriptor(o, k))
      if (i > 0) this.emit(',')
      this.emit('"' + k + '":') // the key grammar is ASCII with nothing to escape
      this.value(x, depth)
    }
    this.emit('}')
  }
}

export function encode (value) {
  try {
    if (typeof value !== 'object' || value === null) fail('top-level')
    const w = new Writer()
    w.container(value, 1, true)
    return w.out
  } catch (e) {
    if (EncodingError.isRefusal(e)) throw e
    throw new EncodingError('exotic') // a trap or an exotic object threw something of its own
  }
}

// A deeply frozen copy with null prototypes, built only from own data properties of JSON.parse output (E8).
function nullPrototypeCopy (v) {
  if (typeof v !== 'object') return v
  const copy = isArray(v) ? setPrototypeOf([], null) : create(null)
  const keys = ownKeys(v)
  for (let i = 0; i < keys.length; i++) {
    const k = keys[i]
    if (k === 'length' && isArray(v)) continue // an array's length is not an element; it follows from them
    defineProperty(copy, k, { __proto__: null, value: nullPrototypeCopy(v[k]), enumerable: true })
  }
  return freeze(copy)
}

export function decode (text) {
  if (typeof text !== 'string') fail('type')
  // The length test is a constant-time short cut for oversized input; it never changes a result, because UTF-8 needs
  // at least one byte per UTF-16 code unit.
  // Stryker disable next-line ConditionalExpression,EqualityOperator,LogicalOperator: equivalent; see the line above.
  if (text.length > MAX_BYTES || utf8Length(text) > MAX_BYTES) fail('size')
  let value
  try {
    value = parse(text)
  } catch {
    fail('syntax')
  }
  if (encode(value) !== text) fail('non-canonical')
  return nullPrototypeCopy(value)
}
