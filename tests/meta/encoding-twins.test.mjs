// TESTING.md §2.4 and §6: the encoding suite must fail against every broken twin, and pass against the real encoder
// run through the same harness. Twins are generated from src/encode.js by one targeted change each, so no buggy copy
// of trust-path code is committed and the twins follow the source as it changes. Each change must match the source
// exactly once; if a refactor removes the target, this test fails until the twin is updated.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, writeFileSync, mkdtempSync, rmSync, readdirSync } from 'node:fs'
import { spawn } from 'node:child_process'
import { tmpdir, availableParallelism } from 'node:os'
import { join } from 'node:path'

const SRC = new URL('../../src/encode.js', import.meta.url)
const SUITE_DIR = new URL('../encoding/', import.meta.url).pathname
const SUITE = readdirSync(SUITE_DIR).filter((f) => f.endsWith('.test.mjs')).map((f) => join(SUITE_DIR, f))

// [name, bug class, [find, replace] pairs]
const TWINS = [
  ['floats-accepted', 'a non-integer is encoded instead of refused', [
    ["        if (!isInteger(x)) fail('float')\n        if (!isSafeInteger(x)) fail('unsafe-integer')\n",
      "        if (x > 9007199254740991 || x < -9007199254740991) fail('unsafe-integer')\n"]]],
  ['negative-zero-rewritten', '-0 silently becomes 0', [
    ["if (is(x, -0)) fail('negative-zero')", 'if (is(x, -0)) x = 0']]],
  ['no-reencode-check', 'decode trusts JSON.parse: duplicate keys, whitespace and escapes pass', [
    ["if (encode(value) !== text) fail('non-canonical')", 'encode(value)']]],
  ['no-surrogate-check', 'lone surrogates are encoded', [
    ["        if (!apply(isWellFormed, x, NO_ARGS)) fail('surrogate')\n", '']]],
  ['no-depth-limit', 'nesting is unbounded', [
    ["    if (depth > MAX_DEPTH) fail('depth')\n", '']]],
  ['shallow-null-prototype', 'only the top level of a decoded value is copied, frozen and prototype-free', [
    ['value: nullPrototypeCopy(v[k])', 'value: v[k]']]],
  ['count-only-array-check', 'an array hole hidden by an extra property passes the shape check', [
    ["      if (d === undefined) fail('array-shape')\n", '']]],
  ['utf16-size', 'size counted in UTF-16 code units instead of UTF-8 bytes', [
    ['emit (s, n = utf8Length(s))', 'emit (s, n = s.length)'],
    [' || utf8Length(text) > MAX_BYTES', '']]],
  ['getter-invoked', 'an accessor is read instead of refused', [
    ["if (!hasOwn(d, 'value')) fail('accessor')", "if (!hasOwn(d, 'value')) return d.get ? d.get() : undefined"]]],
  ['unsorted-keys', 'keys emitted in insertion order', [
    ['    apply(sort, keys, NO_ARGS)', '    keys']]],
  ['no-output-limit', 'output size is not checked while encoding', [
    ["    if (this.bytes > MAX_BYTES) fail('size')\n", '']]],
  ['underscore-keys', 'a key may start with an underscore (admits __proto__)', [
    ['const KEY = /^[a-z][a-z0-9_]{0,31}$/', 'const KEY = /^[a-z_][a-z0-9_]{0,31}$/']]],
  ['non-enumerable-skipped', 'a non-enumerable property is treated as absent', [
    ["  if (!d.enumerable) fail('non-enumerable')\n  return d.value", '  return d.enumerable ? d.value : undefined']]],
  ['null-accepted', 'null is encoded', [
    ["        if (x === null) fail('null')\n        this.container(x, depth + 1, false)",
      "        if (x === null) { this.emit('null'); return }\n        this.container(x, depth + 1, false)"]]],
  // Hardening found by adversarial review: each must be shown to be necessary.
  ['no-array-width-check', 'a wide array is enumerated before any size check', [
    ["    if (this.bytes + 2 * length + 2 > MAX_BYTES) fail('size')", '    if (false) fail(\'size\')']]],
  ['no-object-width-check', 'a wide object is enumerated and sorted before any size check', [
    ["    if (6 * keys.length + 1 > MAX_BYTES) fail('size')", '    if (false) fail(\'size\')']]],
  ['no-string-precheck', 'a huge string is copied and escaped before the size check', [
    ["        if (this.bytes + x.length + 3 > MAX_BYTES) fail('size')\n", '']]],
  ['foreign-throws-escape', 'a throw from a trap or exotic object leaves encode as itself', [
    ["    throw new EncodingError('exotic')", '    throw e']]],
  ['no-slot-check', 'an object with internal slots and a plain prototype is encoded as {}', [
    ['(!array && hasInternalSlot(v, proto))', 'false']]],
  ['live-builtins', 'built-ins are looked up when called, so patching them later changes results', [
    ['const stringify = JSON.stringify', 'const stringify = (x) => JSON.stringify(x)'],
    ['apply(exec, KEY, [k]) === null', '!KEY.test(k)']]],
  ['inherited-output', 'decoded objects and arrays inherit from the shared prototypes', [
    ['const copy = isArray(v) ? setPrototypeOf([], null) : create(null)', 'const copy = isArray(v) ? [] : {}']]],
  ['length-read-in-loop', 'an array length is read again on every iteration', [
    ['    for (let i = 0; i < length; i++) {\n      const d', '    for (let i = 0; i < a.length; i++) {\n      const d']]],
  ['descriptor-read-twice', 'a property descriptor is read twice', [
    ['const x = dataValue(getOwnPropertyDescriptor(o, k))', 'getOwnPropertyDescriptor(o, k); const x = dataValue(getOwnPropertyDescriptor(o, k))']]],
  // Found by automated review.
  ['own-tag-read', 'the slot check reads an own Symbol.toStringTag, running an accessor', [
    ['if (hasOwn(v, toStringTag) || (proto', 'if ((proto']]],
  ['inherited-tag-read', 'the slot check reads a Symbol.toStringTag defined on Object.prototype after loading', [
    [' || (proto !== null && hasOwn(ObjectPrototype, toStringTag))', '']]],
  ['escapes-uncounted', 'a string is escaped and copied before its escaped size is checked', [
    ["        if (this.bytes + n + 1 > MAX_BYTES) fail('size')\n", '']]],
  ['controls-two-bytes', 'every escape is counted as two bytes, so \\u00XX controls are copied past the limit', [
    ['c === 0x22 || c === 0x5c || (c > 7 && c < 14 && c !== 11) ? 2 : 6', '2']]],
]

function run (implPath) {
  // The test runner marks its child processes with NODE_TEST_CONTEXT, which makes a nested `node --test` report to
  // the parent instead of running as its own suite. The control test below fails if this is ever wrong again.
  const { NODE_TEST_CONTEXT, ...env } = process.env
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['--test', '--test-reporter=tap', ...SUITE], {
      env: { ...env, MUID_ENCODING_IMPL: implPath ?? '', FC_RUNS: '100' },
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    let out = ''
    child.stdout.on('data', (d) => { out += d })
    child.stderr.on('data', (d) => { out += d })
    child.on('close', (code) => {
      const count = (k) => Number((out.match(new RegExp(`^# ${k} (\\d+)`, 'm')) ?? [])[1] ?? NaN)
      resolve({ code, pass: count('pass'), fail: count('fail') })
    })
  })
}

const source = readFileSync(SRC, 'utf8')
const dir = mkdtempSync(join(tmpdir(), 'muid-twins-'))

function generate (name, edits) {
  let text = source
  for (const [find, replace] of edits) {
    const n = text.split(find).length - 1
    assert.equal(n, 1, `twin ${name}: target must occur exactly once in src/encode.js, found ${n}: ${JSON.stringify(find)}`)
    text = text.replace(find, () => replace)
  }
  const path = join(dir, `${name}.js`)
  writeFileSync(path, text)
  return path
}

test('broken twins', { timeout: 600_000 }, async (t) => {
  try {
    await t.test('control: the real encoder passes through this harness', async () => {
      const r = await run(null)
      assert.equal(r.code, 0, `real encoder: exit ${r.code}, ${r.fail} failing`)
      assert.ok(r.pass > 200, `real encoder: only ${r.pass} tests ran`)
    })

    const jobs = [
      ['stringify', 'JSON.stringify with sorted keys and no domain checks',
        new URL('../twins/encoding/stringify.js', import.meta.url).pathname],
      ...TWINS.map(([name, why, edits]) => [name, why, generate(name, edits)]),
    ]
    assert.equal(jobs.length, 28, 'twin count')

    // Each suite run already runs its files in parallel, so run only a few suites at a time.
    const results = []
    const queue = [...jobs]
    const workers = Math.max(1, Math.floor(availableParallelism() / 4))
    await Promise.all(Array.from({ length: workers }, async () => {
      for (let job = queue.shift(); job; job = queue.shift()) {
        const [name, why, path] = job
        results.push([name, why, await run(path)])
      }
    }))
    results.sort((a, b) => jobs.findIndex((j) => j[0] === a[0]) - jobs.findIndex((j) => j[0] === b[0]))
    for (const [name, why, r] of results) {
      await t.test(`twin ${name} is caught (${why})`, () => {
        assert.notEqual(r.code, 0, `the suite passed against twin ${name}`)
        assert.ok(r.pass > 0 && r.fail > 0, `twin ${name}: the suite did not run normally (pass ${r.pass}, fail ${r.fail})`)
      })
    }
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
