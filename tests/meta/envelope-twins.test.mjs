// TESTING.md §3.5 and §6: the envelope suite must fail against every broken twin, and pass against the real module
// run through the same harness. Twins are generated from src/envelope.js by one targeted change each; every change
// must match the source exactly once. A twin that re-serialises before hashing is not here: no vector can catch it
// while E2 holds, and tests/guards/envelope-no-reserialise.test.mjs does.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, writeFileSync, mkdtempSync, rmSync, readdirSync } from 'node:fs'
import { spawn } from 'node:child_process'
import { tmpdir, availableParallelism } from 'node:os'
import { join } from 'node:path'

const SRC = new URL('../../src/envelope.js', import.meta.url)
const SUITE_DIR = new URL('../envelope/', import.meta.url).pathname
const SUITE = readdirSync(SUITE_DIR).filter((f) => f.endsWith('.test.mjs')).map((f) => join(SUITE_DIR, f))

// A twin lives outside the repository, so its imports are made absolute.
const IMPORTS = [
  ["from './bytes.js'", "from '" + new URL('../../src/bytes.js', import.meta.url).href + "'"],
  ["from '@noble/hashes/sha2.js'", `from '${import.meta.resolve('@noble/hashes/sha2.js')}'`],
  ["from './encode.js'", `from '${new URL('../../src/encode.js', import.meta.url).href}'`],
]

// [name, bug class, [find, replace] pairs]
const TWINS = [
  ['no-version-check', 'any version is accepted', [["  if (p.v !== 1) fail('version')\n", '']]],
  ['no-type-check', 'a record of one type opens as another', [["  if (p.type !== type) fail('type')\n", '']]],
  ['root-shape-ignored', 'a root may carry sig and a signed type may omit it', [
    ["if (!sameKeys(env, root ? ['payload'] : ['payload', 'sig'])) fail('envelope-shape')",
      "if (!sameKeys(env, ['payload', 'sig']) && !sameKeys(env, ['payload'])) fail('envelope-shape')"]]],
  ['extra-keys-accepted', 'keys beyond the expected ones are ignored', [
    ['function sameKeys (o, expected) {\n', 'function sameKeys (o, expected) {\n  return expected.every((e) => apply(includes, keys(o), [e]))\n']]],
  ['id-without-prefix', 'the record id hashes the payload without the domain prefix', [
    ['toHex(sha256(signedBytes(payload)))', 'toHex(sha256(apply(textEncode, UTF8, [payload])))']]],
  ['no-payload-size-on-open', 'open accepts a payload too large to have been sealed', [
    ["  if (envelopeBytes(env.payload) > MAX_PAYLOAD) fail('payload-size')\n", '']]],
  ['no-payload-size-on-seal', 'seal returns a payload that cannot be wrapped with a signature', [
    ["  if (envelopeBytes(payload) > MAX_PAYLOAD) fail('payload-size')\n", '']]],
  ['payload-size-unescaped', 'the payload is measured without its escapes', [
    ['apply(textEncode, UTF8, [stringify(payload)]).length - 2', 'apply(textEncode, UTF8, [payload]).length']]],
  ['signed-bytes-unchecked', 'signedBytes encodes anything, replacing lone surrogates', [
    ["  if (typeof payload !== 'string' || !apply(isWellFormed, payload, [])) {", '  if (false) {']]],
  ['id-over-envelope', 'the record id covers the whole envelope, signature included', [
    ['  out.id = idOf(env.payload)\n', '  out.id = idOf(text)\n']]],
  ['prefix-without-newline', 'the domain prefix lacks its newline', [["const PREFIX = 'muid/v1\\n'", "const PREFIX = 'muid/v1'"]]],
  ['body-array-allowed', 'body may be an array', [["|| !isObject(p.body)) fail('payload-shape')", "|| typeof p.body !== 'object') fail('payload-shape')"]]],
  ['output-not-frozen', 'the opened record can be modified', [['  out.payload = env.payload\n  return freeze(out)', '  out.payload = env.payload\n  return out']]],
]

function run (implPath) {
  const { NODE_TEST_CONTEXT, ...env } = process.env
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['--test', '--test-reporter=tap', ...SUITE], {
      env: { ...env, MUID_ENVELOPE_IMPL: implPath ?? '', FC_RUNS: '100' },
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
const dir = mkdtempSync(join(tmpdir(), 'muid-envelope-twins-'))

function generate (name, edits) {
  let text = source
  for (const [find, replace] of [...IMPORTS, ...edits]) {
    const n = text.split(find).length - 1
    assert.equal(n, 1, `twin ${name}: target must occur exactly once in src/envelope.js, found ${n}: ${JSON.stringify(find)}`)
    text = text.replace(find, () => replace)
  }
  const path = join(dir, `${name}.js`)
  writeFileSync(path, text)
  return path
}

test('envelope broken twins', { timeout: 600_000 }, async (t) => {
  try {
    await t.test('control: an unmodified copy, run from outside the repository, passes', async () => {
      const r = await run(generate('control', []))
      assert.equal(r.code, 0, `control: exit ${r.code}, ${r.fail} failing`)
      assert.ok(r.pass > 60, `control: only ${r.pass} tests ran`)
    })

    const jobs = TWINS.map(([name, why, edits]) => [name, why, generate(name, edits)])
    assert.equal(jobs.length, 13, 'twin count')
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
