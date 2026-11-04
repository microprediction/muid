// TESTING.md §4b and §6: the assertion suite must fail against every broken twin, and pass against the real module
// run through the same harness. Twins are generated from src/assertion.js by one targeted change each; every change
// must match the source exactly once.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, writeFileSync, mkdtempSync, rmSync, readdirSync } from 'node:fs'
import { spawn } from 'node:child_process'
import { tmpdir, availableParallelism } from 'node:os'
import { join } from 'node:path'

const SRC = new URL('../../src/assertion.js', import.meta.url)
const SUITE_DIR = new URL('../assertion/', import.meta.url).pathname
const SUITE = readdirSync(SUITE_DIR).filter((f) => f.endsWith('.test.mjs')).map((f) => join(SUITE_DIR, f))

// A twin lives outside the repository, so its imports are made absolute.
const IMPORTS = [
  ["from './bytes.js'", "from '" + new URL('../../src/bytes.js', import.meta.url).href + "'"],
  ["from '@noble/hashes/sha2.js'", `from '${import.meta.resolve('@noble/hashes/sha2.js')}'`],
  ["from './encode.js'", `from '${new URL('../../src/encode.js', import.meta.url).href}'`],
  ["from './p256.js'", `from '${new URL('../../src/p256.js', import.meta.url).href}'`],
]

// [name, bug class, [find, replace] pairs]
const TWINS = [
  ['no-challenge-check', 'any challenge is accepted', [["  if (m[1] !== d.challenge) return refuse('challenge')\n", '']]],
  ['origin-ends-with', 'the origin is matched by suffix', [["  if (m[2] !== origin) return refuse('origin')", "  if (!m[2].endsWith(origin.slice(8))) return refuse('origin')"]]],
  ['uv-not-required', 'user verification is not required', [["  if (!(flags & UV)) return refuse('user-verification')\n", '']]],
  ['trailing-auth-data', 'bytes after the 37-byte header are allowed', [["  if (authData.length !== 37) return refuse('auth-data-length')", "  if (authData.length < 37) return refuse('auth-data-length')"]]],
  ['top-origin-allowed', 'topOrigin is accepted', [["'crossOrigin', 'topOrigin'])", "'crossOrigin'])"]]],
  ['signed-bytes-prefix', 'the challenge is computed over the signed-bytes prefix', [["    let text = 'muid/v1/assert\\n'", "    let text = 'muid/v1\\n'"]]],
  ['covers-without-record', 'covers need not contain the record', [['  return mine\n', '  return true\n']]],
  ['no-rp-id-check', 'the rp id hash is not compared', [["  if (!sameBytes(authData, d.rpIdHash)) return refuse('rp-id')\n", '']]],
  ['lax-base64url', 'padding and non-canonical base64url are accepted', [['  return toB64u(out) === text ? out : undefined', "  return text.endsWith('=') || toB64u(out) === text || true ? out : undefined"]]],
  ['duplicates-allowed', 'a prefix key may appear again later in client data', [["const RESERVED = freeze(['type', 'challenge', 'origin', 'crossOrigin', 'topOrigin'])", "const RESERVED = freeze(['topOrigin'])"]]],
  ['unanchored-end', 'client data may continue after a closing brace', [['    if (at === text.length - 1) return apply(charCodeAt, text, [at]) === 125', '    if (apply(charCodeAt, text, [at]) === 125) return true']]],
  ['no-snapshot', 'sig is read directly, so accessors and proxies reach the checks', [['    return decode(encode(sig))', '    return sig']]],
  ['flags-unchecked', 'AT, ED and reserved bits are ignored', [["  if (flags & FORBIDDEN || (flags & BS && !(flags & BE))) return refuse('auth-data-flags')\n", '']]],
]

function run (implPath) {
  const { NODE_TEST_CONTEXT, ...env } = process.env
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['--test', '--test-reporter=tap', ...SUITE], {
      env: { ...env, MUID_ASSERTION_IMPL: implPath ?? '', FC_RUNS: '100' },
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
const dir = mkdtempSync(join(tmpdir(), 'muid-assertion-twins-'))

function generate (name, edits) {
  let text = source
  for (const [find, replace] of [...IMPORTS, ...edits]) {
    const n = text.split(find).length - 1
    assert.equal(n, 1, `twin ${name}: target must occur exactly once in src/assertion.js, found ${n}: ${JSON.stringify(find)}`)
    text = text.replace(find, () => replace)
  }
  const path = join(dir, `${name}.js`)
  writeFileSync(path, text)
  return path
}

test('assertion broken twins', { timeout: 600_000 }, async (t) => {
  try {
    await t.test('control: an unmodified copy, run from outside the repository, passes', async () => {
      const r = await run(generate('control', []))
      assert.equal(r.code, 0, `control: exit ${r.code}, ${r.fail} failing`)
      assert.ok(r.pass > 25, `control: only ${r.pass} tests ran`)
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
