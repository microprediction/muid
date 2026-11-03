// TESTING.md §4a and §6: the P-256 suite must fail against every broken twin, and pass against the real module run
// through the same harness. Twins are generated from src/p256.js by one targeted change each; every change must match
// the source exactly once.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, writeFileSync, mkdtempSync, rmSync, readdirSync } from 'node:fs'
import { spawn } from 'node:child_process'
import { tmpdir, availableParallelism } from 'node:os'
import { join } from 'node:path'

const SRC = new URL('../../src/p256.js', import.meta.url)
const SUITE_DIR = new URL('../p256/', import.meta.url).pathname
const SUITE = readdirSync(SUITE_DIR).filter((f) => f.endsWith('.test.mjs')).map((f) => join(SUITE_DIR, f))

// A twin lives outside the repository, so its import is made absolute.
const IMPORTS = [
  ["from '@noble/curves/nist.js'", `from '${import.meta.resolve('@noble/curves/nist.js')}'`],
]

// [name, bug class, [find, replace] pairs]
const TWINS = [
  ['low-s-only', 'the library default: high-S signatures, which passkeys emit, are rejected', [
    ["const OPTIONS = freeze({ __proto__: null, format: 'der', lowS: false, prehash: true })",
      "const OPTIONS = freeze({ __proto__: null, format: 'der', prehash: true })"]]],
  ['no-prehash', 'the message is treated as already hashed', [
    ["format: 'der', lowS: false, prehash: true })", "format: 'der', lowS: false, prehash: false })"]]],
  ['compressed-keys', 'compressed and hybrid keys are accepted', [
    ['const KEY_HEX = /^04[0-9a-f]{128}$/', 'const KEY_HEX = /^(?:0[23][0-9a-f]{64}|0[467][0-9a-f]{128})$/']]],
  ['no-point-check', 'a key off the curve reaches verify, so the reason is wrong', [
    ["  return isPoint(fromHex(key)) ? undefined : 'key-point'", '  return undefined']]],
  ['library-throw-escapes', 'a throw from the library leaves checkP256', [
    ['  } catch { /* a throw is a reject (K2) */ }', '  } finally { /* none */ }']]],
  ['no-snapshot', 'a subclass can change the bytes while they are verified', [
    ['    return new Bytes(x)\n', '    return x\n']]],
  ['live-builtins', 'built-ins are looked up when called, so patching them later changes results', [
    ['      const c = apply(charCodeAt, text, [2 * i + j])', '      const c = text.charCodeAt(2 * i + j)']]],
]

function run (implPath) {
  const { NODE_TEST_CONTEXT, ...env } = process.env
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['--test', '--test-reporter=tap', ...SUITE], {
      env: { ...env, MUID_P256_IMPL: implPath ?? '', FC_RUNS: '100' },
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
const dir = mkdtempSync(join(tmpdir(), 'muid-p256-twins-'))

function generate (name, edits) {
  let text = source
  for (const [find, replace] of [...IMPORTS, ...edits]) {
    const n = text.split(find).length - 1
    assert.equal(n, 1, `twin ${name}: target must occur exactly once in src/p256.js, found ${n}: ${JSON.stringify(find)}`)
    text = text.replace(find, () => replace)
  }
  const path = join(dir, `${name}.js`)
  writeFileSync(path, text)
  return path
}

test('P-256 broken twins', { timeout: 600_000 }, async (t) => {
  try {
    await t.test('control: an unmodified copy, run from outside the repository, passes', async () => {
      const r = await run(generate('control', []))
      assert.equal(r.code, 0, `control: exit ${r.code}, ${r.fail} failing`)
      assert.ok(r.pass > 15, `control: only ${r.pass} tests ran`)
    })

    const jobs = TWINS.map(([name, why, edits]) => [name, why, generate(name, edits)])
    assert.equal(jobs.length, 7, 'twin count')
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
