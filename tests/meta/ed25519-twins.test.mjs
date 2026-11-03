// TESTING.md §4.3 and §6: the Ed25519 suite must fail against every broken twin, and pass against the real module
// run through the same harness. Twins are generated from src/ed25519.js by one targeted change each; every change
// must match the source exactly once. Calling the library without `zip215: false` (its default is ZIP-215) is not
// a twin: the canonical, prime-order checks on key and R run first, so no input reaches the library on which the
// two modes differ. The option is kept as defence in depth.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, writeFileSync, mkdtempSync, rmSync, readdirSync } from 'node:fs'
import { spawn } from 'node:child_process'
import { tmpdir, availableParallelism } from 'node:os'
import { join } from 'node:path'

const SRC = new URL('../../src/ed25519.js', import.meta.url)
const SUITE_DIR = new URL('../ed25519/', import.meta.url).pathname
const SUITE = readdirSync(SUITE_DIR).filter((f) => f.endsWith('.test.mjs')).map((f) => join(SUITE_DIR, f))

// A twin lives outside the repository, so its import is made absolute.
const IMPORTS = [
  ["from '@noble/curves/ed25519.js'", `from '${import.meta.resolve('@noble/curves/ed25519.js')}'`],
]

// [name, bug class, [find, replace] pairs]
const TWINS = [
  ['zip215', 'the library is called with ZIP-215 rules', [
    ['const VERIFY_OPTIONS = freeze({ __proto__: null, zip215: false })', 'const VERIFY_OPTIONS = freeze({ __proto__: null, zip215: true })'],
    ['p = Point.fromBytes(bytes, false)', 'p = Point.fromBytes(bytes, true)']]],
  ['no-small-order-check', 'small-order keys and R values are not refused as such', [
    ['    if (p.isSmallOrder()) return `${prefix}-small-order`\n', '']]],
  ['no-torsion-check', 'mixed-order keys and R values are accepted', [
    ['    if (!p.isTorsionFree()) return `${prefix}-mixed-order`\n', '']]],
  ['no-r-checks', 'R is not checked (K4)', [
    ["  const rFault = pointFault(apply(subarray, sigBytes, [0, 32]), 'sig-r')\n  if (rFault) return result(rFault)\n", '']]],
  ['no-s-range-check', 'S >= L is left to the library, so the reason is wrong', [
    ["  if (!scalarInRange(apply(subarray, sigBytes, [32]))) return result('sig-s-range')\n", '']]],
  ['uppercase-hex', 'uppercase hex is accepted', [
    ['const KEY_HEX = /^[0-9a-f]{64}$/', 'const KEY_HEX = /^[0-9a-fA-F]{64}$/i'],
    ['const SIG_HEX = /^[0-9a-f]{128}$/', 'const SIG_HEX = /^[0-9a-fA-F]{128}$/i']]],
  ['library-throw-escapes', 'a throw from the library leaves checkEd25519', [
    ['  } catch { /* a throw is a reject (K2) */ }', '  } finally { /* none */ }']]],
  ['no-snapshot', 'a subclass can change the message while it is verified', [
    ['    return new Bytes(x)\n', '    return x\n']]],
  ['live-builtins', 'built-ins are looked up when called, so patching them later changes results', [
    ['      const c = apply(charCodeAt, text, [2 * i + j])', '      const c = text.charCodeAt(2 * i + j)']]],
  ['key-checks-after-sig', 'the signature is examined before the key', [
    ["  const keyFault = keyReason(key)\n  if (keyFault) return result(keyFault)\n  const keyBytes = fromHex(key)\n  if (!isHex(SIG_HEX, sig)) return result('sig-encoding')\n",
      "  if (!isHex(SIG_HEX, sig)) return result('sig-encoding')\n  const keyFault = keyReason(key)\n  if (keyFault) return result(keyFault)\n  const keyBytes = fromHex(key)\n"]]],
]

function run (implPath) {
  const { NODE_TEST_CONTEXT, ...env } = process.env
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['--test', '--test-reporter=tap', ...SUITE], {
      env: { ...env, MUID_ED25519_IMPL: implPath ?? '', FC_RUNS: '100' },
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
const dir = mkdtempSync(join(tmpdir(), 'muid-ed25519-twins-'))

function generate (name, edits) {
  let text = source
  for (const [find, replace] of [...IMPORTS, ...edits]) {
    const n = text.split(find).length - 1
    assert.equal(n, 1, `twin ${name}: target must occur exactly once in src/ed25519.js, found ${n}: ${JSON.stringify(find)}`)
    text = text.replace(find, () => replace)
  }
  const path = join(dir, `${name}.js`)
  writeFileSync(path, text)
  return path
}

test('Ed25519 broken twins', { timeout: 600_000 }, async (t) => {
  try {
    await t.test('control: an unmodified copy, run from outside the repository, passes', async () => {
      const r = await run(generate('control', []))
      assert.equal(r.code, 0, `control: exit ${r.code}, ${r.fail} failing`)
      assert.ok(r.pass > 40, `control: only ${r.pass} tests ran`)
    })

    const jobs = TWINS.map(([name, why, edits]) => [name, why, generate(name, edits)])
    assert.equal(jobs.length, 10, 'twin count')
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
