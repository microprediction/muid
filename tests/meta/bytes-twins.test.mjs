// TESTING.md §6: the bytes suite must fail against every broken twin, and pass against the real module run through
// the same harness. Twins are generated from src/bytes.js by one targeted change each.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, writeFileSync, mkdtempSync, rmSync, readdirSync } from 'node:fs'
import { spawn } from 'node:child_process'
import { tmpdir, availableParallelism } from 'node:os'
import { join } from 'node:path'

const SRC = new URL('../../src/bytes.js', import.meta.url)
const SUITE_DIR = new URL('../bytes/', import.meta.url).pathname
const SUITE = readdirSync(SUITE_DIR).filter((f) => f.endsWith('.test.mjs')).map((f) => join(SUITE_DIR, f))

const IMPORTS = []

// [name, bug class, [find, replace] pairs]
const TWINS = [
  ['accept-inherited', 'a verdict copies the fields it inherits too', [['  const ks = fields === undefined ? [] : keys(fields)\n  for (let i = 0; i < ks.length; i++) out[ks[i]] = fields[ks[i]]', '  for (const k in fields) out[k] = fields[k]']]],
  ['live-builtins', 'built-ins are looked up when called, so patching them later changes results', [
    ['      const c = apply(charCodeAt, text, [2 * i + j])', '      const c = text.charCodeAt(2 * i + j)']]],
  ['no-snapshot', 'the caller\'s array is returned, so a subclass can change it while it is checked', [['    return new Bytes(x)\n', '    return x\n']]],
  ['lookalikes', 'anything with a length is copied', [["  if (apply(tagOf, x, []) !== 'Uint8Array') return undefined\n", "  if (typeof x !== 'object' || x === null) return undefined\n"]]],
  ['hex-table', 'the hex table pads the wrong bytes', [["(i < 16 ? '0' : '')", "(i <= 16 ? '0' : '')"]]],
  ['unfrozen-verdicts', 'verdicts can be modified', [['  out.reason = reason\n  return freeze(out)', '  out.reason = reason\n  return out']]],
]

function run (implPath) {
  const { NODE_TEST_CONTEXT, ...env } = process.env
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['--test', '--test-reporter=tap', ...SUITE], {
      env: { ...env, MUID_BYTES_IMPL: implPath ?? '', FC_RUNS: '100' },
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
const dir = mkdtempSync(join(tmpdir(), 'muid-bytes-twins-'))

function generate (name, edits) {
  let text = source
  for (const [find, replace] of [...IMPORTS, ...edits]) {
    const n = text.split(find).length - 1
    assert.equal(n, 1, `twin ${name}: target must occur exactly once in src/bytes.js, found ${n}: ${JSON.stringify(find)}`)
    text = text.replace(find, () => replace)
  }
  const path = join(dir, `${name}.js`)
  writeFileSync(path, text)
  return path
}

test('bytes broken twins', { timeout: 600_000 }, async (t) => {
  try {
    await t.test('control: an unmodified copy, run from outside the repository, passes', async () => {
      const r = await run(generate('control', []))
      assert.equal(r.code, 0, `control: exit ${r.code}, ${r.fail} failing`)
      assert.ok(r.pass >= 4, `control: only ${r.pass} tests ran`)
    })

    const jobs = TWINS.map(([name, why, edits]) => [name, why, generate(name, edits)])
    assert.equal(jobs.length, 6, 'twin count')
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
