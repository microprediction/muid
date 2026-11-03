// TESTING.md §4c2 and §6: the root suite must fail against every broken twin, and pass against the real module run
// through the same harness. Twins are generated from src/root.js by one targeted change each.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, writeFileSync, mkdtempSync, rmSync, readdirSync } from 'node:fs'
import { spawn } from 'node:child_process'
import { tmpdir, availableParallelism } from 'node:os'
import { join } from 'node:path'

const SRC = new URL('../../src/root.js', import.meta.url)
const SUITE_DIR = new URL('../root/', import.meta.url).pathname
const SUITE = readdirSync(SUITE_DIR).filter((f) => f.endsWith('.test.mjs')).map((f) => join(SUITE_DIR, f))

// A twin lives outside the repository, so its imports are made absolute.
const absolute = (m) => new URL('../../src/' + m + '.js', import.meta.url).href
const IMPORTS = [
  ["from '@noble/hashes/sha2.js'", "from '" + import.meta.resolve('@noble/hashes/sha2.js') + "'"],
  ...['envelope', 'p256'].map((m) => ["from './" + m + ".js'", "from '" + absolute(m) + "'"]),
]

// [name, bug class, [find, replace] pairs]
const TWINS = [
  ['id-without-prefix', 'the root id omits its domain prefix', [["concat('muid-root\\n' + rpId + '\\n', pub)", "concat(rpId + '\\n', pub)"]]],
  ['id-over-hex-text', 'the root id hashes the key as hex text', [["concat('muid-root\\n' + rpId + '\\n', pub)", "concat('muid-root\\n' + rpId + '\\n' + pub, '')"]]],
  ['rp-id-unchecked', 'any rp ID is accepted', [["  if (b.rp_id !== rpId) return verdict({ ok: false, reason: 'rp-id' })\n", '']]],
  ['identity-over-hex', 'the identity id hashes the root id as hex text', [["concat('muid-identity\\n', rootId)", "concat('muid-identity\\n' + rootId, '')"]]],
  ['identity-unchecked-input', 'identityOf accepts anything', [["  if (typeof rootId !== 'string' || apply(exec, ID, [rootId]) === null) throw new TypeError('root id must be 64 lowercase hex')\n", '']]],
]

function run (implPath) {
  const { NODE_TEST_CONTEXT, ...env } = process.env
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['--test', '--test-reporter=tap', ...SUITE], {
      env: { ...env, MUID_ROOT_IMPL: implPath ?? '', FC_RUNS: '100' },
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
const dir = mkdtempSync(join(tmpdir(), 'muid-root-twins-'))

function generate (name, edits) {
  let text = source
  for (const [find, replace] of [...IMPORTS, ...edits]) {
    const n = text.split(find).length - 1
    assert.equal(n, 1, `twin ${name}: target must occur exactly once in src/root.js, found ${n}: ${JSON.stringify(find)}`)
    text = text.replace(find, () => replace)
  }
  const path = join(dir, `${name}.js`)
  writeFileSync(path, text)
  return path
}

test('root broken twins', { timeout: 600_000 }, async (t) => {
  try {
    await t.test('control: an unmodified copy, run from outside the repository, passes', async () => {
      const r = await run(generate('control', []))
      assert.equal(r.code, 0, `control: exit ${r.code}, ${r.fail} failing`)
      assert.ok(r.pass >= 9, `control: only ${r.pass} tests ran`)
    })

    const jobs = TWINS.map(([name, why, edits]) => [name, why, generate(name, edits)])
    assert.equal(jobs.length, 5, 'twin count')
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
