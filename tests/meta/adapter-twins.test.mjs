// Issue #21: the adapter suite must fail against every broken twin of adapter/, and pass against the real adapter
// run through the same harness. Each twin is a copy of adapter/ with one targeted change.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, writeFileSync, mkdtempSync, mkdirSync, rmSync, readdirSync } from 'node:fs'
import { spawn } from 'node:child_process'
import { tmpdir, availableParallelism } from 'node:os'
import { join } from 'node:path'

const DIR = new URL('../../adapter/', import.meta.url)
const FILES = ['relying-party.js', 'stores.js']
const SUITE_DIR = new URL('../adapter/', import.meta.url).pathname
const SUITE = readdirSync(SUITE_DIR).filter((f) => f.endsWith('.test.mjs')).map((f) => join(SUITE_DIR, f))
// The adapter's one import of the core, made absolute because a twin lives outside the repository.
const IMPORTS = [["from '../" + "src/envelope.js'", "from '" + new URL('../../src/envelope.js', import.meta.url).href + "'"]]

// [name, bug class, file, [find, replace] pairs]
const TWINS = [
  ['memory-check-then-insert', 'the memory store checks, yields, then inserts, so two requests both consume', 'stores.js',
    [['      if (consumed.has(id)) return false\n      consumed.set(id, until)', '      if (consumed.has(id)) return false\n      await null\n      consumed.set(id, until)']]],
  ['sqlite-check-then-insert', 'the database store selects, then inserts, so two instances both consume', 'stores.js',
    [["    async consume (id, until) { return insert.run(id, until).changes === 1 },",
      "    async consume (id, until) {\n      if (db.prepare('SELECT 1 FROM consumed WHERE id = ?').get(id)) return false\n      await new Promise((resolve) => setTimeout(resolve, 50))\n      db.prepare('INSERT OR REPLACE INTO consumed (id, until) VALUES (?, ?)').run(id, until)\n      return true\n    },"]]],
  ['action-before-consume', 'the action runs before the claim is consumed', 'relying-party.js',
    [['    let fresh\n', '    const early = await action(r)\n    let fresh\n'], ['    const value = await action(r)\n', '    const value = early\n']]],
  ['memory-head-regresses', 'the memory store replaces a head with an older one', 'stores.js', [['if (old === undefined || at > old.at) heads.set', 'heads.set']]],
  ['sqlite-head-regresses', 'the database store replaces a head with an older one', 'stores.js', [[' WHERE excluded.at > heads.at', '']]],
  ['storage-failure-is-fresh', 'a failed insert is taken as a fresh claim', 'relying-party.js',
    [["      fresh = await store.consume(r.id, r.until)\n    } catch {\n      return refusal('storage')", '      fresh = await store.consume(r.id, r.until)\n    } catch {\n      fresh = true']]],
  ['no-head-memory', 'the stored head is not passed to the verifier', 'relying-party.js', [['r = verifier[method](given, { ...call, lastHead })', 'r = verifier[method](given, call)']]],
  ['corrupt-storage-throws', 'a stored head the verifier cannot read escapes as an exception', 'relying-party.js', [['      if (!(e instanceof TypeError)) throw e\n', '      throw e\n']]],
]

function run (dir) {
  const { NODE_TEST_CONTEXT, ...env } = process.env
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['--test', '--test-reporter=tap', ...SUITE], {
      env: { ...env, MUID_ADAPTER_DIR: dir, FC_RUNS: '100' },
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

const sources = Object.fromEntries(FILES.map((f) => [f, readFileSync(new URL(f, DIR), 'utf8')]))
const root = mkdtempSync(join(tmpdir(), 'muid-adapter-twins-'))

function generate (name, file, edits) {
  const dir = join(root, name)
  mkdirSync(dir)
  for (const f of FILES) {
    let text = sources[f]
    for (const [find, replace] of [...IMPORTS, ...(f === file ? edits : [])]) {
      if (find === IMPORTS[0][0] && !text.includes(find)) continue
      const n = text.split(find).length - 1
      assert.equal(n, 1, `twin ${name}: target must occur exactly once in adapter/${f}, found ${n}: ${JSON.stringify(find)}`)
      text = text.replace(find, () => replace)
    }
    writeFileSync(join(dir, f), text)
  }
  return dir
}

test('adapter broken twins', { timeout: 900_000 }, async (t) => {
  try {
    await t.test('control: an unmodified copy, run from outside the repository, passes', async () => {
      const r = await run(generate('control', null, []))
      assert.equal(r.code, 0, `control: exit ${r.code}, ${r.fail} failing`)
      assert.ok(r.pass >= 20, `control: only ${r.pass} tests ran`)
    })
    const jobs = TWINS.map(([name, why, file, edits]) => [name, why, generate(name, file, edits)])
    assert.equal(jobs.length, 8, 'twin count')
    const results = []
    const queue = [...jobs]
    const workers = Math.max(1, Math.floor(availableParallelism() / 4))
    await Promise.all(Array.from({ length: workers }, async () => {
      for (let job = queue.shift(); job; job = queue.shift()) {
        const [name, why, dir] = job
        results.push([name, why, await run(dir)])
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
    rmSync(root, { recursive: true, force: true })
  }
})
