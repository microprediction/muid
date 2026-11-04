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
  ['memory-not-read-in-transaction', 'the transaction verifies without the memory as it stands there', 'relying-party.js',
    [['const stored = tx.lastHead(fields.identity)', 'const stored = undefined']]],
  ['storage-read-in-verifier-guard', 'a failing memory read is taken for a verifier error and escapes', 'relying-party.js',
    [['        const stored = tx.lastHead(fields.identity) // the store\'s: a failure here is refused as storage\n        let r\n        try {\n          r = verifyWith(method, given, call, stored)',
      '        let r\n        try {\n          r = verifyWith(method, given, call, tx.lastHead(fields.identity))']]],
  ['consume-ignored', 'a claim already consumed is accepted again', 'relying-party.js',
    [["if (method === 'verifyClaim' && !tx.consume(r.id, r.until)) return refusal('replay')", "if (method === 'verifyClaim') tx.consume(r.id, r.until)"]]],
  ['storage-failure-ignored', 'a failed transaction is taken as success', 'relying-party.js',
    [["      })\n    } catch {\n      return refusal('storage')", "      })\n    } catch {\n      return verifier[method](given, call)"]]],
  ['no-head-memory', 'the stored head is not passed to the verifier', 'relying-party.js',
    [['return verifier[method](given, { ...call, lastHead: stored.head })', 'return verifier[method](given, call)']]],
  ['rotation-locks-out', 'a stored head the verifier cannot read locks its identity out', 'relying-party.js',
    [['      return verifier[method](given, { ...call, minHeadAt: Math.max(call.minHeadAt ?? 0, stored.at) })', "      return refusal('storage')"]]],
  ['time-floor-ignored', "an unreadable stored head's time is not kept as a floor", 'relying-party.js',
    [['      return verifier[method](given, { ...call, minHeadAt: Math.max(call.minHeadAt ?? 0, stored.at) })', '      return verifier[method](given, call)']]],
  ['records-read-twice', 'the head is read again from the presented records', 'relying-party.js',
    [["const fields = open(given.head, 'head').body", "const fields = open(records.head, 'head').body"]]],
  ['call-spread', "the call is copied with a spread, dropping inherited fields", 'relying-party.js', [['const call = readCall(rawCall)', 'const call = { ...rawCall }']]],
  ['no-precheck', 'refused records still take the transaction', 'relying-party.js', [['    if (!pre.ok) return refusal(pre.reason)\n', '']]],
  ['memory-no-grace', 'the memory store expires claim ids at until', 'stores.js', [['if (until + grace <= now) consumed.delete(id)', 'if (until <= now) consumed.delete(id)']]],
  ['sqlite-no-grace', 'the database store expires claim ids at until', 'stores.js', [['remove.run(now - grace)', 'remove.run(now)']]],
  ['memory-head-regresses', 'the memory store replaces a head with an older one', 'stores.js', [['if (old === undefined || at > old.at) heads.set', 'heads.set']]],
  ['sqlite-head-regresses', 'the database store replaces a head with an older one', 'stores.js', [[' WHERE excluded.at > heads.at', '']]],
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
    assert.equal(jobs.length, 14, 'twin count')
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
