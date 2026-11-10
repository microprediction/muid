// Issue #21: the adapter suite must fail against every broken twin of adapter/, and pass against the real adapter
// run through the same harness. Each twin is a copy of adapter/ with one targeted change.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, writeFileSync, mkdtempSync, mkdirSync, rmSync, readdirSync } from 'node:fs'
import { spawn } from 'node:child_process'
import { tmpdir, availableParallelism } from 'node:os'
import { join } from 'node:path'

// A test that never ends under a twin fails (the twin is caught) instead of holding the harness open.
const TEST_TIMEOUT = 300_000

const DIR = new URL('../../adapter/', import.meta.url)
const FILES = ['relying-party.js', 'stores.js']
const SUITE_DIR = new URL('../adapter/', import.meta.url).pathname
const SUITE = readdirSync(SUITE_DIR).filter((f) => f.endsWith('.test.mjs')).map((f) => join(SUITE_DIR, f))
// The adapter's one import of the core, made absolute because a twin lives outside the repository.
const IMPORTS = [["from '../" + "src/envelope.js'", "from '" + new URL('../../src/envelope.js', import.meta.url).href + "'"]]

// [name, bug class, file, [find, replace] pairs]
const TWINS = [
  ['verified-at-request-start', 'the transaction verifies at the time the request arrived, whatever the clock says then (model/tla/Adapter.tla)', 'relying-party.js',
    [['          const current = { ...call, now }\n', '          const current = call\n']]],
  ['call-time-ignored', "a request the call's time refuses is accepted when the clock, behind it, does not", 'relying-party.js',
    [["        if (!pre.ok) return refusal(pre.reason) // refused at the call's time, whatever the clock says\n", '']]],
  ['clock-unchecked', 'a clock that gives no time is passed on as a time', 'relying-party.js',
    [["          if (!Number.isSafeInteger(now) || now < 0) throw new TypeError('clock() must give a time in seconds')\n", '']]],
  ['memory-not-read-in-transaction', 'the transaction verifies without the memory as it stands there', 'relying-party.js',
    [['const stored = tx.lastHead(seen.identity)', 'const stored = undefined']]],
  ['consume-ignored', 'a claim already consumed is accepted again', 'relying-party.js',
    [["if (method === 'verifyClaim' && !tx.consume(r.id, r.until)) return refusal('replay')", "if (method === 'verifyClaim') tx.consume(r.id, r.until)"]]],
  ['storage-failure-ignored', 'a failed transaction is taken as success', 'relying-party.js',
    [["      })\n    } catch {\n      return refusal('storage')", "      })\n    } catch {\n      return pre"]]],
  ['no-head-memory', 'the stored head is not passed to the verifier', 'relying-party.js',
    [['return check({ ...call, lastHead: stored.head })', 'return check(call)']]],
  ['rotation-locks-out', 'a stored head the verifier cannot read locks its identity out', 'relying-party.js',
    [['      return check({ ...call, minHeadAt: Math.max(call.minHeadAt ?? 0, stored.at) })', "      return refusal('storage')"]]],
  ['time-floor-ignored', "an unreadable stored head's time is not kept as a floor", 'relying-party.js',
    [['      return check({ ...call, minHeadAt: Math.max(call.minHeadAt ?? 0, stored.at) })', '      return check(call)']]],
  ['refused-head-forgotten', "a refused request's verified head is not remembered", 'relying-party.js',
    [['        if (head.ok) {', '        if (head.ok && r.ok) {']]],
  ['equivocating-head-remembered', 'a head refused against the memory is remembered anyway', 'relying-party.js',
    [['        if (head.ok) {', '        if (true) {']]],
  ['refused-always-locks', 'every refused request whose head verifies takes the lock', 'relying-party.js',
    [['if (stored !== undefined && (stored.at > seen.at || stored.head === given.head)) {', 'if (false) {']]],
  ['call-lastHead-accepted', "a caller's lastHead is silently dropped", 'relying-party.js',
    [["  if (lastHead !== undefined) throw new TypeError('the adapter supplies lastHead from its memory')\n", '']]],
  ['tie-keeps-first', 'of two heads of one second, the first seen is kept', 'relying-party.js',
    [['            tx.replaceHead(seen.identity, given.head, seen.at, stored.head)\n', '']]],
  ['reason-without-memory', 'a request refused before the lock gives its reason without the memory', 'relying-party.js',
    [['        return refusal(withMemory((c) => verifier[method](given, c), call, stored).reason)', '        return refusal(pre.reason)']]],
  ['nonce-dropped', "the request's nonce is not passed to the verifier", 'relying-party.js', [['return { now, scope, method, url, nonce, contentDigest,', 'return { now, scope, method, url, contentDigest,']]],
  ['call-spread', 'the call is copied with a spread, dropping inherited fields', 'relying-party.js', [['const call = readCall(rawCall)', 'const call = { ...rawCall }']]],
  ['memory-head-regresses', 'the memory store replaces a head with an older one', 'stores.js', [['if (old === undefined || at > old.at) heads.set', 'heads.set']]],
  ['sqlite-head-regresses', 'the database store replaces a head with an older one', 'stores.js', [[' WHERE excluded.at > heads.at', '']]],
  ['memory-no-grace', 'the memory store expires claim ids at until', 'stores.js', [['if (until + grace <= now) consumed.delete(id)', 'if (until <= now) consumed.delete(id)']]],
  ['sqlite-no-grace', 'the database store expires claim ids at until', 'stores.js', [['remove.run(now - grace)', 'remove.run(now)']]],
]

function run (dir) {
  const { NODE_TEST_CONTEXT, ...env } = process.env
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['--test', '--test-reporter=tap', `--test-timeout=${TEST_TIMEOUT}`, ...SUITE], {
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
    assert.equal(jobs.length, 21, 'twin count')
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
