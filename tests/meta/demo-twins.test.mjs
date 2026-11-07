// The demo's unit suites must fail against every broken twin of demo/, and pass against the real demo run through
// the same harness. Each twin is a copy of demo/ with one targeted change. (D1, the end-to-end scenarios, needs Go
// and runs in the test job.)
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, writeFileSync, mkdtempSync, mkdirSync, rmSync, readdirSync } from 'node:fs'
import { spawn } from 'node:child_process'
import { tmpdir, availableParallelism } from 'node:os'
import { join } from 'node:path'

const DIR = new URL('../../demo/', import.meta.url)
const FILES = ['forecasts.js', 'history.js']
const SUITE_DIR = new URL('../demo/', import.meta.url).pathname
const SUITE = readdirSync(SUITE_DIR).filter((f) => /^D[234]-.*\.test\.mjs$/.test(f)).map((f) => join(SUITE_DIR, f))
// The demo's imports of the core, made absolute because a twin lives outside the repository.
const CORE = ["from '../" + 'src/', "from '" + new URL('../../src/', import.meta.url).href]
// And its one package import, resolved from here.
const NOBLE = ["from '@noble/hashes/sha2.js'", `from '${import.meta.resolve('@noble/hashes/sha2.js')}'`]

// [name, bug class, [find, replace] pairs, file]
const TWINS = [
  ['bundle-proof-unchecked', 'a proof the log gives is kept unchecked', [['      if (!verifyInclusion({ leafHash: leaf, index: k.index, size: c.size, proof, root: bytes(c.root) })) return false\n', '']], 'forecasts.js'],
  ['publish-concurrent', 'two publications of one contribution run at once', [['    if (k.flight !== undefined) { await k.flight; return false } // one publication of a contribution at a time\n', '']], 'forecasts.js'],
  ['standing-by-arrival', 'the standing forecast is the last to arrive', [['if (s === undefined || k.signedAt >= s.signedAt) standing.set', 'standing.set']], 'forecasts.js'],
  ['history-duplicates', 'a contribution given twice is counted twice', [["      else if (r.ok && seen.has(r.claim)) refused.push({ index: i, reason: 'duplicate' })\n", '']], 'history.js'],
  ['checkpoint-not-holding', 'the bundle keeps a checkpoint that does not hold the receipt', [['if (c.ok && c.size > index) return', 'if (c.ok) return']], 'forecasts.js'],
  ['checkpoint-uncosigned', 'a checkpoint without the cosigner quorum is bundled', [['verifyCheckpoint(text, { ...checkpoints, now: clock() })', 'verifyCheckpoint(text, { ...checkpoints, quorum: 0, now: clock() })']], 'forecasts.js'],
  ['receipt-postdated', 'the receipt is dated after the claim was accepted', [['claim: accepted.id, at: now }', 'claim: accepted.id, at: now + 3600 }']], 'forecasts.js'],
  ['receipt-other-claim', 'the receipt names the delegation, not the claim', [['claim: accepted.id, at: now }', 'claim: accepted.delegation.id, at: now }']], 'forecasts.js'],
  ['lost-on-failure', 'a contribution whose receipt is not yet published is dropped', [['    kept.push(k)\n', ''], ['return (await published(k)) ? { bundle: k.bundle }', 'return (await published(k)) ? (kept.push(k), { bundle: k.bundle })']], 'forecasts.js'],
  ['contributions-everyone', "every identity's contributions are listed", [['return json(200, kept.filter((k) => k.identity === identity)\n', 'return json(200, kept\n']], 'forecasts.js'],
  ['body-unbounded', 'a request body of any size is read', [["    if (text === undefined) return { error: json(413, { ok: false, reason: 'too-large' }) }\n", '']], 'forecasts.js'],
  ['body-read-in-full', 'the body is read in full before its size is checked', [['    n += r.value.length\n    if (n > max) {', '    n += r.value.length\n    if (false) {']], 'forecasts.js'],
  ['answer-unchecked', 'an answer that is not a list is iterated', [["    if (!Array.isArray(bundles)) return { accepted, refused: [{ index: null, reason: 'bundles' }] }\n", '']], 'history.js'],
  ['collect-any-scope', 'collection needs no collect scope', [["const collect = (request) => claimed(request, 'collect',", "const collect = (request) => claimed(request, 'forecast',"]], 'forecasts.js'],
  ['resolved-twice', 'a question resolved again scores its forecasts again', [['      return 0\n    }\n    q.outcome = outcome', '    }\n    q.outcome = outcome']], 'forecasts.js'],
  ['forecast-unchecked', 'any data is kept as a forecast', [['    if (f === undefined) return { refused: \'forecast\' }\n', '']], 'forecasts.js'],
  ['earnings-everyone', "every identity's contributions count toward one's earnings", [['const mine = kept.filter((k) => k.identity === identity)', 'const mine = kept']], 'forecasts.js'],
  ['collect-twice', 'what was collected is not taken off the balance', [['collected.set(identity, (collected.get(identity) ?? 0) + amount)', 'collected.get(identity)']], 'forecasts.js'],
  ['identity-unchecked', "another identity's receipt is counted as this one's", [["if (r.ok && r.identity !== identity) refused.push({ index: i, reason: 'identity' })\n      else if (r.ok && seen", 'if (r.ok && seen']], 'history.js'],
  ['claim-dropped', 'the claim a bundle carries is not checked against its receipt', [['index: b.index, claim: b.claim }', 'index: b.index }']], 'history.js'],
  ['proof-unchecked', 'a proof that is not hex is read anyway', [["b.proof.every((h) => typeof h === 'string' && /^(?:[0-9a-f]{2})*$/.test(h))", 'true']], 'history.js'],
  ['appended-twice', 'a receipt the log already took is appended again on retry', [['if (k.index === undefined) k.index = await log.append(k.receipt)', 'k.index = await log.append(k.receipt)']], 'forecasts.js'],
  ['pending-as-200', 'a contribution whose receipt is not published is answered as if it were', [['json(r.value.pending ? 202 : 200,', 'json(200,']], 'forecasts.js'],
  ['every-forecast-scores', 'every forecast scores, not each identity\'s standing one', [['standing.get(k.identity)', 'standing.get(k.claim)'], ['standing.set(k.identity, k)', 'standing.set(k.claim, k)']], 'forecasts.js'],
  ['closed-accepted', 'a forecast after the closing time is kept', [[' || now >= q.closes) return', ') return']], 'forecasts.js'],
  ['resolved-open', 'a forecast for a resolved question is kept', [['if (q === undefined || q.outcome !== undefined ||', 'if (q === undefined ||']], 'forecasts.js'],
  ['conflicting-resolution', 'a question resolved with the other outcome is quietly left', [["      if (q.outcome !== outcome) throw new Error('already resolved with the other outcome')\n", '']], 'forecasts.js'],
  ['pending-verified', 'a pending contribution is verified as a bundle', [['const r = b?.pending === true', 'const r = false']], 'history.js'],
]

function run (dir) {
  const { NODE_TEST_CONTEXT, ...env } = process.env
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['--test', '--test-reporter=tap', ...SUITE], {
      env: { ...env, MUID_DEMO_DIR: dir },
      stdio: ['ignore', 'pipe', 'pipe'],
      detached: true, // its own process group, so that a hang is ended with every test process it started
    })
    // A twin that makes advance loop for ever is caught by the suite never finishing.
    const timer = setTimeout(() => process.kill(-child.pid, 'SIGKILL'), HANG)
    let out = ''
    child.stdout.on('data', (d) => { out += d })
    child.stderr.on('data', (d) => { out += d })
    child.on('close', (code, signal) => {
      clearTimeout(timer)
      if (signal === 'SIGKILL') return resolve({ code: null, hung: true })
      const count = (k) => Number((out.match(new RegExp(`^# ${k} (\\d+)`, 'm')) ?? [])[1] ?? NaN)
      resolve({ code, pass: count('pass'), fail: count('fail') })
    })
  })
}

const HANG = 180_000 // ms; the real suite takes seconds here
const sources = Object.fromEntries(FILES.map((f) => [f, readFileSync(new URL(f, DIR), 'utf8')]))
const root = mkdtempSync(join(tmpdir(), 'muid-demo-twins-'))

function generate (name, edits, file) {
  const dir = join(root, name)
  mkdirSync(dir)
  for (const f of FILES) {
    let text = sources[f].split(CORE[0]).join(CORE[1]).split(NOBLE[0]).join(NOBLE[1])
    for (const [find, replace] of f === file ? edits : []) {
      const n = text.split(find).length - 1
      assert.equal(n, 1, `twin ${name}: target must occur exactly once in demo/${f}, found ${n}: ${JSON.stringify(find)}`)
      text = text.replace(find, () => replace)
    }
    writeFileSync(join(dir, f), text)
  }
  return dir
}

test('demo broken twins', { timeout: 1_800_000 }, async (t) => {
  try {
    await t.test('control: an unmodified copy, run from outside the repository, passes', async () => {
      const r = await run(generate('control', []))
      assert.equal(r.code, 0, `control: exit ${r.code}, ${r.fail} failing${r.hung ? ', hung' : ''}`)
      assert.ok(r.pass >= 8, `control: only ${r.pass} tests ran`)
    })
    const jobs = TWINS.map(([name, why, edits, file]) => [name, why, generate(name, edits, file)])
    assert.equal(jobs.length, 28, 'twin count')
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
        if (r.hung) return
        assert.ok(r.pass > 0 && r.fail > 0, `twin ${name}: the suite did not run normally (pass ${r.pass}, fail ${r.fail})`)
      })
    }
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})
