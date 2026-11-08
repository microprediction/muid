// TESTING.md §4d and §6: the delegation suite must fail against every broken twin, and pass against the real module
// run through the same harness. Twins are generated from src/delegation.js by one targeted change each.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, writeFileSync, mkdtempSync, rmSync, readdirSync } from 'node:fs'
import { spawn } from 'node:child_process'
import { tmpdir, availableParallelism } from 'node:os'
import { join } from 'node:path'

// A test that never ends under a twin fails (the twin is caught) instead of holding the harness open.
const TEST_TIMEOUT = 300_000

const SRC = new URL('../../src/delegation.js', import.meta.url)
const SUITE_DIR = new URL('../delegation/', import.meta.url).pathname
const SUITE = readdirSync(SUITE_DIR).filter((f) => f.endsWith('.test.mjs')).map((f) => join(SUITE_DIR, f))

// A twin lives outside the repository, so its imports are made absolute.
const absolute = (m) => new URL('../../src/' + m + '.js', import.meta.url).href
const IMPORTS = ['envelope', 'assertion', 'ed25519', 'origin', 'root', 'bytes'].map((m) => ["from './" + m + ".js'", "from '" + absolute(m) + "'"])

// [name, bug class, [find, replace] pairs]
const TWINS = [
  ['skew-on-exp', 'clock skew also extends the expiry', [["  if (ctx.now >= b.exp) return refuse('expired')", "  if (ctx.now >= b.exp + ctx.skew) return refuse('expired')"]]],
  ['inclusive-exp', 'a delegation is still valid at exp', [["  if (ctx.now >= b.exp) return refuse('expired')", "  if (ctx.now > b.exp) return refuse('expired')"]]],
  ['no-lifetime-cap', 'any lifetime is accepted', [[' || b.exp - b.nbf > ctx.maxLifetime', '']]],
  ['scopes-unsorted', 'scopes need not be sorted or distinct', [["    if (i > 0 && !(scopes[i - 1] < scopes[i])) return false\n", '']]],
  ['no-consent', 'the subject\'s countersignature is not checked', [["  return checkEd25519(sig.subject, acceptMessage(id), b.subject).ok ? accept({ id, body: b }) : refuse('subject-consent')", '  return accept({ id, body: b })']]],
  ['aud-unchecked', 'the audience is not checked', [["  if (!isCanonicalOrigin(b.aud)) return refuse('aud')\n", '']]],
  ['fixed-record', 'the root assertion is checked against the payload text, not the record id', [['{ record: id, rpId', '{ record: record.payload.slice(0, 64), rpId']]],
  ['root-unbound', 'the key given is not tied to the root the delegation names', [["  if (rootIdOf(ctx.rpId, ctx.rootKey) !== b.root) return refuse('root')\n", '']]],
  ['subject-key-unchecked', 'the subject key is not checked for K1', [["  if (!checkEd25519Key(b.subject).ok) return refuse('subject-key')\n", '']]],
]

function run (implPath) {
  const { NODE_TEST_CONTEXT, ...env } = process.env
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['--test', '--test-reporter=tap', `--test-timeout=${TEST_TIMEOUT}`, ...SUITE], {
      env: { ...env, MUID_DELEGATION_IMPL: implPath ?? '', FC_RUNS: '100' },
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
const dir = mkdtempSync(join(tmpdir(), 'muid-delegation-twins-'))

function generate (name, edits) {
  let text = source
  for (const [find, replace] of [...IMPORTS, ...edits]) {
    const n = text.split(find).length - 1
    assert.equal(n, 1, `twin ${name}: target must occur exactly once in src/delegation.js, found ${n}: ${JSON.stringify(find)}`)
    text = text.replace(find, () => replace)
  }
  const path = join(dir, `${name}.js`)
  writeFileSync(path, text)
  return path
}

test('delegation broken twins', { timeout: 600_000 }, async (t) => {
  try {
    await t.test('control: an unmodified copy, run from outside the repository, passes', async () => {
      const r = await run(generate('control', []))
      assert.equal(r.code, 0, `control: exit ${r.code}, ${r.fail} failing`)
      assert.ok(r.pass > 10, `control: only ${r.pass} tests ran`)
    })

    const jobs = TWINS.map(([name, why, edits]) => [name, why, generate(name, edits)])
    assert.equal(jobs.length, 9, 'twin count')
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
