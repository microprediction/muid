// TESTING.md §4e and §6: the attestation suite must fail against every broken twin, and pass against the real
// module run through the same harness. Twins are generated from src/attestation.js by one targeted change each.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, writeFileSync, mkdtempSync, rmSync, readdirSync } from 'node:fs'
import { spawn } from 'node:child_process'
import { tmpdir, availableParallelism } from 'node:os'
import { join } from 'node:path'

const SRC = new URL('../../src/attestation.js', import.meta.url)
const SUITE_DIR = new URL('../attestation/', import.meta.url).pathname
const SUITE = readdirSync(SUITE_DIR).filter((f) => f.endsWith('.test.mjs')).map((f) => join(SUITE_DIR, f))

// A twin lives outside the repository, so its imports are made absolute.
const absolute = (m) => new URL('../../src/' + m + '.js', import.meta.url).href
const IMPORTS = ['envelope', 'ed25519', 'bytes'].map((m) => ["from './" + m + ".js'", "from '" + absolute(m) + "'"])

// [name, bug class, [find, replace] pairs]
const TWINS = [
  ['no-check-digit', 'the ORCID check digit is not checked', [['  return apply(charCodeAt, id, [18]) === (r === 10 ? 88 : 48 + r)', '  return r >= 0']]],
  ['leading-zeros', 'GitHub ids may have leading zeros', [['const GITHUB = /^[1-9][0-9]{0,19}$/', 'const GITHUB = /^[0-9]{1,20}$/']]],
  ['any-provider', 'an unknown provider is checked as GitHub', [["  if (form === undefined) return refuse('provider')", '  if (form === undefined) return refuse(ACCOUNT.github(b.account) ? undefined : \'account\')']]],
  ['witness-by-trying', 'the named witness is ignored: any pinned key in its window will do', [['    if (w.key === sig.witness && w.nbf <= ctx.now', '    if (w.nbf <= ctx.now']]],
  ['key-window-ignored', 'a pinned key is accepted outside its own window', [['w.key === sig.witness && w.nbf <= ctx.now && ctx.now < w.exp', 'w.key === sig.witness']]],
  ['no-prefix', 'the witness signature covers the payload without the domain prefix', [['checkEd25519(sig.signature, signedBytes(payload), sig.witness)', 'checkEd25519(sig.signature, new TextEncoder().encode(payload), sig.witness)']]],
]

function run (implPath) {
  const { NODE_TEST_CONTEXT, ...env } = process.env
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['--test', '--test-reporter=tap', ...SUITE], {
      env: { ...env, MUID_ATTESTATION_IMPL: implPath ?? '', FC_RUNS: '100' },
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
const dir = mkdtempSync(join(tmpdir(), 'muid-attestation-twins-'))

function generate (name, edits) {
  let text = source
  for (const [find, replace] of [...IMPORTS, ...edits]) {
    const n = text.split(find).length - 1
    assert.equal(n, 1, `twin ${name}: target must occur exactly once in src/attestation.js, found ${n}: ${JSON.stringify(find)}`)
    text = text.replace(find, () => replace)
  }
  const path = join(dir, `${name}.js`)
  writeFileSync(path, text)
  return path
}

test('attestation broken twins', { timeout: 600_000 }, async (t) => {
  try {
    await t.test('control: an unmodified copy, run from outside the repository, passes', async () => {
      const r = await run(generate('control', []))
      assert.equal(r.code, 0, `control: exit ${r.code}, ${r.fail} failing`)
      assert.ok(r.pass > 10, `control: only ${r.pass} tests ran`)
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
