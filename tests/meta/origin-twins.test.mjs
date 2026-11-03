// TESTING.md §4c and §6: the origin suite must fail against every broken twin, and pass against the real module
// run through the same harness. Twins are generated from src/origin.js by one targeted change each.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, writeFileSync, mkdtempSync, rmSync, readdirSync } from 'node:fs'
import { spawn } from 'node:child_process'
import { tmpdir, availableParallelism } from 'node:os'
import { join } from 'node:path'

const SRC = new URL('../../src/origin.js', import.meta.url)
const SUITE_DIR = new URL('../origin/', import.meta.url).pathname
const SUITE = readdirSync(SUITE_DIR).filter((f) => f.endsWith('.test.mjs')).map((f) => join(SUITE_DIR, f))

const IMPORTS = []

// [name, bug class, [find, replace] pairs]
const TWINS = [
  ['uppercase', 'uppercase hosts are accepted', [['const SHAPE = /^https:\\/\\/([a-z0-9.-]{1,253})', 'const SHAPE = /^https:\\/\\/([a-zA-Z0-9.-]{1,253})'],
    ['const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/', 'const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i']]],
  ['port-443', 'the default port is accepted', [[" || m[2] === '443')", ')']]],
  ['trailing-slash', 'a trailing slash is accepted', [['(?::([1-9][0-9]{0,4}))?$/', '(?::([1-9][0-9]{0,4}))?\\/?$/']]],
  ['idn-allowed', 'xn-- labels are accepted', [["  return apply(exec, LABEL, [label]) !== null && !(label[2] === '-' && label[3] === '-')", '  return apply(exec, LABEL, [label]) !== null']]],
  ['ipv4-allowed', 'an all-digit last label (an IPv4 address) is accepted', [['  return apply(exec, DIGITS, [labels[labels.length - 1]]) === null', '  return true']]],
  ['no-length-limits', 'labels and hosts of any length are accepted', [['([a-z0-9.-]{1,253})', '([a-z0-9.-]+)'], ['[a-z0-9-]{0,61}', '[a-z0-9-]*']]],
]

function run (implPath) {
  const { NODE_TEST_CONTEXT, ...env } = process.env
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['--test', '--test-reporter=tap', ...SUITE], {
      env: { ...env, MUID_ORIGIN_IMPL: implPath ?? '', FC_RUNS: '100' },
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
const dir = mkdtempSync(join(tmpdir(), 'muid-origin-twins-'))

function generate (name, edits) {
  let text = source
  for (const [find, replace] of [...IMPORTS, ...edits]) {
    const n = text.split(find).length - 1
    assert.equal(n, 1, `twin ${name}: target must occur exactly once in src/origin.js, found ${n}: ${JSON.stringify(find)}`)
    text = text.replace(find, () => replace)
  }
  const path = join(dir, `${name}.js`)
  writeFileSync(path, text)
  return path
}

test('origin broken twins', { timeout: 600_000 }, async (t) => {
  try {
    await t.test('control: an unmodified copy, run from outside the repository, passes', async () => {
      const r = await run(generate('control', []))
      assert.equal(r.code, 0, `control: exit ${r.code}, ${r.fail} failing`)
      assert.ok(r.pass >= 5, `control: only ${r.pass} tests ran`)
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
