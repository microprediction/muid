// SPEC R8 and TESTING.md §6: the membership suite must fail against every broken twin, and pass against the real
// module run through the same harness. Twins are generated from src/membership.js by one targeted change each.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, writeFileSync, mkdtempSync, rmSync, readdirSync } from 'node:fs'
import { spawn } from 'node:child_process'
import { tmpdir, availableParallelism } from 'node:os'
import { join } from 'node:path'

const SRC = new URL('../../src/membership.js', import.meta.url)
const SUITE_DIR = new URL('../membership/', import.meta.url).pathname
const SUITE = readdirSync(SUITE_DIR).filter((f) => f.endsWith('.test.mjs')).map((f) => join(SUITE_DIR, f))

// A twin lives outside the repository, so its imports are made absolute.
const absolute = (m) => new URL('../../src/' + m + '.js', import.meta.url).href
const IMPORTS = ['envelope', 'assertion', 'root', 'attestation', 'bytes'].map((m) => ["from './" + m + ".js'", "from '" + absolute(m) + "'"])

// [name, bug class, [find, replace] pairs]
const TWINS = [
  ['half-is-majority', 'exactly half of the previous roots can change membership', [['  if (2 * yes <= cur.roots.length) return false', '  if (2 * yes < cur.roots.length) return false']]],
  ['added-roots-unsigned', 'a root can be added without its own signature', [['    if (!has(cur.roots, r) && !p.signers.has(r)) return false', '    if (false) return false']]],
  ['witness-window-ignored', 'anchors and settlements are accepted whatever the witness key\'s window', [['ctx.keys, r.body.at, r.body.at + 1)', 'ctx.keys, 0, 0)']]],
  ['contest-without-majority', 'any one root can end the identity with a contest', [['        if (2 * yes > cur.roots.length) return accept({ dead: true })', '        if (yes > 0) return accept({ dead: true })']]],
  ['pending-full-authority', 'new roots have authority before settlement', [['if (!pending || has(cur.roots, m.roots[i])) authority', 'if (true) authority']]],
  ['freeze-lifted-at-anchor', 'a freeze on the settled membership stops applying once a successor is anchored', [['frozenBy(m) || frozenBy(cur)', 'frozenBy(m)']]],
  ['settlements-ignored', 'settlements are not followed', [['    const outcomes = r.settled.get(cur.id)', '    const outcomes = undefined']]],
  ['rival-chosen', 'of two anchored rivals the first is taken', [['    if (candidates.length > 1) return accept({ dead: true })\n', '']]],
  ['assertion-unchecked', 'root signatures are not verified', [['  if (!a.ok) return undefined\n  counted.add', '  counted.add']]],
]

function run (implPath) {
  const { NODE_TEST_CONTEXT, ...env } = process.env
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['--test', '--test-reporter=tap', ...SUITE], {
      env: { ...env, MUID_MEMBERSHIP_IMPL: implPath ?? '', FC_RUNS: '60' },
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
const dir = mkdtempSync(join(tmpdir(), 'muid-membership-twins-'))

function generate (name, edits) {
  let text = source
  for (const [find, replace] of [...IMPORTS, ...edits]) {
    const n = text.split(find).length - 1
    assert.equal(n, 1, `twin ${name}: target must occur exactly once in src/membership.js, found ${n}: ${JSON.stringify(find)}`)
    text = text.replace(find, () => replace)
  }
  const path = join(dir, `${name}.js`)
  writeFileSync(path, text)
  return path
}

test('membership broken twins', { timeout: 600_000 }, async (t) => {
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
