// SPEC §12 and TESTING.md §6: the Merkle proof suite must fail against every broken twin, and pass against the real module run
// through the same harness. Twins are generated from src/merkle.js by one targeted change each.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, writeFileSync, mkdtempSync, rmSync, readdirSync } from 'node:fs'
import { spawn } from 'node:child_process'
import { tmpdir, availableParallelism } from 'node:os'
import { join } from 'node:path'

const SRC = new URL('../../src/merkle.js', import.meta.url)
const SUITE_DIR = new URL('../merkle/', import.meta.url).pathname
const SUITE = readdirSync(SUITE_DIR).filter((f) => f.endsWith('.test.mjs')).map((f) => join(SUITE_DIR, f))

// A twin lives outside the repository, so its imports are made absolute.
const IMPORTS = [
  ["from './bytes.js'", "from '" + new URL('../../src/bytes.js', import.meta.url).href + "'"],
  ["from '@noble/hashes/sha2.js'", "from '" + import.meta.resolve('@noble/hashes/sha2.js') + "'"],
]

// [name, bug class, [find, replace] pairs]
const TWINS = [
  ['no-node-prefix', 'interior nodes are hashed without their 0x01 prefix (second-preimage across levels)', [['  b[0] = 1\n', '']]],
  ['size-order-unchecked', 'a proof from a larger tree to a smaller one is accepted', [['  if (size1 > size2) return false // not redundant', '  if (false) return false // not redundant']]],
  ['trailing-path-accepted', 'an inclusion proof is accepted before its path is exhausted', [['  return sn === 0 && same(r, root)', '  return same(r, root)']]],
  ['index-unbounded', 'an index at or past the tree size is accepted', [['  if (index >= size) return false\n', '']]],
  ['first-root-unchecked', 'consistency checks only the second root', [['  return sn === 0 && same(fr, root1) && same(sr, root2)', '  return sn === 0 && same(sr, root2)']]],
  ['empty-tree-any-root', 'the empty tree is consistent whatever its root', [['  if (size1 === 0) return proof.length === 0 && same(root1, EMPTY)', '  if (size1 === 0) return proof.length === 0']]],
  ['equal-sizes-any-roots', 'equal sizes are consistent whatever their roots', [['  if (size1 === size2) return proof.length === 0 && same(root1, root2)', '  if (size1 === size2) return proof.length === 0']]],
  ['short-hashes', 'a hash of any length is accepted', [['  return b !== undefined && b.length === 32', '  return b !== undefined']]],
  ['bit-shift-halving', 'halving by a 32-bit shift, wrong for sizes past 2^31', [['const half = (n) => (n - (n % 2)) / 2', 'const half = (n) => n >> 1']]],
  ['proof-unbounded', 'a proof of any length is read in full', [['list.length > MAX_PROOF) return undefined', 'false) return undefined']]],
]

function run (implPath) {
  const { NODE_TEST_CONTEXT, ...env } = process.env
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['--test', '--test-reporter=tap', ...SUITE], {
      env: { ...env, MUID_MERKLE_IMPL: implPath ?? '', FC_RUNS: '100' },
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
const dir = mkdtempSync(join(tmpdir(), 'muid-merkle-twins-'))

function generate (name, edits) {
  let text = source
  for (const [find, replace] of [...IMPORTS, ...edits]) {
    const n = text.split(find).length - 1
    assert.equal(n, 1, `twin ${name}: target must occur exactly once in src/merkle.js, found ${n}: ${JSON.stringify(find)}`)
    text = text.replace(find, () => replace)
  }
  const path = join(dir, `${name}.js`)
  writeFileSync(path, text)
  return path
}

test('merkle broken twins', { timeout: 600_000 }, async (t) => {
  try {
    await t.test('control: an unmodified copy, run from outside the repository, passes', async () => {
      const r = await run(generate('control', []))
      assert.equal(r.code, 0, `control: exit ${r.code}, ${r.fail} failing`)
      assert.ok(r.pass >= 9, `control: only ${r.pass} tests ran`)
    })

    const jobs = TWINS.map(([name, why, edits]) => [name, why, generate(name, edits)])
    assert.equal(jobs.length, 10, 'twin count')
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
