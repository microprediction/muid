// The witness suite must fail against every broken twin of witness/, and pass against the real witness run through
// the same harness. Each twin is a copy of witness/ with one targeted change.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, writeFileSync, mkdtempSync, mkdirSync, rmSync, readdirSync } from 'node:fs'
import { spawn } from 'node:child_process'
import { tmpdir, availableParallelism } from 'node:os'
import { join } from 'node:path'

const DIR = new URL('../../witness/', import.meta.url)
const FILE = 'witness.js'
const SUITE_DIR = new URL('../witness/', import.meta.url).pathname
const SUITE = readdirSync(SUITE_DIR).filter((f) => f.endsWith('.test.mjs')).map((f) => join(SUITE_DIR, f))
// The witness's imports of the core, made absolute because a twin lives outside the repository.
const CORE = ["from '../" + 'src/', "from '" + new URL('../../src/', import.meta.url).href]

// [name, bug class, [find, replace] pairs]
const TWINS = [
  ['rival-admitted', 'a record whose prev is not the effective membership is held (R3)', [["    if (b.prev !== s.membership) return refuse('prev')\n", '']]],
  ['epoch-unchecked', 'a membership record of another epoch is held', [["    if (b.epoch !== s.epoch + 1) return refuse('epoch')\n", '']]],
  ['added-root-early', "an added root's signature is held before a majority signed", [['2 * signersOf(held, r.id, s.roots) > s.roots.length', 'true']]],
  ['contest-by-pending-roots', 'a contest signed by a root of the pending record is held', [['      roots = rootsOf(held, s.settled)\n', '      roots = s.roots\n']]],
  ['freeze-any-membership', 'a freeze of a membership outside the state is held', [["      if (b.membership !== s.settled && b.membership !== s.membership) return refuse('membership')\n", '']]],
  ['signature-unchecked', "a root's signature is not verified on admission", [["return refuse('root-missing')\n    if (!checkRootAssertion(r.sig.assertion, { record: r.id, rpId, origin, key: k }).ok) return refuse('signature')\n", "return refuse('root-missing')\n"]]],
  ['revocation-signature-unchecked', "a root's revocation is not verified", [["const k = rootKeys(held).get(r.sig.root)\n      if (!checkRootAssertion(r.sig.assertion, { record: r.id, rpId, origin, key: k }).ok) return refuse('signature')\n", 'const k = rootKeys(held).get(r.sig.root)\n']]],
  ['self-revocation-unsigned', "a delegate's revocation of itself is not verified", [["      if (!checkEd25519(r.sig.signature, signedBytes(r.payload), b.target).ok) return refuse('signature')\n", '']]],
  ['no-cap', 'a list grows past MAX_RECORDS', [["    if (held[list].length >= MAX_RECORDS) return refuse('full')\n", '']]],
  ['root-unnamed', 'any root record is held', [["      return refuse('root-unnamed')", '      return accept({ held: add(held, \'roots\', text) })']]],
  ['dead-admits', 'records are held for a dead identity', [["return s.dead ? refuse('dead') : s", 'return s']]],
  ['identity-unchecked', "another identity's record is held", [["    if (b.identity !== held.identity) return refuse('identity')\n", '']]],
  ['shape-unchecked', 'a record of the wrong form is held', [["    if (!SHAPES[type](b) || !onlyKeys(r.sig, ['assertion', 'root'])) return refuse('shape')\n", '']]],
  ['anchor-unchecked', 'a successor is anchored without verifiers following it', [['if (stateOf(add(own, \'anchors\', text)).membership === x)', 'if (true)']]],
  ['anchor-highest-id', 'of several successors, the highest id is anchored', [['.map((m) => m.id))].sort()', '.map((m) => m.id))].sort().reverse()']]],
  ['anchor-first-held', 'of several successors, the first held is anchored', [['.map((m) => m.id))].sort()', '.map((m) => m.id))]']]],
  ['settle-early', 'the epoch is settled before the window has passed', [['if (now < at + contestWindow) {', 'if (now < at) {']]],
  ['contest-ignored', 'a contest inside the window is never anchored', [['        if (contest === undefined || contested) break\n', '        break\n']]],
  ['contest-unchecked', 'a contest is anchored whatever its signers', [['        if (!stateOf(add(held, \'anchors\', text)).dead) break\n', '']]],
  ['settle-ignores-contest', 'an anchored contest does not make the settlement contested', [["outcome: contested ? 'contested' : s.membership", 'outcome: s.membership']]],
  ['own-view-with-contests', "the witness's view counts contest anchors, so a contested epoch never settles", [['anchors: held.anchors.filter((t, i) => !isContest(anchors[i]))', 'anchors: held.anchors']]],
  ['one-step', 'a held successor waits for the next step after a settlement', [['      sign1(\'settlement\', text) // a contested', '      sign1(\'settlement\', text); break // a contested']]],
  ['sign-unchecked', "a signature not under the witness's key is published", [["    if (!checkEd25519(signature, signedBytes(payload), key).ok) throw new Error('sign gave no valid signature under the witness key')\n", '']]],
  ['head-without-revocations', 'the head leaves out the revocations held', [['headOf(s, now, kept(held, s).map((x) => x.target))', 'headOf(s, now, [])']]],
  ['revoke-without-authority', 'any root of the identity can revoke', [["      if (!has(s.authority, r.sig.root)) return refuse('signer')\n", '']]],
  ['self-revoke-any-key', 'a key revokes itself without the delegation that makes it a delegate', [["      if (!delegates(held, s, delegation, now, b.target)) return refuse('delegation')\n", '']]],
  ['revocations-kept-forever', 'a revocation outlives the membership it was admitted under', [['(x) => x.under === s.settled || x.under === s.membership)', '() => true)']]],
  ['revocation-under-settled', 'a revocation admitted while a change is pending is dropped when it settles', [['under: s.membership })', 'under: s.settled })']]],
  ['revocation-duplicates', 'another revocation for a target already held adds an entry', [['    if (live.some((x) => x.target === b.target)) return accept({ held })\n', '']]],
]

function run (dir) {
  const { NODE_TEST_CONTEXT, ...env } = process.env
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['--test', '--test-reporter=tap', ...SUITE], {
      env: { ...env, MUID_WITNESS_DIR: dir, FC_RUNS: '30' },
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    // A twin that makes advance loop for ever is caught by the suite never finishing.
    const timer = setTimeout(() => child.kill('SIGKILL'), HANG)
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
const source = readFileSync(new URL(FILE, DIR), 'utf8')
const root = mkdtempSync(join(tmpdir(), 'muid-witness-twins-'))

function generate (name, edits) {
  const dir = join(root, name)
  mkdirSync(dir)
  let text = source.split(CORE[0]).join(CORE[1])
  for (const [find, replace] of edits) {
    const n = text.split(find).length - 1
    assert.equal(n, 1, `twin ${name}: target must occur exactly once in witness/${FILE}, found ${n}: ${JSON.stringify(find)}`)
    text = text.replace(find, () => replace)
  }
  writeFileSync(join(dir, FILE), text)
  return dir
}

test('witness broken twins', { timeout: 1_800_000 }, async (t) => {
  try {
    await t.test('control: an unmodified copy, run from outside the repository, passes', async () => {
      const r = await run(generate('control', []))
      assert.equal(r.code, 0, `control: exit ${r.code}, ${r.fail} failing${r.hung ? ', hung' : ''}`)
      assert.ok(r.pass >= 25, `control: only ${r.pass} tests ran`)
    })
    const jobs = TWINS.map(([name, why, edits]) => [name, why, generate(name, edits)])
    assert.equal(jobs.length, 29, 'twin count')
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
