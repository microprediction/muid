// SPEC §12 and TESTING.md §6: the receipt suite must fail against every broken twin, and pass against the real module run
// through the same harness. Twins are generated from src/receipt.js by one targeted change each.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, writeFileSync, mkdtempSync, rmSync, readdirSync } from 'node:fs'
import { spawn } from 'node:child_process'
import { tmpdir, availableParallelism } from 'node:os'
import { join } from 'node:path'

// A test that never ends under a twin fails (the twin is caught) instead of holding the harness open.
const TEST_TIMEOUT = 300_000

const SRC = new URL('../../src/receipt.js', import.meta.url)
const SUITE_DIR = new URL('../receipt/', import.meta.url).pathname
const SUITE = readdirSync(SUITE_DIR).filter((f) => f.endsWith('.test.mjs')).map((f) => join(SUITE_DIR, f))

// A twin lives outside the repository, so its imports are made absolute.
const IMPORTS = [
  ["from './bytes.js'", "from '" + new URL('../../src/bytes.js', import.meta.url).href + "'"],
  ...['envelope', 'ed25519', 'origin', 'note', 'merkle', 'attestation'].map((m) => ["from './" + m + ".js'", "from '" + new URL('../../src/' + m + '.js', import.meta.url).href + "'"]),
]

// [name, bug class, [find, replace] pairs]
const TWINS = [
  ['services-length-reread', 'the pinned services have their length read at every step', [['  for (let i = 0; i < n; i++) {', '  for (let i = 0; i < services.length; i++) {']]],
  ['service-window-inclusive', "a pinned service key's window includes its exp", [['s.nbf <= b.at && b.at < s.exp && s.exp > exp', 's.nbf <= b.at && b.at <= s.exp && s.exp > exp'], ['if (existedBy >= exp + c.skew)', 'if (existedBy > exp + c.skew)']]],
  ['service-origin-unchecked', 'a key pinned for one service vouches for receipts naming another', [['if (s.origin === b.service && s.key === sig.service', 'if (s.key === sig.service']]],
  ['window-unchecked', 'a service key outside its window is accepted', [[' && s.nbf <= b.at && b.at < s.exp && s.exp > exp)', ' && s.exp > exp)']]],
  ['retired-key-backdates', 'a retired key mints receipts by backdating into its old window', [["  if (existedBy >= exp + c.skew) return refuse('service')\n", '']]],
  ['signature-unchecked', 'the service signature is not checked', [['  if (!k.ok) return k\n', '']]],
  ['entry-is-payload', 'the logged entry is taken to be the payload, not the envelope as logged', [['[receipt]))', '[r.payload]))']]],
  ['inclusion-skipped', 'a receipt need not be in the log', [["root: fromHex(cp.root) })) return refuse('inclusion')", "root: fromHex(cp.root) })) {}"]]],
  ['checkpoint-ignored', "the checkpoint's verdict is ignored", [["  if (!cp.ok) return refuse('checkpoint')\n", '']]],
  ['latest-time', 'existedBy is the latest cosignature, which one cosigner alone controls', [['cp.times[c.quorum - 1]', 'cp.times[cp.times.length - 1]']]],
  ['time-unchecked', 'a receipt may claim acceptance after it was logged', [['b.at > existedBy + c.skew || ', '']]],
  ['future-receipt', 'a receipt dated after now is accepted', [[' || b.at > c.now + c.skew) return refuse', ') return refuse']]],
  ['quorum-zero', 'receipts are accepted with no time from outside the service', [["  if (quorum < 1) throw", "  if (false) throw"]]],
  ['claim-unchecked', 'a given claim is not compared with the one named', [["    if (named.id !== b.claim || named.body.delegation !== b.delegation) return refuse('claim')\n", '']]],
  ['claim-delegation-unchecked', 'a given claim under another delegation is accepted', [[' || named.body.delegation !== b.delegation', '']]],
]

function run (implPath) {
  const { NODE_TEST_CONTEXT, ...env } = process.env
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['--test', '--test-reporter=tap', `--test-timeout=${TEST_TIMEOUT}`, ...SUITE], {
      env: { ...env, MUID_RECEIPT_IMPL: implPath ?? '', FC_RUNS: '100' },
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
const dir = mkdtempSync(join(tmpdir(), 'muid-receipt-twins-'))

function generate (name, edits) {
  let text = source
  for (const [find, replace] of [...IMPORTS, ...edits]) {
    const n = text.split(find).length - 1
    assert.equal(n, 1, `twin ${name}: target must occur exactly once in src/receipt.js, found ${n}: ${JSON.stringify(find)}`)
    text = text.replace(find, () => replace)
  }
  const path = join(dir, `${name}.js`)
  writeFileSync(path, text)
  return path
}

test('receipt broken twins', { timeout: 600_000 }, async (t) => {
  try {
    await t.test('control: an unmodified copy, run from outside the repository, passes', async () => {
      const r = await run(generate('control', []))
      assert.equal(r.code, 0, `control: exit ${r.code}, ${r.fail} failing`)
      assert.ok(r.pass >= 9, `control: only ${r.pass} tests ran`)
    })

    const jobs = TWINS.map(([name, why, edits]) => [name, why, generate(name, edits)])
    assert.equal(jobs.length, 15, 'twin count')
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
