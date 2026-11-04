// The id page suite must fail against every broken twin of id/, and pass against the real page run through the same
// harness. Each twin is a copy of id/ with one targeted change, beside links to src/ and node_modules/, so its
// relative imports resolve the same in Node and in the browser.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, writeFileSync, mkdtempSync, mkdirSync, rmSync, readdirSync, symlinkSync } from 'node:fs'
import { spawn } from 'node:child_process'
import { tmpdir, availableParallelism } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = fileURLToPath(new URL('../../', import.meta.url))
const FILES = ['records.js', 'page.js', 'index.html', 'page.css']
const SUITE_DIR = join(ROOT, 'tests/id/')
const SUITE = readdirSync(SUITE_DIR).filter((f) => f.endsWith('.test.mjs')).map((f) => join(SUITE_DIR, f))

// [name, bug class, [find, replace] pairs, file]
const TWINS = [
  ['challenge-domain', 'the challenge is not in the W1 domain', [["const ASSERT_PREFIX = 'muid/v1/assert\\n'", "const ASSERT_PREFIX = 'muid/v1\\n'"]], 'records.js'],
  ['any-algorithm', 'a passkey of another algorithm becomes a root', [["  if (alg !== -7) throw new Error('the passkey must use ES256 (P-256)')\n", '']], 'records.js'],
  ['scopes-unsorted', 'scopes are signed in the order typed', [['const list = [...new Set(scopes)].sort()', 'const list = [...new Set(scopes)]']], 'records.js'],
  ['lifetime-unbounded', 'a delegation may outlive 30 days', [['lifetime > MAX_LIFETIME', 'lifetime > 10 * MAX_LIFETIME']], 'records.js'],
  ['attest-granted', 'a worker may be granted attest', [["  if (list.includes('attest')) throw new Error('the attest scope is not granted to a worker') // SPEC §8\n", '']], 'records.js'],
  ['audience-unchecked', 'any audience text is signed', [["  if (!isCanonicalOrigin(aud)) throw new Error('the audience must be an origin, such as https://app.example')\n", '']], 'records.js'],
  ['edit-keeps-review', 'an edit leaves the reviewed delegation signable', [["for (const id of ['subject', 'aud', 'scopes', 'days']) $(id).addEventListener('input', withdraw)", '']], 'page.js'],
  ['late-signature-kept', 'a signature that returns after an edit is handed over', [['    if (pending !== d) return // withdrawn while the passkey was asked\n', '']], 'page.js'],
  ['uv-preferred', 'the assertion does not require user verification', [["rpId, challenge: challenge([d.id]), userVerification: 'required',", "rpId, challenge: challenge([d.id]), userVerification: 'preferred',"]], 'page.js'],
  ['any-passkey', 'any passkey for the site may sign', [["      allowCredentials: [{ type: 'public-key', id: fromB64u(root.credential) }],\n", '']], 'page.js'],
  ['not-discoverable', 'the passkey is not a resident credential', [["residentKey: 'required', userVerification: 'required'", "userVerification: 'required'"]], 'page.js'],
  ['inline-script-allowed', "the CSP allows any inline script", [["script-src 'self' 'sha256-", "script-src 'self' 'unsafe-inline' 'sha256-"]], 'index.html'],
  ['hidden-shown', 'hidden parts of the page are displayed', [['[hidden] { display: none !important; }\n', '']], 'page.css'],
]

function run (dir) {
  const { NODE_TEST_CONTEXT, ...env } = process.env
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['--test', '--test-reporter=tap', ...SUITE], { env: { ...env, MUID_ID_DIR: dir }, stdio: ['ignore', 'pipe', 'pipe'] })
    let out = ''
    child.stdout.on('data', (d) => { out += d })
    child.stderr.on('data', (d) => { out += d })
    child.on('close', (code) => {
      const count = (k) => Number((out.match(new RegExp(`^# ${k} (\\d+)`, 'm')) ?? [])[1] ?? NaN)
      resolve({ code, pass: count('pass'), fail: count('fail') })
    })
  })
}

const sources = Object.fromEntries(FILES.map((f) => [f, readFileSync(join(ROOT, 'id', f), 'utf8')]))
const root = mkdtempSync(join(tmpdir(), 'muid-id-twins-'))

function generate (name, edits, file) {
  const base = join(root, name)
  const dir = join(base, 'id')
  mkdirSync(dir, { recursive: true })
  symlinkSync(join(ROOT, 'src'), join(base, 'src'))
  symlinkSync(join(ROOT, 'node_modules'), join(base, 'node_modules'))
  for (const f of FILES) {
    let text = sources[f]
    for (const [find, replace] of f === file ? edits : []) {
      const n = text.split(find).length - 1
      assert.equal(n, 1, `twin ${name}: target must occur exactly once in id/${f}, found ${n}: ${JSON.stringify(find)}`)
      text = text.replace(find, () => replace)
    }
    writeFileSync(join(dir, f), text)
  }
  return dir
}

test('id page broken twins', { timeout: 1_800_000 }, async (t) => {
  try {
    await t.test('control: an unmodified copy, run from outside the repository, passes', async () => {
      const r = await run(generate('control', [], null))
      assert.equal(r.code, 0, `control: exit ${r.code}, ${r.fail} failing`)
      assert.ok(r.pass >= 14, `control: only ${r.pass} tests ran`)
    })
    const jobs = TWINS.map(([name, why, edits, file]) => [name, why, generate(name, edits, file)])
    assert.equal(jobs.length, 13, 'twin count')
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
