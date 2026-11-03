// SPEC F5 and TESTING.md §6: the verifier suite must fail against every broken twin, and pass against the real module
// run through the same harness. Twins are generated from src/verifier.js by one targeted change each.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, writeFileSync, mkdtempSync, rmSync, readdirSync } from 'node:fs'
import { spawn } from 'node:child_process'
import { tmpdir, availableParallelism } from 'node:os'
import { join } from 'node:path'

const SRC = new URL('../../src/verifier.js', import.meta.url)
const SUITE_DIR = new URL('../verifier/', import.meta.url).pathname
const SUITE = readdirSync(SUITE_DIR).filter((f) => f.endsWith('.test.mjs')).map((f) => join(SUITE_DIR, f))

// A twin lives outside the repository, so its imports are made absolute.
const absolute = (m) => new URL('../../src/' + m + '.js', import.meta.url).href
const IMPORTS = ['envelope', 'root', 'delegation', 'attestation', 'origin', 'bytes'].map((m) => ["from './" + m + ".js'", "from '" + absolute(m) + "'"])

// [name, bug class, [find, replace] pairs]
const TWINS = [
  ['no-staleness', 'a head of any age is accepted', [['h.at < now - cfg.maxStaleness || ', '']]],
  ['min-head-at-ignored', 'a head older than one already seen is accepted', [[' || h.at < minHeadAt', '']]],
  ['head-revocations-ignored', 'revocations carried by the head are not applied', [["    if (has(h.revoked, d.id) || has(h.revoked, b.subject)) return refuse('revoked')\n", '']]],
  ['revoke-by-id-only', 'revoking a subject key does not revoke its delegations', [[' || has(h.revoked, b.subject)', '']]],
  ['key-window-at-head-only', 'a retired witness key\'s heads are accepted', [['  const until = (now > b.at ? now : b.at) + 1', '  const until = b.at + 1']]],
  ['head-from-the-future', 'a head dated after now is accepted', [[' || h.at > now + cfg.skew', '']]],
  ['membership-unchecked', 'the delegation may name any membership', [["    if (!has(h.memberships, b.membership)) return refuse('membership')\n", '']]],
  ['authority-unchecked', 'any root of the identity may delegate', [["    if (!has(h.authority, b.root)) return refuse('authority')\n", '']]],
  ['identity-unchecked', 'a head of another identity is accepted', [["    if (h.identity !== b.identity) return refuse('identity')\n", '']]],
  ['revocations-ignored', 'revoked delegations are accepted', [["    for (let i = 0; i < n; i++) if (revoked[i] === d.id) return refuse('revoked')\n", '']]],
  ['audience-unchecked', 'a delegation for another relying party is accepted', [["    if (b.aud !== cfg.audience) return refuse('audience')\n", '']]],
  ['scope-unchecked', 'any scope is granted', [["    if (!has(b.scopes, scope)) return refuse('scope')\n", '']]],
  ['head-unsigned', 'the head\'s signature is not checked', [['  if (!isWitnessSig(r.sig) || witnessReason(r.sig, r.payload, cfg.keys, b.at, until) !== undefined) return undefined\n', '']]],
]

function run (implPath) {
  const { NODE_TEST_CONTEXT, ...env } = process.env
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['--test', '--test-reporter=tap', ...SUITE], {
      env: { ...env, MUID_VERIFIER_IMPL: implPath ?? '', FC_RUNS: '100' },
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
const dir = mkdtempSync(join(tmpdir(), 'muid-verifier-twins-'))

function generate (name, edits) {
  let text = source
  for (const [find, replace] of [...IMPORTS, ...edits]) {
    const n = text.split(find).length - 1
    assert.equal(n, 1, `twin ${name}: target must occur exactly once in src/verifier.js, found ${n}: ${JSON.stringify(find)}`)
    text = text.replace(find, () => replace)
  }
  const path = join(dir, `${name}.js`)
  writeFileSync(path, text)
  return path
}

test('verifier broken twins', { timeout: 600_000 }, async (t) => {
  try {
    await t.test('control: an unmodified copy, run from outside the repository, passes', async () => {
      const r = await run(generate('control', []))
      assert.equal(r.code, 0, `control: exit ${r.code}, ${r.fail} failing`)
      assert.ok(r.pass > 10, `control: only ${r.pass} tests ran`)
    })

    const jobs = TWINS.map(([name, why, edits]) => [name, why, generate(name, edits)])
    assert.equal(jobs.length, 13, 'twin count')
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
