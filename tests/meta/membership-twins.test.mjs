// SPEC R8 and TESTING.md §6: the membership suite must fail against every broken twin, and pass against the real
// module run through the same harness. Twins are generated from src/membership.js by one targeted change each.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, writeFileSync, mkdtempSync, rmSync, readdirSync } from 'node:fs'
import { spawn } from 'node:child_process'
import { tmpdir, availableParallelism } from 'node:os'
import { join } from 'node:path'

// A test that never ends under a twin fails (the twin is caught) instead of holding the harness open.
const TEST_TIMEOUT = 300_000

const SRC = new URL('../../src/membership.js', import.meta.url)
const SUITE_DIR = new URL('../membership/', import.meta.url).pathname
const SUITE = readdirSync(SUITE_DIR).filter((f) => f.endsWith('.test.mjs')).map((f) => join(SUITE_DIR, f))

// A twin lives outside the repository, so its imports are made absolute.
const absolute = (m) => new URL('../../src/' + m + '.js', import.meta.url).href
const IMPORTS = [...['envelope', 'assertion', 'ed25519', 'root', 'attestation', 'bytes'].map((m) => ["from './" + m + ".js'", "from '" + absolute(m) + "'"]),
  ["from '@noble/hashes/sha2.js'", "from '" + import.meta.resolve('@noble/hashes/sha2.js') + "'"]]

// [name, bug class, [find, replace] pairs]
const TWINS = [
  ['head-length-reread', "a head's revoked list has its length read at every step", [['  for (let i = 0; i < n; i++) {\n    const x = revoked[i]', '  for (let i = 0; i < revoked.length; i++) {\n    const x = revoked[i]']]],
  ['half-is-majority', 'exactly half of the previous roots can change membership', [['  if (2 * yes <= cur.roots.length) return false', '  if (2 * yes < cur.roots.length) return false']]],
  ['added-roots-unsigned', 'a root can be added without its own signature', [['    if (!has(cur.roots, r) && p.signers[r] !== true) return false', '    if (false) return false']]],
  ['witness-window-ignored', 'anchors and settlements are accepted whatever the witness key\'s window', [['ctx.keys, r.body.at, r.body.at + 1)', 'ctx.keys, 0, 0)']]],
  ['contest-without-majority', 'any one root can end the identity with a contest', [['        if (2 * yes > cur.roots.length) return accept({ dead: true })', '        if (yes > 0) return accept({ dead: true })']]],
  ['pending-full-authority', 'new roots have authority before settlement', [['if (!pending || has(cur.roots, m.roots[i])) authority', 'if (true) authority']]],
  ['freeze-lifted-at-anchor', 'a freeze on the settled membership stops applying once a successor is anchored', [['frozenBy(m) || frozenBy(cur)', 'frozenBy(m)']]],
  ['settlements-ignored', 'settlements are not followed', [['    const outcomes = r.settled[cur.id]', '    const outcomes = undefined']]],
  ['rival-chosen', 'of two anchored rivals the first is taken', [['    if (candidates.length > 1) return accept({ dead: true })\n', '']]],
  ['revoked-cap-after-loop', 'a long revocation list is read in full before the cap applies', [['    if (list.length > MAX_REVOKED) return undefined\n  }\n', '  }\n  if (list.length > MAX_REVOKED) return undefined\n']]],
  ['head-epoch-pending', 'a head carries the pending epoch as if it were settled', [['epoch: state.pending ? state.epoch - 1 : state.epoch', 'epoch: state.epoch']]],
  ['assertion-unchecked', 'root signatures are not verified', [['  if (!a.ok) return undefined\n  counted[', '  counted[']]],
  // R11
  ['recovery-unmatured', 'a recovery is taken as a membership without the witness having said it matured', [['  if (matured && recoveryOf(cur, p)) return true', '  if (recoveryOf(cur, p)) return true']]],
  ['recovery-below-threshold', 'one party is enough whatever the threshold', [['  if (seen.length < cur.recovery.threshold) return false', '  if (seen.length < 1) return false']]],
  ['recovery-by-a-root', "a root named as its own membership's party recovers it alone", [['root !== undefined && !has(cur.roots, root) && !has(seen, root)', 'root !== undefined && !has(seen, root)']]],
  ['party-counted-twice', 'a party committed to twice counts twice', [['root !== undefined && !has(cur.roots, root) && !has(seen, root)', 'root !== undefined && !has(cur.roots, root)']]],
  ['recovery-adds-unsigned', 'a recovery adds a root that did not sign it', [['  if (seen.length < cur.recovery.threshold) return false\n  return addedSigned(cur, p)', '  if (seen.length < cur.recovery.threshold) return false\n  return true']]],
  ['recovery-undesignated', 'any root with a salt recovers a membership that designated nobody', [['    const root = p.opened[parties[i]]', '    const root = p.opened[parties[i]] ?? p.openedBy'], ['    if (m.salt !== undefined) memberships[m.id].opened[', '    if (m.salt !== undefined) memberships[m.id].openedBy = m.signer\n    if (m.salt !== undefined) memberships[m.id].opened[']]],
  ['commitment-domain', 'the commitment is made under another domain', [["encode('muid-recovery\\n')", "encode('muid-recoverx\\n')"]]],
  ['commitment-without-salt', 'the commitment leaves out the salt', [['  bytes.set(fromHex(salt), PARTY.length + 32)\n', '']]],
  ['plain-hides-salted', "a root's plain signature on a record keeps its salted one from being counted", [['  const once = r.id + r.sig.root + salt', '  const once = r.id + r.sig.root']]],
  ['salt-any-text', 'a salt that is no id is taken', [['(salt !== undefined && !isId(salt))', 'false']]],
  ['salted-contest', 'a salt is allowed in the signature of any record type', [['  const salt = party ? r.sig.salt : undefined', '  const salt = r.sig.salt']]],
  ['designation-inherited', 'a successor that names no designation keeps its predecessor\'s', [['roots: p.body.roots, recovery: p.body.recovery })', 'roots: p.body.roots, recovery: p.body.recovery ?? cur.recovery })']]],
  ['designation-four-parties', 'a designation may name four parties', [['parties.length > MAX_PARTIES', 'parties.length > MAX_PARTIES + 1']]],
  ['designation-unsorted', 'a designation may repeat a party or list them in any order', [['    if (!isId(parties[i]) || (i > 0 && !(parties[i - 1] < parties[i]))) return false', '    if (!isId(parties[i])) return false']]],
  ['designation-threshold-minority', 'one party of several is a threshold', [['2 * threshold > parties.length && threshold <= parties.length', 'threshold >= 1 && threshold <= parties.length']]],
  ['designation-threshold-zero', 'with one party, a threshold of zero is allowed', [['2 * threshold > parties.length && threshold <= parties.length', '2 * threshold >= parties.length - 1 && threshold <= parties.length']]],
  ['designation-threshold-above', 'a threshold above the number of parties is allowed', [['2 * threshold > parties.length && threshold <= parties.length', '2 * threshold > parties.length']]],
  ['designation-short-window', 'a window shorter than three days is allowed', [['window >= MIN_RECOVERY_WINDOW && ', '']]],
  ['designation-long-window', 'a window longer than ninety days is allowed', [[' && window <= MAX_RECOVERY_WINDOW', '']]],
  ['designation-extra-keys', 'a designation may carry other keys', [["!onlyKeys(x, ['parties', 'threshold', 'window'])", 'false']]],
  ['notice-after-cancel', 'a cancelled recovery is still shown as under notice', [["r.cancelled[n.record] === true || ", '']]],
  ['notice-of-anchored', 'an anchored recovery is still shown as under notice', [[" || r.anchored[n.record] === true) continue", ') continue']]],
  ['notice-of-any-prev', 'a notice of a record that does not follow the settled membership is shown', [["p === undefined || p.body.prev !== cur.id || ", 'p === undefined || ']]],
  ['notice-of-unheld', 'a notice of a record that is not held is shown', [["    if (p === undefined || p.body.prev !== cur.id || ", '    if (p !== undefined && p.body.prev !== cur.id || ']]],
  ['notice-earliest', 'of several notices the earliest is shown', [['n.at < notice.at || (n.at === notice.at', 'n.at > notice.at || (n.at === notice.at']]],
  ['notice-tie-greatest', 'of two notices at one time the greater id is shown', [['n.record >= notice.record', 'n.record <= notice.record']]],
  ['notice-unsigned-time', "a notice's key window is not checked: any list is read as notices", [["stated('cancelled', 'cancelled', (s)", "stated('cancelled', 'notice', (s)"]]],
  ['matured-is-notice', 'a notice is read as the statement that a recovery matured', [["stated('matured', 'matured', (s)", "stated('matured', 'notice', (s)"]]],
  ['head-without-notice', 'a head leaves out the recovery under notice', [["  if (typeof state.recovering === 'object' && state.recovering !== null) body.recovering = state.recovering\n", '']]],
  ['head-notice-undefined', 'a head of a state made without the field carries an undefined one', [["  if (typeof state.recovering === 'object' && state.recovering !== null) body.recovering", '  if (state.recovering !== null) body.recovering']]],
]

// Runs the suite against an implementation. With `untilCaught`, the run is stopped as soon as one test has passed
// and one has failed: the twin is caught, and the suite ran normally (a twin that cannot be loaded passes nothing).
// The suite runs in a process group of its own, so that stopping it stops every file's process.
function run (implPath, untilCaught = false) {
  const { NODE_TEST_CONTEXT, ...env } = process.env
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['--test', '--test-reporter=tap', `--test-timeout=${TEST_TIMEOUT}`, ...SUITE], {
      env: { ...env, MUID_MEMBERSHIP_IMPL: implPath ?? '', FC_RUNS: '60' },
      stdio: ['ignore', 'pipe', 'pipe'],
      detached: true,
    })
    let out = ''
    let caught
    const results = (k) => (out.match(new RegExp(`^${k} \\d+ - `, 'gm')) ?? []).length // each test's own line; subtests are indented
    const seen = (d) => {
      out += d
      if (!untilCaught || caught !== undefined) return
      const now = { pass: results('ok'), fail: results('not ok') }
      if (now.pass > 0 && now.fail > 0) {
        caught = now
        try { process.kill(-child.pid, 'SIGKILL') } catch { /* already gone */ }
      }
    }
    child.stdout.on('data', seen)
    child.stderr.on('data', seen)
    child.on('close', (code) => {
      const count = (k) => Number((out.match(new RegExp(`^# ${k} (\\d+)`, 'm')) ?? [])[1] ?? NaN)
      resolve(caught !== undefined ? { code: 1, ...caught } : { code, pass: count('pass'), fail: count('fail') })
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

test('membership broken twins', { timeout: 1_800_000 }, async (t) => {
  try {
    await t.test('control: an unmodified copy, run from outside the repository, passes', async () => {
      const r = await run(generate('control', []))
      assert.equal(r.code, 0, `control: exit ${r.code}, ${r.fail} failing`)
      assert.ok(r.pass > 10, `control: only ${r.pass} tests ran`)
    })

    const jobs = TWINS.map(([name, why, edits]) => [name, why, generate(name, edits)])
    assert.equal(jobs.length, 42, 'twin count')
    const results = []
    const queue = [...jobs]
    const workers = Math.max(1, Math.floor(availableParallelism() / 4))
    await Promise.all(Array.from({ length: workers }, async () => {
      for (let job = queue.shift(); job; job = queue.shift()) {
        const [name, why, path] = job
        results.push([name, why, await run(path, true)])
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
