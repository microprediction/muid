// The witness suite must fail against every broken twin of witness/, and pass against the real witness run through
// the same harness. Each twin is a copy of witness/ with one targeted change.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, writeFileSync, mkdtempSync, mkdirSync, rmSync, readdirSync } from 'node:fs'
import { spawn } from 'node:child_process'
import { tmpdir, availableParallelism } from 'node:os'
import { join } from 'node:path'

const DIR = new URL('../../witness/', import.meta.url)
const FILES = ['witness.js', 'service.js', 'log.js']
const SUITE_DIR = new URL('../witness/', import.meta.url).pathname
const SUITE = readdirSync(SUITE_DIR).filter((f) => f.endsWith('.test.mjs')).map((f) => join(SUITE_DIR, f))
// The witness's imports of the core, made absolute because a twin lives outside the repository.
const CORE = ["from '../" + 'src/', "from '" + new URL('../../src/', import.meta.url).href]
// And its one package import, resolved from here.
const NOBLE = ["from '@noble/hashes/sha2.js'", `from '${import.meta.resolve('@noble/hashes/sha2.js')}'`]

// [name, bug class, [find, replace] pairs, file (witness.js unless named)]
const TWINS = [
  ['rival-admitted', 'a record whose prev is not the effective membership is held (R3)', [["    if (b.prev !== s.membership) return refuse('prev')\n", '']]],
  ['epoch-unchecked', 'a membership record of another epoch is held', [["    if (b.epoch !== s.epoch + 1) return refuse('epoch')\n", '']]],
  ['added-root-early', "an added root's signature is held before a majority signed", [['2 * signersOf(held, r.id, s.roots) > s.roots.length', 'true']]],
  ['contest-by-pending-roots', 'a contest signed by a root of the pending record is held', [['      roots = rootsOf(held, s.settled)\n', '      roots = s.roots\n']]],
  ['freeze-any-membership', 'a freeze of a membership outside the state is held', [["      if (b.membership !== s.settled && b.membership !== s.membership) return refuse('membership')\n", '']]],
  ['signature-unchecked', "a root's signature is not verified on admission", [["return refuse('root-missing')\n    if (!checkRootAssertion(r.sig.assertion, { record: r.id, rpId, origin, key: k }).ok) return refuse('signature')\n", "return refuse('root-missing')\n"]]],
  ['revocation-signature-unchecked', "a root's revocation is not verified", [["const k = rootKeys(held).get(r.sig.root)\n      if (!checkRootAssertion(r.sig.assertion, { record: r.id, rpId, origin, key: k }).ok) return refuse('signature')\n", 'const k = rootKeys(held).get(r.sig.root)\n']]],
  ['kept-before-logged', 'a holding is kept without its outbox, before the log has taken what it signed', [['return { entry: { ...e, outbox: { entry: s.entry, texts: s.texts } }, value: { staged: s.value } }', 'return { entry: s.entry, value: { staged: s.value } }']], 'service.js'],
  ['unserialised', 'changes to one identity interleave, so one is lost', [['(queues.get(identity) ?? Promise.resolve())', 'Promise.resolve()']], 'service.js'],
  ['head-kept-after-change', 'a head signed before a change is served after it', [['return texts.length === 0 ? { entry: { held: a.held }, value } : { entry: { held: a.held }, texts, value }', 'return texts.length === 0 ? { entry: { held: a.held, head: entry?.head }, value } : { entry: { held: a.held, head: entry?.head }, texts, value }']], 'service.js'],
  ['head-kept-for-ever', 'a head is reused however old', [['now - entry.head.at < headInterval', 'true']], 'service.js'],
  ['head-unlogged', 'a head is served that the log did not take', [['texts: [text], value: json(200, { head: text })', 'value: json(200, { head: text })']], 'service.js'],
  ['body-unbounded', 'a request body of any size is read', [["    if (text === undefined) return { error: refusal(413, 'too-large') }\n", '']], 'service.js'],
  ['type-unfiltered', 'a type that may not be submitted reaches the witness', [["      if (!SUBMITTED.includes(b.type)) return refusal(422, 'type')\n", '']], 'service.js'],
  ['log-split-halves', 'a tree is split in halves, not at the largest power of two below its size', [['  let k = 1\n  while (k * 2 < n) k *= 2\n  return k', '  return Math.floor(n / 2)']], 'log.js'],
  ['log-no-full-fallback', 'a partial tile no longer served is not read from its full tile', [['(await get(`${path}.p/${width}`)) ?? (await get(path))', '(await get(`${path}.p/${width}`))']], 'log.js'],
  ['log-short-tile', 'a tile shorter than its width is used', [["        if (b.length < width * 32) throw new Error(`log tile short: ${path}`)\n", '']], 'log.js'],
  ['log-index-unprefixed', 'tile indices without the x prefix', [["(i < groups.length - 1 ? 'x' + g : g)", 'g']], 'log.js'],
  ['log-append-any-body', 'whatever the log answers is taken as an index', [['if (!res.ok || !/^(?:0|[1-9][0-9]*)$/.test(body))', 'if (!res.ok)']], 'log.js'],
  ['log-proof-order', 'the proof lists the sibling before the path below it', [['[...await path(m, a, a + k), await mth(a + k, b)]', '[await mth(a + k, b), ...await path(m, a, a + k)]']], 'log.js'],
  ['envelopes-per-signer', 'every envelope of one record by one root is held', [["    if (held[list].some((t) => { const x = open(t, type); return x.id === r.id && x.sig.root === signer })) return accept({ held })\n", '']]],
  ['proposals-accumulate', "a root's later proposal is held beside its earlier one", [["held.memberships.filter((t) => !mine(open(t, 'membership')))", 'held.memberships']]],
  ['replaced-roots-kept', 'root records a replaced proposal named stay held', [['memberships, roots: rootsNamed(held, memberships), replaced })', 'memberships, replaced })']]],
  ['w0-pending-unchecked', "a successor's assertion may cover the pending record's contest", [[' || has(covers, contestOf(held.identity, b.prev))', '']]],
  ['w0-successor-unchecked', "a contest's assertion may cover a successor of the record it contests", [[" || held.memberships.some((t) => { const x = open(t, 'membership'); return x.body.prev === b.record && has(covers, x.id) })", '']]],
  ['covers-unchecked', 'one assertion may propose a change and contest it', [["    if (shared) return refuse('covers')\n", '']]],
  ['revocation-by-retired-root', "a delegation from a root without authority serves a self-revocation", [['return has(s.authority, d.root) && d.identity', 'return d.identity']]],
  ['outbox-skipped', 'records signed before a lost log answer are not appended again first', [['    if (entry?.outbox === undefined) return entry\n    await append(entry.outbox.texts)\n', '    if (entry?.outbox === undefined) return entry\n']], 'service.js'],
  ['body-read-in-full', 'the body is read in full before its size is checked', [['    n += r.value.length\n    if (n > max) {', '    n += r.value.length\n    if (false) {']], 'service.js'],
  ['self-revocation-unsigned', "a delegate's revocation of itself is not verified", [["      if (!checkEd25519(r.sig.signature, signedBytes(r.payload), b.target).ok) return refuse('signature')\n", '']]],
  ['no-cap', 'a list grows past MAX_RECORDS', [["    if (held[list].length >= MAX_RECORDS) return refuse('full')\n", '']]],
  ['root-unnamed', 'any root record is held', [["      return refuse('root-unnamed')", '      return accept({ held: add(held, \'roots\', text) })']]],
  ['dead-admits', 'records are held for a dead identity', [["return s.dead ? refuse('dead') : s", 'return s']]],
  ['identity-unchecked', "another identity's record is held", [["    if (b.identity !== held.identity) return refuse('identity')\n", '']]],
  ['shape-unchecked', 'a record of the wrong form is held', [["    if (!SHAPES[type](b) || !onlyKeys(r.sig, ['assertion', 'root'])) return refuse('shape')\n", '']]],
  ['anchor-unchecked', 'a successor is anchored without verifiers following it', [['if (stateOf(add(own, \'anchors\', text)).membership === x)', 'if (true)']]],
  ['settle-early', 'the epoch is settled before the window has passed', [['if (now < at + contestWindow) {', 'if (now < at) {']]],
  ['contest-ignored', 'a contest inside the window is never anchored', [['        if (contest === undefined || contested) break\n', '        break\n']]],
  ['contest-unchecked', 'a contest is anchored whatever its signers', [['        if (!stateOf(add(held, \'anchors\', text)).dead) break\n', '']]],
  ['settle-ignores-contest', 'an anchored contest does not make the settlement contested', [["outcome: contested ? 'contested' : s.membership", 'outcome: s.membership']]],
  ['own-view-with-contests', "the witness's view counts contest anchors, so a contested epoch never settles", [['anchors: held.anchors.filter((t, i) => !isContest(anchors[i]))', 'anchors: held.anchors']]],
  ['one-step', 'a held successor waits for the next step after a settlement', [['      sign1(\'settlement\', text) // a contested', '      sign1(\'settlement\', text); break // a contested']]],
  ['sign-unchecked', "a signature not under the witness's key is published", [["    if (!checkEd25519(signature, signedBytes(payload), key).ok) throw new Error('sign gave no valid signature under the witness key')\n", '']]],
  ['head-without-revocations', 'the head leaves out the revocations held', [['headOf(s, now, kept(held, now).map((x) => x.target))', 'headOf(s, now, [])']]],
  ['revoke-without-authority', 'any root of the identity can revoke', [["      if (!has(s.authority, r.sig.root)) return refuse('signer')\n", '']]],
  ['self-revoke-any-key', 'a key revokes itself without the delegation that makes it a delegate', [["      if (!delegates(held, s, delegation, now, b.target)) return refuse('delegation')\n", '']]],
  ['revocation-never-lapses', "a revocation outlives the delegation it names, given with it", [['(x) => x.until === null || now < x.until)', '() => true)']]],
  ['revocation-lapses-late', 'a lapsed revocation is carried at its expiry plus skew', [['(x) => x.until === null || now < x.until)', '(x) => x.until === null || now <= x.until)']]],
  ['revocation-any-delegation', 'any delegation sets when a revocation lapses', [["      if (d === undefined || d.id !== b.target) return refuse('delegation')\n", "      if (d === undefined) return refuse('delegation')\n"]]],
  ['revocation-duplicates', 'another revocation for a target already held adds an entry', [['    if (live.some((x) => x.target === b.target)) return accept({ held })\n', '']]],
  ['tombstone-ignored', 'a replaced proposal can be resubmitted and made current again', [["    if (tombs.some((x) => x.record === r.id && x.signer === signer)) return refuse('replaced')\n", '']]],
  ['tombstones-unbounded', 'a root may replace its proposals without limit', [["    if (tombs.filter((x) => x.signer === signer).length >= TOMBSTONES) return refuse('quota')\n", '']]],
  ['tombstones-kept-for-ever', 'tombstones of an earlier prev are kept', [['const tombs = held.replaced.filter((x) => x.prev === b.prev)', 'const tombs = held.replaced']]],
  ['quota-ignored', 'one root may file every revocation a head carries', [["    if (live.filter((x) => x.root === root).length >= QUOTA) return refuse('quota')\n", '']]],
  ['quota-shared', "a root's quota counts every root's entries", [['live.filter((x) => x.root === root).length >= QUOTA', 'live.length >= QUOTA']]],
  ['quota-self-uncounted', "a delegate's revocation of itself counts against no root", [['      root = named(delegation).body.root\n', '      root = undefined\n']]],
  ['losers-kept', 'proposals that lost a settled prev stay held', [["held = contested ? add(held, 'settlements', text) : purge(add(held, 'settlements', text), s.settled, s.membership)", "held = add(held, 'settlements', text)"]]],
  ['purge-winner', 'the settled record goes with the losers', [["return x.body.prev !== prev || x.id === outcome", 'return x.body.prev !== prev']]],
  ['revocations-past-head', 'live revocations may outnumber what a head carries', [['if (live.length >= MAX_REVOKED)', 'if (live.length >= MAX_RECORDS)']]],
]

function run (dir) {
  const { NODE_TEST_CONTEXT, ...env } = process.env
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['--test', '--test-reporter=tap', ...SUITE], {
      env: { ...env, MUID_WITNESS_DIR: dir, FC_RUNS: '30' },
      stdio: ['ignore', 'pipe', 'pipe'],
      detached: true, // its own process group, so that a hang is ended with every test process it started
    })
    // A twin that makes advance loop for ever is caught by the suite never finishing.
    const timer = setTimeout(() => process.kill(-child.pid, 'SIGKILL'), HANG)
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
const sources = Object.fromEntries(FILES.map((f) => [f, readFileSync(new URL(f, DIR), 'utf8')]))
const root = mkdtempSync(join(tmpdir(), 'muid-witness-twins-'))

function generate (name, edits, file = 'witness.js') {
  const dir = join(root, name)
  mkdirSync(dir)
  for (const f of FILES) {
    let text = sources[f].split(CORE[0]).join(CORE[1]).split(NOBLE[0]).join(NOBLE[1])
    for (const [find, replace] of f === file ? edits : []) {
      const n = text.split(find).length - 1
      assert.equal(n, 1, `twin ${name}: target must occur exactly once in witness/${f}, found ${n}: ${JSON.stringify(find)}`)
      text = text.replace(find, () => replace)
    }
    writeFileSync(join(dir, f), text)
  }
  return dir
}

test('witness broken twins', { timeout: 1_800_000 }, async (t) => {
  try {
    await t.test('control: an unmodified copy, run from outside the repository, passes', async () => {
      const r = await run(generate('control', []))
      assert.equal(r.code, 0, `control: exit ${r.code}, ${r.fail} failing${r.hung ? ', hung' : ''}`)
      assert.ok(r.pass >= 25, `control: only ${r.pass} tests ran`)
    })
    const jobs = TWINS.map(([name, why, edits, file]) => [name, why, generate(name, edits, file)])
    assert.equal(jobs.length, 59, 'twin count')
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
