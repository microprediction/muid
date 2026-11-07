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
const IMPORTS = ['envelope', 'ed25519', 'root', 'delegation', 'attestation', 'origin', 'bytes'].map((m) => ["from './" + m + ".js'", "from '" + absolute(m) + "'"])

// [name, bug class, [find, replace] pairs]
const TWINS = [
  ['no-staleness', 'a head of any age is accepted', [['h.at < now - cfg.maxStaleness || ', '']]],
  ['min-head-at-ignored', 'a head older than one already seen is accepted', [[' || h.at < minHeadAt', '']]],
  ['head-revocations-ignored', 'revocations carried by the head are not applied', [["    if (has(h.revoked, d.id) || has(h.revoked, b.subject)) return refuse('revoked')\n", '']]],
  ['revoke-by-id-only', 'revoking a subject key does not revoke its delegations', [[' || has(h.revoked, b.subject)', '']]],
  ['equivocation-unchecked', 'a head inconsistent with the last one accepted is accepted', [["    if (last && forked(last, h)) return refuse(h.at === last.at && !forked(h, last) ? 'stale' : 'equivocation')\n", '']]],
  ['same-second-as-evidence', 'two honest heads of one second, shown in reverse, are called equivocation', [["h.at === last.at && !forked(h, last) ? 'stale' : 'equivocation'", "'equivocation'"]]],
  ['epoch-may-fall', 'a lower settled epoch is accepted', [['if (h.epoch < l.epoch || h.epoch', 'if (h.epoch']]],
  ['top-epoch-unchecked', 'a pending successor may vanish', [[' || h.epoch + hm.length < l.epoch + lm.length', '']]],
  ['ids-unbound', 'ids are not tied to epochs: another settled or pending membership is accepted', [['if ((l.epoch + i === h.epoch + j) !== (lm[i] === hm[j])) return true', 'if (false) return true']]],
  ['ids-same-epoch-only', 'one membership at two epochs is accepted', [['(l.epoch + i === h.epoch + j) !== (lm[i] === hm[j])', 'l.epoch + i === h.epoch + j && lm[i] !== hm[j]']]],
  ['authority-unchecked-same-epoch', 'authority may change while the memberships stand', [['  if (h.epoch === l.epoch) return within(h.authority, l.authority) || (hm.length === lm.length && within(l.authority, h.authority))\n', '  if (h.epoch === l.epoch) return false\n']]],
  ['authority-may-grow', 'authority may grow while the memberships stand or a successor turns pending', [['within(h.authority, l.authority) || (hm.length === lm.length && within(l.authority, h.authority))', 'hm.length === lm.length && within(l.authority, h.authority)']]],
  ['authority-may-shrink-at-settlement', 'authority may shrink when the pending successor settles', [['hm.length === 1 && within(l.authority, h.authority)', 'hm.length === 1 && false']]],
  ['epoch-zero', 'a head of epoch 0 is accepted', [['(isTime(b.epoch) && b.epoch > 0 && b.epoch', '(isTime(b.epoch) && b.epoch']]],
  ['epoch-unbounded', 'an epoch near 2^53 rounds in the equivocation check', [[' && b.epoch < 2 ** 32)', ')']]],
  ['identity-as-pending', 'the identity id is accepted as a pending successor, reviving epoch 1', [[' || b.memberships[1] === b.identity) return', ') return']]],
  ['older-than-last-accepted', 'a head older than the last one accepted is accepted', [[' || (last && h.at < last.at)', '']]],
  ['last-identity-unchecked', 'a last head of another identity is compared as if it were this one\'s', [["    if (last && last.identity !== h.identity) return refuse('identity')\n", '']]],
  ['last-head-at-now', 'the last head must still be in its key\'s window now, so key rotation breaks callers', [['headBody(lastHead, cfg, undefined)', 'headBody(lastHead, cfg, now)']]],
  ['last-head-unverified', 'a last head that is not a pinned head is ignored', [[' ||\n    (lastHead !== undefined && last === undefined)', '']]],
  ['epoch-form-unchecked', 'a head whose epoch disagrees with its memberships is accepted', [['(b.epoch === 1) !== (b.memberships[0] === b.identity) || ', '']]],
  ['until-inclusive', 'a store that drops the claim id at until lets it replay once', [['until: b.at + cfg.maxClaimAge + 1 })', 'until: b.at + cfg.maxClaimAge })']]],
  ['claim-time-unchecked', 'a claim of any age is accepted', [['b.at < c.now - cfg.maxClaimAge || b.at > c.now + cfg.skew || ', '']]],
  ['claim-delegation-unchecked', 'a claim may name any delegation', [["    if (b.delegation !== d.id) return refuse('claim-delegation')\n", '']]],
  ['claim-unsigned', 'the claim\'s signature is not checked', [['    if (!s.ok) return s\n', '']]],
  ['claim-scope-unchecked', 'a claim for one scope is accepted where another is needed', [["    if (b.scope !== c.scope) return refuse('claim-scope')\n", '']]],
  ['claim-method-unchecked', 'a claim for one method is accepted for another', [["    if (b.htm !== c.method) return refuse('claim-method')\n", '']]],
  ['claim-url-unchecked', 'a claim for one URL is accepted for another', [["    if (htuOrigin(b.htu) !== cfg.audience || b.htu !== c.url) return refuse('claim-url')\n", '']]],
  ['claim-url-any-origin', "a claim for another origin's URL is accepted where that origin is passed", [['htuOrigin(b.htu) !== cfg.audience || ', '']]],
  ['claim-url-with-query', 'the query is kept in the URL a claim must match', [['apply(exec, BEFORE_QUERY, [url])[0]', 'url']]],
  ['claim-nonce-unchecked', 'a claim without the issued nonce is accepted', [["    if (b.nonce !== c.nonce) return refuse('claim-nonce')\n", '']]],
  ['claim-digest-unchecked', 'a claim for another body is accepted', [["    if (b.content_digest !== c.contentDigest) return refuse('claim-digest')\n", '']]],
  ['claim-htu-any-form', 'an htu outside the grammar is accepted', [['return m !== null && isCanonicalOrigin(m[1]) ? m[1] : undefined', 'return typeof x === \'string\' ? x.split(\'/\').slice(0, 3).join(\'/\') : undefined']]],
  ['claim-keys-any', 'a claim with keys of its own is accepted', [["    for (const k in b) if (!has(CLAIM_KEYS, k)) return refuse('claim-shape')\n", '']]],
  ['claim-outside-delegation', 'a claim dated outside its delegation\'s window is accepted', [[' || b.at < d.body.nbf - cfg.skew ||\n      b.at >= d.body.exp', '']]],
  ['call-revoked-by-id-only', 'a subject key in the call\'s revoked list is ignored', [[' || revoked[i] === b.subject', '']]],
  ['key-window-at-head-only', 'a retired witness key\'s heads are accepted', [['  const until = (now > b.at ? now : b.at) + 1', '  const until = b.at + 1']]],
  ['key-window-from-head-only', 'a key not yet valid now is accepted for a head dated within skew', [['  const from = now < b.at ? now : b.at', '  const from = b.at']]],
  ['head-from-the-future', 'a head dated after now is accepted', [[' || h.at > now + cfg.skew', '']]],
  ['revoked-length-trusted', "a revoked list's length is trusted, so a Proxy reporting Infinity is read forever", [['  if (!(isSafeInteger(n) && n >= 0 && n < 2 ** 32)) return undefined\n', '']]],
  ['membership-unchecked', 'the delegation may name any membership', [["    if (!has(h.memberships, b.membership)) return refuse('membership')\n", '']]],
  ['authority-unchecked', 'any root of the identity may delegate', [["    if (!has(h.authority, b.root)) return refuse('authority')\n", '']]],
  ['identity-unchecked', 'a head of another identity is accepted', [["    if (h.identity !== b.identity) return refuse('identity')\n", '']]],
  ['revocations-ignored', 'revoked delegations are accepted', [["    for (let i = 0; i < n; i++) if (revoked[i] === d.id || revoked[i] === b.subject) return refuse('revoked')\n", '']]],
  ['audience-unchecked', 'a delegation for another relying party is accepted', [["    if (b.aud !== cfg.audience) return refuse('audience')\n", '']]],
  ['scope-unchecked', 'any scope is granted', [["    if (!has(b.scopes, scope)) return refuse('scope')\n", '']]],
  ['head-unsigned', 'the head\'s signature is not checked', [['  if (!isWitnessSig(r.sig) || witnessReason(r.sig, r.payload, cfg.keys, from, until) !== undefined) return undefined\n', '']]],
  ['logged-unchecked', 'a delegation is accepted without its logged record', [["    if (l === undefined || l.identity !== b.identity || l.delegation !== d.id) return refuse('logged')\n", '']]],
  ['logged-any-delegation', "another delegation's logged record is accepted", [['l.identity !== b.identity || l.delegation !== d.id)', 'l.identity !== b.identity)']]],
  ['logged-any-identity', "another identity's logged record is accepted", [['l === undefined || l.identity !== b.identity ||', 'l === undefined ||']]],
  ['logged-form-unchecked', "a logged record's body is used before its form is checked", [["  if (r === undefined || !isId(r.body.identity) || !isId(r.body.delegation) || !isTime(r.body.at)) return undefined\n  if (", '  if (r === undefined || ']]],
  ['logged-unsigned', 'a logged record is accepted without its signature checked', [['  if (!isWitnessSig(r.sig) || witnessReason(r.sig, r.payload, cfg.keys, r.body.at, r.body.at + 1) !== undefined) return undefined\n', '']]],
  ['logged-any-time', "a logged record is accepted whatever its time against the key's window", [['witnessReason(r.sig, r.payload, cfg.keys, r.body.at, r.body.at + 1)', 'witnessReason(r.sig, r.payload, cfg.keys, 0, 1)']]],
  ['logged-any-type', 'a head is accepted as a logged record', [["shaped(text, 'logged', LOGGED_KEYS)", "shaped(text, 'head', LOGGED_KEYS)"]]],
  ['same-second-revocation-dropped', 'a head of the same second may drop a revocation the last head carried', [['  if (h.at === l.at && within(l.revoked, h.revoked)) return true\n', '']]],
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
    assert.equal(jobs.length, 55, 'twin count')
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
