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

// A test that never ends under a twin fails (the twin is caught) instead of holding the harness open.
const TEST_TIMEOUT = 300_000

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
  ['rename-keeps-review', 'renaming the agent leaves the reviewed delegation signable', [["for (const id of ['agent', 'subject',", "for (const id of ['subject',"]], 'page.js'],
  ['agent-not-shown', 'the agent is signed but not shown in the review (I4)', [["    $('show-agent').textContent = d.body.agent\n", '']], 'page.js'],
  ['edit-keeps-review', 'an edit leaves the reviewed delegation signable', [["for (const id of ['agent', 'subject', 'aud', 'scopes', 'days', 'new-root', 'cosign-payload']) $(id).addEventListener('input', withdraw)", "for (const id of ['new-root', 'cosign-payload']) $(id).addEventListener('input', withdraw)"]], 'page.js'],
  ['late-signature-kept', 'a signature that returns after an edit is handed over', [['    if (pending.delegation !== d || changedElsewhere()) return // withdrawn', '    if (changedElsewhere()) return // withdrawn']], 'page.js'],
  ['uv-preferred', 'the assertion does not require user verification', [["rpId, challenge: challenge(covers), userVerification: 'required',", "rpId, challenge: challenge(covers), userVerification: 'preferred',"]], 'page.js'],
  ['any-passkey', 'any passkey for the site may sign', [["    allowCredentials: [{ type: 'public-key', id: fromB64u(root.credential) }],\n", '']], 'page.js'],
  ['not-discoverable', 'the passkey is not a resident credential', [["residentKey: 'required', userVerification: 'required'", "userVerification: 'required'"]], 'page.js'],
  ['cosign-anything', 'a change that does not add this passkey is co-signed', [["    if (!c.body.roots.includes(root.id)) throw new Error('that change does not add this passkey')\n", '']], 'page.js'],
  ['add-edit-keeps-review', 'an edit of the new root leaves the change signable', [["for (const id of ['agent', 'subject', 'aud', 'scopes', 'days', 'new-root', 'cosign-payload'])", "for (const id of ['agent', 'subject', 'aud', 'scopes', 'days', 'cosign-payload'])"]], 'page.js'],
  ['authority-unchecked', 'a passkey without authority yet signs delegations', [["  if (!s.authority.includes(root.id)) throw new Error('this passkey has no authority yet: wait for the change to settle')\n", '']], 'page.js'],
  ['membership-of-epoch-1', 'delegations name the first membership whatever the current one', [['  return s.membership\n', '  return root.identity\n']], 'page.js'],
  ['root-unregistered', 'a new identity is not registered with the witness', [["    await submit(root.identity, 'root', root.text)\n", '']], 'page.js'],
  ['added-root-unsubmitted', "the added root's record is not given to the witness", [["    await submit(root.identity, 'root', c.rootText)\n", '']], 'page.js'],
  ['change-while-pending', 'a change is proposed while another is pending', [["  if (state.pending) throw new Error('a change is already pending: wait for it to settle')\n", '']], 'records.js'],
  ['roots-unsorted', "the change's roots are not sorted", [['roots: [...state.roots, r.id].sort() }', 'roots: [...state.roots, r.id] }']], 'records.js'],
  ['inline-script-allowed', "the CSP allows any inline script", [["script-src 'self' 'sha256-", "script-src 'self' 'unsafe-inline' 'sha256-"]], 'index.html'],
  ['hidden-shown', 'hidden parts of the page are displayed', [['[hidden] { display: none !important; }\n', '']], 'page.css'],
  ['pending-forgotten', 'a root is kept as registered before the witness has it', [['joining, registered: false }', 'joining, registered: true }']], 'page.js'],
  ['no-retry-on-load', 'a pending registration is not retried when the page loads', [['  if (unregistered()) register()\n', '\n']], 'page.js'],
  ['fingerprint-not-shown', 'the joining device shows no fingerprint to compare', [["    $('join-fingerprint').textContent = fingerprint(root.id)\n", '']], 'page.js'],
  ['fingerprint-unchecked', 'the adding device shows no fingerprint of the root it signs in', [["    $('add-fingerprint').textContent = fingerprint(c.added)\n", '']], 'page.js'],
  ['stored-any-form', 'whatever storage holds is taken as the root', [['  const r = checkRoot(x.text, { rpId })\n  if (!r.ok) return null\n', '  return x\n']], 'records.js'],
  ['stored-id-trusted', "a stored root's id is taken from storage, not its record", [['  return { ...x, id: r.id }\n', '  return x\n']], 'records.js'],
  ['create-over-stored', 'a create in a stale tab overwrites the stored identity', [['  if (now !== null) { root = now; show(); return }\n', '']], 'page.js'],
  ['tabs-not-followed', 'what another tab stores is not followed', [["  if (e.key === KEY || e.key === WORKERS || e.key === null) { root = load(); workers = loadWorkers(); withdraw(); show() }\n", '']], 'page.js'],
  ['framed-acts', 'framed, the page still offers its actions', [['const FRAMED = window.top !== window.self', 'const FRAMED = false']], 'page.js'],
  ['origin-unchecked', 'served under another origin, the page still acts', [['  : location.origin !== ORIGIN ?', '  : false ?']], 'page.js'],
  ['cosign-not-kept', 'a co-signature is sent without being kept, so a lost answer loses it', [["    root = { ...root, cosigned: rootSigned(c.payload, root.id, a) }\n    save()\n", "    root = { ...root, cosigned: rootSigned(c.payload, root.id, a) }\n"]], 'page.js'],
  ['cosign-no-retry-on-load', 'a kept co-signature is not sent again when the page loads', [['  if (root?.cosigned !== undefined) cosign()\n', '\n']], 'page.js'],
  ['outbox-sent-framed', 'framed, the page still sends what it kept', [['if (REFUSAL === undefined) {\n', 'if (true) {\n']], 'page.js'],
  ['storage-any-key', 'a change to any key of the origin withdraws what is open', [['if (e.key === KEY || e.key === WORKERS || e.key === null) {', 'if (true) {']], 'page.js'],
  ['cosign-kept-after', 'a co-signature the witness took stays in the outbox', [['    const { cosigned, ...rest } = root\n', '    const rest = root\n']], 'page.js'],
  ['cosigned-trusted', 'a stored co-signature is sent whatever it is', [["  if (x.cosigned !== undefined && (x.joining !== true || cosignedIdentity(x.cosigned, r.id) === undefined)) return null\n", '']], 'records.js'],
  ['renew-unbounded', 'more than eight workers are put under one assertion', [['  if (workers.length < 1 || workers.length > MAX_BATCH) throw', '  if (workers.length < 1) throw']], 'records.js'],
  ['renew-covers-unsorted', "a renewal's covers are in the order listed", [['  const covers = delegations.map((d) => d.id).sort()\n', '  const covers = delegations.map((d) => d.id)\n']], 'records.js'],
  ['workers-any-form', 'whatever storage holds is taken as a worker', [['    const w = workerOf(e)\n', '    const w = e ?? undefined\n']], 'records.js'],
  ['renew-selection-keeps-review', 'a change of selection leaves the reviewed renewal signable', [["else unticked.add(slot(w)); withdraw() })", "else unticked.add(slot(w)) })"]], 'page.js'],
  ['renew-late-signature-kept', 'a renewal signed after a change of selection is handed over', [['    if (pending.renewal !== r || changedElsewhere()) return // withdrawn', '    if (changedElsewhere()) return // withdrawn']], 'page.js'],
  ['renew-unticked', 'a worker that was unticked is renewed', [['    const chosen = workers.filter((w) => !unticked.has(slot(w)))\n', '    const chosen = workers\n']], 'page.js'],
  ['review-wait-keeps', 'a review edited while the witness is asked is shown all the same', [["    if (asked !== withdrawals) return // withdrawn while the witness was asked\n    const d = delegation(", "    const d = delegation("]], 'page.js'],
  ['renew-wait-keeps', 'a renewal changed while the witness is asked is shown all the same', [["    if (asked !== withdrawals) return // withdrawn while the witness was asked\n    const r = renewals(", "    const r = renewals("]], 'page.js'],
  ['withdrawals-uncounted', 'a withdrawal is not counted, so a waiting review goes on', [['  withdrawals++\n', '']], 'page.js'],
  ['reticked', 'a list drawn again ticks what was unticked', [['  for (const s of unticked) if (!listed.has(s)) unticked.delete(s)\n', '  unticked.clear()\n']], 'page.js'],
  ['untick-outlives-entry', 'a forgotten worker authorised again comes back unticked', [['  for (const s of unticked) if (!listed.has(s)) unticked.delete(s)\n', '']], 'page.js'],
  ['stored-key-unchecked', 'a stored worker whose key is not a key is kept', [[' || !checkEd25519Key(x.subject).ok) return undefined', ') return undefined']], 'records.js'],
  ['workers-change-keeps-review', "another tab's change of the workers leaves a review signable", [['workers = loadWorkers(); withdraw(); show() }', 'workers = loadWorkers(); if (e.key !== WORKERS) withdraw(); show() }']], 'page.js'],
  ['renew-partly-shown', 'a renewal signs delegations it does not show (I4)', [["    $('renew-list').replaceChildren(...r.delegations.map((d) =>", "    $('renew-list').replaceChildren(...r.delegations.slice(0, 1).map((d) =>"]], 'page.js'],
  ['renew-partly-signed', 'the assertion does not cover every renewed delegation', [['    const a = await sign(r.covers)\n', '    const a = await sign([r.covers[0]])\n']], 'page.js'],
  ['renew-unauthorised', 'a passkey still joining is offered workers to renew', [["  $('renew').hidden = root === null || joining || workers.length === 0\n", "  $('renew').hidden = root === null || workers.length === 0\n"]], 'page.js'],
  ['worker-not-remembered', 'an authorised worker is not kept for renewal', [["  try { localStorage.setItem(WORKERS, JSON.stringify(next)) } catch { /* said below */ }\n", '']], 'page.js'],
  ['stale-list-written', "a tab not yet told of another's change writes its own list over it", [['  const next = change(loadWorkers())\n', '  const next = change(workers)\n']], 'page.js'],
  ['unsaved-unsaid', 'a change that could not be saved is shown as made', [['  workers = loadWorkers()\n  show()\n  if (JSON.stringify(workers) !== JSON.stringify(next)) fail(', '  workers = next\n  show()\n  if (false) fail(']], 'page.js'],
  ['stale-review-signed', 'a worker reviewed before another tab changed the workers is signed', [['  if (d === null || changedElsewhere()) return\n', '  if (d === null) return\n']], 'page.js'],
  ['stale-renewal-signed', 'a renewal reviewed before another tab changed the workers is signed', [['  if (r === null || changedElsewhere()) return\n', '  if (r === null) return\n']], 'page.js'],
  ['change-while-signing-kept', 'a worker signed while another tab changed the workers is handed over', [['    if (pending.delegation !== d || changedElsewhere()) return // withdrawn', '    if (pending.delegation !== d) return // withdrawn']], 'page.js'],
  ['renew-change-while-signing-kept', 'a renewal signed while another tab changed the workers is handed over', [['    if (pending.renewal !== r || changedElsewhere()) return // withdrawn', '    if (pending.renewal !== r) return // withdrawn']], 'page.js'],
  ['add-wait-keeps', "a new passkey's review edited while the witness is asked is shown all the same", [["    if (asked !== withdrawals) return // withdrawn while the witness was asked\n    const c = addRoot(", "    const c = addRoot("]], 'page.js'],
  ['late-refusal-shown', "a refusal of a worker's review already withdrawn is shown", [["    $('review-panel').hidden = false\n  } catch (e) { if (asked === withdrawals) fail(e) }", "    $('review-panel').hidden = false\n  } catch (e) { fail(e) }"]], 'page.js'],
  ['renew-late-refusal-shown', "a refusal of a renewal already withdrawn is shown", [["    $('renew-panel').hidden = false\n  } catch (e) { if (asked === withdrawals) fail(e) }", "    $('renew-panel').hidden = false\n  } catch (e) { fail(e) }"]], 'page.js'],
  ['add-late-refusal-shown', "a refusal of a new passkey's review already withdrawn is shown", [["    $('add-panel').hidden = false\n  } catch (e) { if (asked === withdrawals) fail(e) }", "    $('add-panel').hidden = false\n  } catch (e) { fail(e) }"]], 'page.js'],
  ['forget-keeps', 'a forgotten worker stays listed', [['keepWorkers((list) => list.filter((x) => x.agent !== w.agent || x.aud !== w.aud))', 'keepWorkers((list) => list)']], 'page.js'],
  ['forget-every-audience', "forgetting a worker at one audience forgets it at the others", [['list.filter((x) => x.agent !== w.agent || x.aud !== w.aud)', 'list.filter((x) => x.agent !== w.agent)']], 'page.js'],
  ['old-key-renewable', "an agent's replaced key stays remembered for renewal (issue #70)", [['(old.subject !== worker.subject || old.aud === worker.aud)', '(old.subject === worker.subject && old.aud === worker.aud)']], 'records.js'],
  ['old-key-elsewhere', "an agent's replaced key stays remembered at its other audiences", [['(old.subject !== worker.subject || old.aud === worker.aud)', 'old.aud === worker.aud']], 'records.js'],
  ['two-keys-renewed', 'a renewal signs one agent under two keys', [["  if (workers.some((w) => workers.some((v) => v.agent === w.agent && v.subject !== w.subject))) throw new Error('an agent is listed with two keys')\n", '']], 'records.js'],
  ['retires-unsaid', 'a review does not say that it replaces a remembered key', [["    $('show-retires').textContent = old.length === 0 ? '' : `", "    $('show-retires').textContent = true ? '' : `"]], 'page.js'],
  ['retires-left-over', 'a review says a key is replaced when none is', [["    $('show-retires').textContent = old.length === 0 ? '' : `", "    if (old.length > 0) $('show-retires').textContent = `"]], 'page.js'],
  ['registered-not-saved', 'a registration that succeeded is not saved, so it is sent again', [['    root = { ...root, registered: true }\n    save()\n', '    root = { ...root, registered: true }\n']], 'page.js'],
]

function run (dir) {
  const { NODE_TEST_CONTEXT, ...env } = process.env
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['--test', '--test-reporter=tap', `--test-timeout=${TEST_TIMEOUT}`, '--test-force-exit', ...SUITE], { env: { ...env, MUID_ID_DIR: dir, MUID_FAIL_FAST: '1' }, stdio: ['ignore', 'pipe', 'pipe'] })
    let out = ''
    // A suite that never ends is reported as one that did not run normally, rather than holding up every other twin.
    const stop = setTimeout(() => child.kill('SIGKILL'), 900_000)
    child.stdout.on('data', (d) => { out += d })
    child.stderr.on('data', (d) => { out += d })
    child.on('close', (code) => {
      clearTimeout(stop)
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

test('id page broken twins', { timeout: 3_600_000 }, async (t) => {
  try {
    await t.test('control: an unmodified copy, run from outside the repository, passes', async () => {
      const r = await run(generate('control', [], null))
      assert.equal(r.code, 0, `control: exit ${r.code}, ${r.fail} failing`)
      assert.ok(r.pass >= 14, `control: only ${r.pass} tests ran`)
    })
    const jobs = TWINS.map(([name, why, edits, file]) => [name, why, generate(name, edits, file)])
    assert.equal(jobs.length, 74, 'twin count')
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
