// The witness suite must fail against every broken twin of witness/, and pass against the real witness run through
// the same harness. Each twin is a copy of witness/ with one targeted change.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, writeFileSync, mkdtempSync, mkdirSync, rmSync, readdirSync } from 'node:fs'
import { spawn } from 'node:child_process'
import { tmpdir, availableParallelism } from 'node:os'
import { part } from './shard.mjs'
import { join } from 'node:path'

// A test that never ends under a twin fails (the twin is caught) instead of holding the harness open.
const TEST_TIMEOUT = 300_000

const DIR = new URL('../../witness/', import.meta.url)
const FILES = ['witness.js', 'service.js', 'log.js', 'holdings.js']
const SUITE_DIR = new URL('../witness/', import.meta.url).pathname
const SUITE = readdirSync(SUITE_DIR).filter((f) => f.endsWith('.test.mjs')).map((f) => join(SUITE_DIR, f))
// The witness's imports of the core, made absolute because a twin lives outside the repository.
const CORE = ["from '../" + 'src/', "from '" + new URL('../../src/', import.meta.url).href]
// And its package imports, resolved from here.
const NOBLE = ['@noble/hashes/sha2.js', '@noble/curves/ed25519.js'].map((m) => [`from '${m}'`, `from '${import.meta.resolve(m)}'`])

// [name, bug class, [find, replace] pairs, file (witness.js unless named)]
const TWINS = [
  ['agent-retirement-ignored', "a revocation naming an agent's light identity id names nothing", [[' || x.target === l.agent', '']]],
  ['retired-agent-relogged', 'a new delegation under a retired name is logged', [['names(x, { delegation: r.id, subject: d.subject, agent })', 'names(x, { delegation: r.id, subject: d.subject })']]],
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
  ['noop-drops-head', 'a resubmission that changes nothing drops the cached head', [['      if (entry !== undefined && a.held === entry.held) return { value }\n', '']], 'service.js'],
  ['state-replayed', "a holding's state is replayed for every submission", [['    let s = states.get(held)\n', '    let s\n']], 'witness.js'],
  ['queues-kept', "every identity's queue is kept for ever", [['if (queues.get(identity) === tail) queues.delete(identity)', 'if (queues.get(identity) === tail) queues.get(identity)']], 'service.js'],
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
  ['outbox-ignored', 'a decision is made against the records held, whatever waits in the outbox', [['      const e = await settle(entry)\n', '      const e = entry === undefined ? undefined : { held: entry.held, head: entry.head }\n']], 'service.js'],
  ['logged-then-kept', 'what is signed is appended to the log and only then kept, with no outbox', [['      return { entry: { ...e, outbox: { entry: s.entry, texts: s.texts } }, value: { staged: s.value } }', '      await append(s.texts)\n      return { entry: s.entry, value: { done: s.value } }']], 'service.js'],
  ['answered-before-logged', 'a request is answered with what it signed before the log has taken it', [['    await holdings.update(identity, async (entry) => ({ entry: await settle(entry) }))\n    return r.staged', '    return r.staged']], 'service.js'],
  ['outbox-served', 'while an outbox waits, the records it would make are the ones served', [['      return { entry: { ...e, outbox: { entry: s.entry, texts: s.texts } }, value: { staged: s.value } }', '      return { entry: { ...s.entry, outbox: { entry: s.entry, texts: s.texts } }, value: { staged: s.value } }']], 'service.js'],
  ['body-read-in-full', 'the body is read in full before its size is checked', [['    n += r.value.length\n    if (n > max) {', '    n += r.value.length\n    if (false) {']], 'service.js'],
  ['self-revocation-unsigned', "a delegate's revocation of itself is not verified", [["      if (!checkEd25519(r.sig.signature, signedBytes(r.payload), b.target).ok) return refuse('signature')\n", '']]],
  ['no-cap', 'a list grows past MAX_RECORDS', [["    if (held[list].length >= MAX_RECORDS) return refuse('full')\n", '']]],
  ['root-unnamed', 'any root record is held', [["      return refuse('root-unnamed')", '      return accept({ held: add(held, \'roots\', text) })']]],
  ['dead-admits', 'records are held for a dead identity', [["return s.dead ? refuse('dead') : s", 'return s']]],
  ['identity-unchecked', "another identity's record is held", [["    if (b.identity !== held.identity) return refuse('identity')\n", '']]],
  ['shape-unchecked', 'a record of the wrong form is held', [["    if (!SHAPES[type](b) || !onlyKeys(r.sig, salted ? ['assertion', 'root', 'salt'] : ['assertion', 'root']) ||\n      (salted && !(isHex(ID, r.sig.salt) && isHex(ID, r.sig.root)))) return refuse('shape')\n", '']]],
  ['anchor-unchecked', 'a successor is anchored without verifiers following it', [['trialState(own, { identity: held.identity, record: x, at: now }).membership === x)', 'true)']]],
  ['settle-early', 'the epoch is settled before the window has passed', [['if (now < at + contestWindow) {', 'if (now < at) {']]],
  ['contest-ignored', 'a contest inside the window is never anchored', [['        if (contest === undefined || contested) break\n', '        break\n']]],
  ['contest-unchecked', 'a contest is anchored whatever its signers', [['        if (!trialState(held, { identity: held.identity, record: contest, at: now }).dead) break\n', '']]],
  ['settle-ignores-contest', 'an anchored contest does not make the settlement contested', [["outcome: contested ? 'contested' : s.membership", 'outcome: s.membership']]],
  ['own-view-with-contests', "the witness's view counts contest anchors, so a contested epoch never settles", [['anchors: held.anchors.filter((t, i) => !isContest(anchors[i]))', 'anchors: held.anchors']]],
  ['one-step', 'a held successor waits for the next step after a settlement', [['      sign1(\'settlement\', text) // a contested', '      sign1(\'settlement\', text); break // a contested']]],
  ['sign-unchecked', "a signature not under the witness's key is published", [["    if (!checkEd25519(signature, signedBytes(payload), key).ok) throw new Error('sign gave no valid signature under the witness key')\n", '']]],
  ['head-without-revocations', 'the head leaves out the revocations held', [['headOf(s, now, entries(held, s, now).map((x) => x.target))', 'headOf(s, now, [])']]],
  ['revoke-without-authority', 'any root of the identity can revoke', [["      if (!has(s.authority, r.sig.root)) return refuse('signer')\n", '']]],
  ['self-revoke-any-key', 'a key revokes itself without the delegation that makes it a delegate', [["      if (!delegates(held, s, delegation, now, b.target)) return refuse('delegation')\n", '']]],
  ['revocation-never-lapses', "a revocation outlives the delegation it names, given with it", [['(x) => x.until === null || now < x.until)', '() => true)']]],
  ['revocation-lapses-late', 'a lapsed revocation is carried at its expiry plus skew', [['(x) => x.until === null || now < x.until)', '(x) => x.until === null || now <= x.until)']]],
  ['revocation-any-delegation', 'any delegation sets when a revocation lapses', [["      if (d === undefined || d.id !== b.target) return refuse('delegation')\n", "      if (d === undefined) return refuse('delegation')\n"]]],
  ['revocation-duplicates', 'another revocation for a target already held adds an entry', [['    if (kept1.some((x) => x.target === b.target)) return accept({ held })\n', '']]],
  ['tombstone-ignored', 'a replaced proposal can be resubmitted and made current again', [["    if (tombs.some((x) => x.record === r.id && x.signer === signer)) return refuse('replaced')\n", '']]],
  ['quorate-replaceable', 'a root may move its signature off a record a majority has signed', [["    if (gone.some((x) => quorate(x.id, 0, 0))) return refuse('quorate')\n", '']]],
  ['quota-blocks-majority', 'the quota refuses even the signature that completes a majority', [[" && !quorate(r.id, has(s.roots, signer) ? 1 : 0, salted ? 1 : 0)) return refuse('quota')", ") return refuse('quota')"]]],
  ['trial-signed', 'each candidate anchor is signed by the witness key, then thrown away if not kept', [["const found = ids.find((x) => trialState(own, { identity: held.identity, record: x, at: now }).membership === x)", "const found = ids.find((x) => stateOf(add(own, 'anchors', make('anchor', { identity: held.identity, record: x, at: now }))).membership === x)"]]],
  ['trial-contest-signed', 'a contest anchor is signed by the witness key before it is known to end the identity', [["if (!trialState(held, { identity: held.identity, record: contest, at: now }).dead) break", "if (!stateOf(add(held, 'anchors', make('anchor', { identity: held.identity, record: contest, at: now }))).dead) break"]]],
  ['trial-any-window', "the trial key is in window at any time, not the witness key's windows", [['.map((k) => freeze({ ...k, key: TRIAL_KEY }))', '.map((k) => freeze({ ...k, key: TRIAL_KEY, nbf: 0, exp: Number.MAX_SAFE_INTEGER }))']]],
  ['trial-key-pinnable', 'a configuration may pin the trial key', [[' || keys.some((k) => k.key === TRIAL_KEY)', '']]],
  ['tombstones-unbounded', 'a root may replace its proposals without limit', [["    if (tombs.filter((x) => x.signer === signer).length >= TOMBSTONES && !quorate(r.id, has(s.roots, signer) ? 1 : 0, salted ? 1 : 0)) return refuse('quota')\n", '']]],
  ['tombstones-kept-for-ever', 'tombstones of an earlier prev are kept', [['const tombs = held.replaced.filter((x) => x.prev === b.prev)', 'const tombs = held.replaced']]],
  ['bucket-ignored', 'a root may file revocations without limit', [["    if (tokens.tokens < 1) return refuse('quota')\n", '']]],
  ['per-root-shared', "a root's head entries count every root's", [['es.filter((x) => x.root === root).length >= PER_ROOT', 'es.length >= PER_ROOT']]],
  ['quota-self-uncounted', "a delegate's revocation of itself counts against no root", [['      root = named(delegation).body.root\n', '      root = undefined\n']]],
  ['losers-kept', 'proposals that lost a settled prev stay held', [["held = contested ? add(held, 'settlements', text) : purge(add(held, 'settlements', text), s.settled, s.membership)", "held = add(held, 'settlements', text)"]]],
  ['purge-winner', 'the settled record goes with the losers', [["return x.body.prev !== prev || x.id === outcome", 'return x.body.prev !== prev']]],
  ['head-cap-off', 'head entries may outnumber what a head carries', [['if (es.length >= MAX_REVOKED ||', 'if (']]],
  ['head-all-kept', 'the head carries every kept revocation, logged or not', [['headOf(s, now, entries(held, s, now).map((x) => x.target))', 'headOf(s, now, kept(held, now).map((x) => x.target))']]],
  ['log-revoked', 'a revoked delegation is logged', [["    if (kept(held, now).some((x) => names(x, { delegation: r.id, subject: d.subject, agent }))) return refuse('revoked')\n", '']]],
  ['log-by-id-only', 'a delegation whose subject key is revoked is logged', [['names(x, { delegation: r.id, subject: d.subject, agent })', 'x.target === r.id || x.target === agent']]],
  ['log-any-membership', 'a delegation under a membership not current is logged', [["    if (d.membership !== s.settled && d.membership !== s.membership) return refuse('membership')\n", '']]],
  ['log-any-root', 'a delegation from a root without authority is logged', [["    if (!has(s.authority, d.root)) return refuse('authority')\n", "    if (!rootKeys(held).has(d.root)) return refuse('authority')\n"]]],
  ['log-unverified', 'a delegation is logged without being verified at now', [['    if (!c.ok) return c\n', '']]],
  ['log-twice', 'a delegation already logged is signed again', [['    if (known !== undefined) return accept({ held, logged: known.text, fresh: false })\n', '']]],
  ['live-past-expiry', 'a logged delegation counts as live after it expires', [['held.logged.filter((l) => now < l.exp + skew &&', 'held.logged.filter((l) =>']]],
  ['live-without-authority', "a logged delegation counts as live after its root loses authority", [['    has(s.authority, l.root))', '    true)']]],
  ['live-any-membership', 'a logged delegation counts as live under a membership no longer current', [['now < l.exp + skew && (l.membership === s.settled || l.membership === s.membership) &&', 'now < l.exp + skew &&']]],
  ['bucket-unrefilled', 'a bucket never refills', [['const days = Math.max(0, Math.floor((now - b.at) / DAY))', 'const days = 0']]],
  ['bucket-unbounded', 'a bucket saves up without limit', [['tokens: Math.min(BURST, b.tokens + days)', 'tokens: b.tokens + days']]],
  ['bucket-backwards', 'a clock that steps back refills the bucket', [['Math.max(0, Math.floor((now - b.at) / DAY))', 'Math.abs(Math.floor((now - b.at) / DAY))']]],
  // R11
  ['party-any-root', 'any root with a salt signs as a recovery party', [[' || !has(s.recovery.parties, recoveryCommitment(signer, r.sig.salt))) return refuse', ') return refuse']]],
  ['party-while-pending', 'a party signs a successor of a pending record', [['        if (s.pending || s.recovery === null || has(s.roots, signer)', '        if (s.recovery === null || has(s.roots, signer)']]],
  ['party-is-root', "a root named as its own membership's party signs as one", [['s.recovery === null || has(s.roots, signer) || ', 's.recovery === null || ']]],
  ['party-root-unchecked', "another key's root record is held for a party", [["          if (!p.ok || p.id !== signer) return refuse('root-record')", "          if (!p.ok) return refuse('root-record')"]]],
  ['added-before-threshold', 'a root a recovery adds signs before the parties have', [[' || recovers(r.id, 0)) ? [signer] : s.roots', ' || s.recovery !== null) ? [signer] : s.roots']]],
  ['salt-on-any-type', 'a contest or freeze signed with a salt is admitted', [["    const salted = type === 'membership' && hasOwn(r.sig, 'salt')", "    const salted = hasOwn(r.sig, 'salt')"]]],
  ['shape-any-membership', "a membership record out of the core's form is held", [['  membership: isMembership,', '  membership: () => true,']]],
  ['cancel-any-record', 'a cancel of a record that is not under notice is admitted', [["      if (s.recovering === null || b.record !== s.recovering.record) return refuse('record')", "      if (s.recovering === null) return refuse('record')"]]],
  ['cancel-by-anyone', 'anyone with a held root record cancels a recovery', [["return accept({ held })\n      roots = rootsOf(held, s.settled)", 'return accept({ held })\n      roots = [signer]']]],
  ['cancel-twice', 'a second cancel of one recovery is held too', [["      if (held.cancels.some((t) => open(t, 'cancel').body.record === b.record)) return accept({ held })\n", '']]],
  ['cancel-ignored', 'a held cancel does not end the recovery', [["          if (held.cancels.some((t) => open(t, 'cancel').body.record === under.record)) state1('cancelled', under.record)\n          else if (now", '          if (now']]],
  ['matures-before-cancel', 'a recovery whose window has passed matures though a cancel is held', [["          if (held.cancels.some((t) => open(t, 'cancel').body.record === under.record)) state1('cancelled', under.record)\n          else if (now >= under.at + s.recovery.window) state1('matured', under.record)", "          if (now >= under.at + s.recovery.window) state1('matured', under.record)\n          else if (held.cancels.some((t) => open(t, 'cancel').body.record === under.record)) state1('cancelled', under.record)"]]],
  ['matures-at-once', 'a recovery matures the moment it is noticed', [['now >= under.at + s.recovery.window', 'now >= under.at']]],
  ['matures-a-second-late', 'a recovery matures a second after its window', [['now >= under.at + s.recovery.window', 'now > under.at + s.recovery.window']]],
  ['notice-unchecked', 'any held successor signed by a party is put under notice', [["        const fresh = ids.filter((x) => !said(held, 'notices', 'notice', x) &&\n          trialState(own, { identity: held.identity, record: x, at: now }, true).membership === x).sort()[0]", "        const fresh = ids.filter((x) => !said(held, 'notices', 'notice', x) && partiesOf(held, x) > 0).sort()[0]"]]],
  ['notice-again', 'a cancelled recovery is put under notice again', [["ids.filter((x) => !said(held, 'notices', 'notice', x) &&", 'ids.filter((x) =>']]],
  ['no-cooling-off', 'another recovery is put under notice at once after a cancel', [[' || now < last + COOLING_OFF) break', ') break']]],
  ['cooling-off-a-second-short', 'the cooling-off ends a second early', [['now < last + COOLING_OFF', 'now < last + COOLING_OFF - 1']]],
  ['notices-unbounded', 'notices are given past the list that holds them', [['        if (held.notices.length >= MAX_RECORDS || now', '        if (now']]],
  ['party-withdraws', 'a party takes its signature from a recovery under notice', [[' > s.roots.length || recovers(id, parties)', ' > s.roots.length']]],
  ['held-to-a-cancelled-recovery', 'a party is held to a recovery that was cancelled', [[" && !said(held, 'cancelled', 'cancelled', id)", '']]],
  ['purge-keeps-notices', 'notices of a settled prev are kept', [['cancels: none, notices: none, matured,', 'cancels: none, matured,']]],
  ['purge-drops-matured', "the outcome's maturity is dropped at settlement, so the state cannot be replayed", [['notices: none, matured, cancelled:', 'notices: none, matured: none, cancelled:']]],
  ['purge-drops-cancelled', 'the last cancellation is dropped at a settlement, and the cooling-off with it', [['cancelled: freeze(held.cancelled.slice(-1))', 'cancelled: none']]],
  ['party-root-dropped', "a party's root record is dropped while its signature is held", [[" || (hasOwn(m.sig, 'salt') && m.sig.root === id) })", ' })']]],
  ['key-window-unchecked', 'the witness signs at a time outside its key\'s window', [["    if (!keys.some((k) => k.key === key && k.nbf <= body.at && body.at < k.exp)) throw new Error('the witness key is outside its window at the time it would sign')\n", '']]],
  ['key-window-a-second-long', "the witness signs at the second its key's window ends", [['k.nbf <= body.at && body.at < k.exp', 'k.nbf <= body.at && body.at <= k.exp']]],
  ['dead-advanced', 'a dead identity is looked at for recoveries', [['        if (!s.ok || s.dead) break\n', '']]],
  ['service-cancel-refused', 'the service takes no cancel', [["const SUBMITTED = ['root', 'membership', 'contest', 'freeze', 'cancel']", "const SUBMITTED = ['root', 'membership', 'contest', 'freeze']"]], 'service.js'],
  ['service-root-dropped', "the service does not pass on a party's root record", [['witness.admit(held, b.type, b.text, b.root)', 'witness.admit(held, b.type, b.text)']], 'service.js'],
  ['service-root-any-value', "a party's root record that is no text is passed on", [[" || (b.root !== undefined && typeof b.root !== 'string')) return refusal(400, 'request')", ") return refusal(400, 'request')"]], 'service.js'],
  ['service-notices-unserved', 'the records served leave out notices', [["'settlements', 'notices', 'cancelled', 'matured']", "'settlements', 'cancelled', 'matured']"]], 'service.js'],
  ['holdings-shared', 'a second process may open the holdings file while the first has it', [['PRAGMA locking_mode = EXCLUSIVE; PRAGMA synchronous = FULL', 'PRAGMA synchronous = FULL']], 'holdings.js'],
  ['holdings-unread-is-absent', "a stored holding that is not its identity's is taken for no holding, and written over", [["throw new Error('a stored holding is not its identity\\'s')", 'return undefined']], 'holdings.js'],
  ['holdings-held-unsaved', 'an entry is held in memory before it is written, so one that cannot be written is served', [['          upsert.run(identity, JSON.stringify(r.entry))\n          hold(identity, r.entry)\n', '          hold(identity, r.entry)\n          upsert.run(identity, JSON.stringify(r.entry))\n']], 'holdings.js'],
  ['holdings-memory-only', 'an entry is held in memory and never written to the file', [['          upsert.run(identity, JSON.stringify(r.entry))\n', '']], 'holdings.js'],
  ['holdings-first-entry-only', "an identity's first entry is written and no later one", [['DO UPDATE SET entry = excluded.entry', 'DO NOTHING']], 'holdings.js'],
  ['holdings-cache-unbounded', 'every entry ever read or kept stays in memory', [['    if (held.size > cache) held.delete(held.keys().next().value)\n', '']], 'holdings.js'],
  ['holdings-any-format', 'a file of another format is opened as holdings', [['} else if (version !== FORMAT) {', '} else if (version === -1) {']], 'holdings.js'],
  ['holdings-closed-answers', 'a closed store goes on answering from memory', [['      held.clear()\n', '']], 'holdings.js'],
  ['holdings-not-journalled', 'a file that cannot be journalled ahead of its writes is used all the same', [["!== 'wal') throw", "=== 'never') throw"]], 'holdings.js'],
]

function run (dir) {
  const { NODE_TEST_CONTEXT, ...env } = process.env
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['--test', '--test-reporter=tap', `--test-timeout=${TEST_TIMEOUT}`, ...SUITE], {
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
    let text = NOBLE.reduce((t, [from, to]) => t.split(from).join(to), sources[f].split(CORE[0]).join(CORE[1]))
    for (const [find, replace] of f === file ? edits : []) {
      const n = text.split(find).length - 1
      assert.equal(n, 1, `twin ${name}: target must occur exactly once in witness/${f}, found ${n}: ${JSON.stringify(find)}`)
      text = text.replace(find, () => replace)
    }
    writeFileSync(join(dir, f), text)
  }
  return dir
}

// Ninety minutes: at 83 twins, one at a time on a CI runner of four cores, a nightly run was cut off at thirty with
// none reported. The suite starts no browser, so twins run on half the cores.
test('witness broken twins', { timeout: 5_400_000 }, async (t) => {
  try {
    await t.test('control: an unmodified copy, run from outside the repository, passes', async () => {
      const r = await run(generate('control', []))
      assert.equal(r.code, 0, `control: exit ${r.code}, ${r.fail} failing${r.hung ? ', hung' : ''}`)
      assert.ok(r.pass >= 25, `control: only ${r.pass} tests ran`)
    })
    const jobs = TWINS.map(([name, why, edits, file]) => [name, why, generate(name, edits, file)])
    assert.equal(jobs.length, 128, 'twin count')
    const results = []
    const queue = part(jobs)
    assert.ok(queue.length > 0, 'this part has twins')
    const workers = Math.max(1, Math.floor(availableParallelism() / 2))
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
