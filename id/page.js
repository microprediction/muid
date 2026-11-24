// The id page (SPEC §8): create an identity with a passkey and register its root with the witness; add a passkey on
// another device (a membership change, R1: signed here, co-signed there); and authorise a worker's key by one
// assertion, under the identity's current membership. Every record the passkey signs is shown first from its exact
// payload (I4); changing any input withdraws it, and a signature that returns after an edit is discarded. The root
// record and the credential id are kept in this browser only. The workers it authorised are remembered here too, so
// that one assertion renews up to eight of them at once (decision 3).
import { openStore } from './store.js'
import { rootRecord, challenge, assertion, delegations, handOff, readRequest, audiencesOf, answer, opened, firstRootIdentities, secretInput, prfOutput, sealSecret, b64u, fromB64u, currentMembership, addRoot, rootSigned, changeToSign, fingerprint, storedRoot, cosignedIdentity, storedWorkers, remember, retired, renewals, cancel, maturesAt, withheld, rootsOf, card, kept, newSalt, fromCard, majority, possessionId, shows, designate, undesignate, designated, recoveryChange, MAX_SALTS, recovery, rescue, partySigned } from './records.js'

const $ = (id) => document.getElementById(id)
const meta = (name) => document.querySelector(`meta[name="${name}"]`).content
// SPEC §8: the rp ID and the exact origin are deployment configuration, compared exactly. Served under any other
// origin (a hosting platform's default domain, an alias), the page would make roots for the wrong rp ID: it does nothing.
const rpId = meta('muid-rp-id')
const ORIGIN = meta('muid-origin')
const KEY = 'root'
const WORKERS = 'workers'
const WITNESS = meta('muid-witness')
const WITNESS_KEYS = JSON.parse(meta('muid-witness-keys'))
// A value no one could have signed before: 32 random bytes, in hex.
const freshValue = () => Array.from(crypto.getRandomValues(new Uint8Array(32)), (x) => x.toString(16).padStart(2, '0')).join('')
// The code a recovery party's passkey signs to show it is held now (issue #247): fresh on each load and after each
// check, so that what was signed before, for the designation or an earlier check, shows nothing of now.
let recheckCode = freshValue()

// SPEC §7: what the page keeps (the root with its credential id, and the remembered workers) it keeps through the
// storage adapter alone. Every change is one transaction there, made to what storage holds at that moment, so no tab
// writes back a value another tab has since replaced. What is read back is untrusted: anything on the origin may
// have written it. The page's own copies are never ahead of storage: a change that was not saved is not shown as made.
let store
let root = null
// Stryker disable next-line ArrayDeclaration: equivalent; read from storage before anything is listed
let workers = []
const text = (held) => JSON.stringify({ rev: revOf(held), workers: workersOf(held) })
const rootOf = (held) => held.absent ? null : storedRoot(held.value, rpId)
// The workers are stored as { rev, workers }: `rev` is one more with every change, so that the list a review was
// made against is told apart from an equal list reached by later changes (a key replaced and then put back).
const workersOf = (held) => storedWorkers(held.absent ? null : held.value?.workers)
const revOf = (held) => Number.isSafeInteger(held.value?.rev) ? held.value.rev : 0
// `seen` is the workers as this tab last read them, as read (what is stored may not be JSON at all): a change since.
let seen
// The tab's copy of the workers is brought to what storage holds. Whatever the tab has open was reviewed against
// the copy as it was: if the copy changes, that is withdrawn, unless the open review's own saving made the change.
function adopt (held, own) {
  if (text(held) !== seen && !own) withdraw()
  seen = text(held)
  workers = workersOf(held)
}
async function refresh () {
  root = rootOf(await store.get(KEY))
  // Stryker disable next-line BooleanLiteral: equivalent; nothing is open when this runs at load, a notice withdraws
  // whatever it finds, and a saving that failed was a Forget's, which withdrew when pressed
  adopt(await store.get(WORKERS), false)
}
// Stryker disable next-line ObjectLiteral: nothing shown differs; without the nulls a signing button (hidden) pressed
// before any review throws where it would return, and does nothing either way
// SPEC §8: an application's request, from the fragment the person arrived with, or null. It fills the form once the
// page has an identity to authorise with, and is answered when the worker it names is authorised.
let request = null
let unread
try {
  request = readRequest(location.hash)
} catch (e) { unread = e }
let filled = false
let reviewed = false
// The sign-in view: for one arriving with a request, what it asks and one button, until they ask for more.
let full = false
const pending = { delegation: null, change: null, cosign: null, renewal: null, designation: null, recoveryCosign: null, proof: null, recover: null, rescue: null }

// A change to the stored root, made only while storage holds the root it was decided for (`mine`, for the identity
// it was then held for: null when one is being created): another's root, or this one held for another identity, is
// adopted, never overwritten, and what was shown for the one before is withdrawn, as a notice of it would have it
// withdrawn. Whether the change was made.
async function keepRoot (mine, change) {
  // Stryker disable next-line BooleanLiteral: equivalent; set by every update that returns
  let made = false
  const held = await store.update(KEY, (now) => {
    const r = rootOf(now)
    made = same(r, mine)
    return made ? { value: change(r) } : undefined
  })
  root = rootOf(held)
  if (!made) withdraw()
  show()
  return made
}

// A change to the remembered workers, made to what storage holds at that moment. Given `reviewed` (the workers as
// they were when the user reviewed what this change follows from), it is made only if storage still holds exactly
// that. 'saved'; or 'changed' (another tab changed them: this one is brought up to date, with nothing left to sign);
// or 'unsaved' (the browser could not keep it: said, and the list stays as storage holds it). `open()` says
// whether the review this change follows from is still the one open, when the change has been made.
async function keepWorkers (change, reviewed, open) {
  let outcome = 'saved'
  try {
    const held = await store.update(WORKERS, (now) => {
      if (reviewed !== undefined && text(now) !== reviewed) { outcome = 'changed'; return undefined }
      return { value: { rev: revOf(now) + 1, workers: change(workersOf(now)) } }
    })
    adopt(held, outcome === 'saved' && reviewed !== undefined && open())
  } catch {
    outcome = 'unsaved'
    await refresh()
  }
  show()
  if (outcome === 'changed') fail(new Error('The remembered workers were changed in another tab: review again.'))
  if (outcome === 'unsaved') fail(new Error('This browser could not save the change to the remembered workers: they are listed as it holds them.'))
  return outcome
}

const element = (tag, ...children) => {
  const e = document.createElement(tag)
  e.append(...children)
  return e
}
// A delegation's fields, from the body of the exact payload to be signed (I4).
const fields = (b) => [['Agent', b.agent], ['Audience', b.aud], ['Scopes', b.scopes.join(' ')], ['Expires', new Date(b.exp * 1000).toISOString()],
  ['Worker key', b.subject]]

// A remembered worker's place in the list: its agent at its audience. Those the user unticked, for as long as they
// are listed, are not renewed.
// R11: a designation as a membership change states it (I4): how many of its parties recover, after how long, and
// which parties, by their commitments' fingerprints, so that two designations of other parties never read alike
// (issue #147). A change that states none ends the one in force.
const DAY = 86_400
const wait = (s) => s % DAY === 0 ? `${s / DAY} days` : `${s} seconds`
// Roots listed by id, or none.
const listed = (ids) => ids.length === 0 ? 'none' : ids.join(' ')
const designation = (r) => r === undefined || r === null ? 'none' : `${r.threshold} of ${r.parties.length}, after ${wait(r.window)}; parties ${r.parties.map(fingerprint).join(', ')}`
const when = (t) => new Date(t * 1000).toISOString()
const slot = (w) => JSON.stringify([w.agent, w.aud])
const unticked = new Set()
// The remembered workers, each selected for renewal until unticked, with a button to forget it. Stored text is shown
// as text only.
function listWorkers () {
  const listed = new Set(workers.map(slot))
  for (const s of unticked) if (!listed.has(s)) unticked.delete(s)
  $('workers').replaceChildren(...workers.map((w) => {
    const box = element('input')
    box.type = 'checkbox'
    box.checked = !unticked.has(slot(w))
    box.addEventListener('change', () => { if (box.checked) unticked.delete(slot(w)); else unticked.add(slot(w)); withdraw() })
    const forget = element('button', 'Forget')
    forget.type = 'button'
    forget.addEventListener('click', () => { withdraw(); keepWorkers((list) => list.filter((x) => x.agent !== w.agent || x.aud !== w.aud || x.subject !== w.subject)) })
    return element('li', element('label', box, ` ${w.agent} at ${w.aud}: ${w.scopes.join(' ')} `, element('code', w.subject)), forget)
  }))
}

// SPEC §8: root registration and every root-signed action happen in a top-level window. The deployment's headers
// refuse framing; framed anyway, the page shows nothing to act on.
const FRAMED = window.top !== window.self
let REFUSAL = FRAMED ? 'This page acts only in its own window: open it directly.'
  : location.origin !== ORIGIN ? `This page acts only at ${ORIGIN}: open it there.` : undefined

function show () {
  if (REFUSAL !== undefined) {
    $('error').textContent = REFUSAL
    return
  }
  const joining = root?.joining === true
  $('create').hidden = root !== null
  $('joining').hidden = !joining
  $('identity').hidden = root === null || joining
  $('add-root').hidden = root === null || joining
  $('authorise').hidden = root === null || joining
  $('recovery').hidden = root === null || joining
  $('party').hidden = root === null || joining
  $('renew').hidden = root === null || joining || workers.length === 0
  listWorkers()
  $('pending').hidden = !unregistered()
  $('request-waiting').hidden = request === null // inside the creation section, shown only with no root
  $('request').hidden = request === null || root === null || joining
  if (!$('request').hidden && !filled) {
    filled = true
    $('request-from').textContent = request.from
    $('agent').value = request.agent
    $('subject').value = request.subject
    $('aud').value = audiencesOf(request).join(' ')
    $('scopes').value = request.scopes.join(' ')
    $('days').value = String(request.days)
  }
  // And reviewed at once, when the witness knows the identity: nothing in the form was typed by the person, so
  // there is nothing for them to finish before they are shown what would be signed.
  if (filled && !reviewed && full && !$('request').hidden && root.registered === true) {
    reviewed = true
    review()
  }
  $('request-unread').hidden = unread === undefined
  $('secret-ask').hidden = request?.sealTo === undefined || root?.joining === true
  $('request-secret').hidden = request?.sealTo === undefined
  if (request?.sealTo !== undefined) $('secret-host').textContent = new URL(request.from).host
  // R11: the recovery under notice, as the witness's records last gave it for the root now held (only a root of its
  // own identity is asked about: not none, and not one that is joining).
  const under = isFor(noticed) ? noticed.state : null
  $('recovery-notice').hidden = under === null
  $('notice-unchecked').hidden = !isFor(unchecked) || joining
  // The designation in force and the membership a party's check is made over, as the witness last gave them.
  const now = isFor(known) ? known.state : null
  $('recovery-now').textContent = now === null ? 'not known' : designation(now.recovery)
  $('recheck-code').textContent = now === null ? '' : recheckCode
  if (under !== null) {
    $('notice-at').textContent = when(under.recovering.at)
    $('notice-matures').textContent = when(maturesAt(under))
    $('notice-record').textContent = under.recovering.record
    // Only a root the identity has now cancels: the passkey a recovery would make its own is told what it waits for.
    const own = under.roots.includes(root.id)
    $('notice-own').hidden = !own
    $('notice-incoming').hidden = own
  }
  $('cosign-pending').hidden = root?.cosigned === undefined
  signinView(joining)
  if (root !== null) {
    $('identity-id').textContent = root.identity
    $('root-text').value = root.text
    $('join-root').value = root.text
    $('join-fingerprint').textContent = fingerprint(root.id)
  }
}

// The sign-in view replaces the page's sections for one arriving with a request: who asks, what for, and one
// button. What it says is the request's fields, which are what is signed (the delegation is built from them alone,
// under the identity this button makes, finds or holds), with the exact payload's fields under Details. A recovery
// under notice, and a witness that could not be asked, are still said.
const host = (origin) => new URL(origin).host
function signinView (joining) {
  const on = request !== null && !full
  $('signin').hidden = !on
  if (!on) return
  for (const id of ['create', 'joining', 'identity', 'add-root', 'authorise', 'recovery', 'party', 'renew', 'request-waiting', 'request']) $(id).hidden = true
  $('signin-title').textContent = `${host(request.from)} asks to act for you`
  const days = request.days === 1 ? '1 day' : `${request.days} days`
  const at = new Intl.ListFormat('en', { type: 'conjunction' }).format(audiencesOf(request).map(host))
  $('signin-what').textContent = `It will be able to ${request.scopes.join(', ')} at ${at}, under the name ${request.agent}, for ${days}, and nothing else.` +
    (root === null || joining ? ' You sign in with a passkey: the one you already have for this page, or a new one.' : '')
  $('signin-button').textContent = root === null || joining ? 'Continue with a passkey' : 'Sign in with your passkey'
  $('signin-agent').textContent = request.agent
  $('signin-aud').textContent = audiencesOf(request).join(' ')
  $('signin-scopes').textContent = [...new Set(request.scopes)].sort().join(' ')
  $('signin-exp').textContent = `${days} from when you sign`
  $('signin-subject').textContent = request.subject
}

function fail (e) {
  $('error').textContent = e.name === 'NotAllowedError' ? 'The passkey request was cancelled.' : e.message
}

// The witness service: a record submitted, or the records it holds for the identity.
async function submit (identity, type, text, root) {
  const r = await (await fetch(WITNESS + 'v1/records', { method: 'POST', body: JSON.stringify({ identity, type, text, root }) })).json()
  if (!r.ok) throw new Error(`the witness refused the ${type}: ${r.reason}`)
}
async function held (identity) {
  const res = await fetch(WITNESS + `v1/identities/${identity}/records`)
  // The witness knows no such identity (404), or holds its records; anything else is no answer at all.
  if (!res.ok && res.status !== 404) throw new Error('the witness did not answer')
  // Only a 404 says the identity is unknown: records that were served and do not verify are no answer either.
  if (!res.ok) throw Object.assign(new Error('the witness holds no record of this identity'), { unknown: true })
  return res.json()
}
const ctxOf = (identity) => ({ identity, rpId, origin: ORIGIN, witnessKeys: WITNESS_KEYS })
const stateOf = (records, identity) => currentMembership(records, ctxOf(identity))
const state = async (r = root) => stateOf(await held(r.identity), r.identity)
// The current membership's id, for a delegation: only a root with authority (R6) signs one.
async function membership () {
  const s = await state()
  if (!s.authority.includes(root.id)) throw new Error('this passkey has no authority yet: wait for the change to settle')
  return s.membership
}

// R11: whether a recovery of this identity is under notice, asked of the witness on load and after anything that
// may change it. `noticed` is the state it was read from, for the root and identity it was read for; `unchecked`,
// the root and identity the witness gave no answer for, which is said: a notice not shown is then not known to be absent.
let noticed = null
let known = null
let unchecked = null
// The records last taken as an answer for each root and identity asked about, what bounds rollback: kept apart, so
// that an answer about one says nothing of another's (issue #251). One entry for each root this tab has held and
// the witness answered for, each the size of an identity's records.
const answered = new Map()
const askedOf = (r) => `${r.id} ${r.identity}`
let asking = null // the latest question: only its answer is kept
// Whether what was read is of root `r`, in the identity it is held for: the witness is asked by identity, and
// storage (untrusted) may hold the same root for another (scenario 109). `isFor`: of the root held now.
const of = (x, r) => x !== null && x.root === r?.id && x.identity === r.identity
const isFor = (x) => of(x, root)
// Whether two roots read are the same: the same root, for the same identity (a root's identity changes as it joins one).
const same = (a, b) => a?.id === b?.id && a?.identity === b?.identity
async function notice () {
  const r = root
  // A root whose registration this browser has not seen answered is asked about too: the answer may have been lost
  // with the witness holding it, and a recovery of it (scenarios 107-108). A witness that does not know it says so.
  if (r === null || r.joining === true) return
  const asked = {}
  asking = asked
  let s = null
  let records = null
  let failed = false
  try {
    records = await held(r.identity)
    s = stateOf(records, r.identity)
    // Records that leave out a notice read before, without what ends it, are no answer either (issue #243).
    const before = answered.get(askedOf(r))
    if (before !== undefined && withheld(before, records, ctxOf(r.identity))) throw new Error() // a notice read before is left out
  } catch (e) {
    // Only the two ordinary states in which there can be no recovery are silent: an identity the witness says it
    // does not know (404), and one that has ended. A malformed answer, or records that do not verify, is no answer:
    // hiding that would make a recovery notice look absent when the page could not check it. So is a 404 for an
    // identity whose records this tab has taken for this root, however many no-answers since: what it read (a notice
    // among them) is not checked away.
    s = null
    records = null
    failed = (e.unknown !== true || answered.has(askedOf(r))) && e.message !== 'this identity has ended'
  }
  // The root can change in another tab while its request is in flight. Its reply is kept for the root it was asked
  // for, each part shown only while that root is held, so it says nothing of the root now held; nor does it replace
  // the answer to a later question, about that root or another, which may already be shown.
  if (asked !== asking) return
  if (records !== null) answered.set(askedOf(r), records)
  noticed = s !== null && s.recovering !== null ? { root: r.id, identity: r.identity, state: s } : null
  known = { root: r.id, identity: r.identity, state: s } // no answer is a state of null: nothing is known of this root
  unchecked = failed ? { root: r.id, identity: r.identity } : null
  show()
}

// SPEC §7: a change notice need not arrive, so the root is read from storage before the passkey is asked, and again
// once it has signed, before what it signed is handed over or sent. One that another tab replaced meanwhile is
// adopted, as a notice would have it adopted, and what was reviewed for the old one is withdrawn: neither asked for,
// nor handed over, nor sent.
async function stillHeld () {
  if (same(rootOf(await store.get(KEY)), root)) return
  await refresh()
  withdraw()
  show()
  notice()
  // Said here, where what was reviewed is withdrawn: the caller says nothing of what was withdrawn (as lapsed does).
  const e = new Error('The passkey for this page was changed in another tab: review again.')
  fail(e)
  throw e
}
// One user-verified assertion by this identity's own passkey over the records in `covers` (W1).
async function signed (covers, extensions) {
  await stillHeld()
  const a = await navigator.credentials.get({ publicKey: {
    rpId, challenge: challenge(covers), userVerification: 'required',
    allowCredentials: [{ type: 'public-key', id: fromB64u(root.credential) }],
    extensions, // undefined is none
  } })
  return { assertion: assertion(covers, a.response), extensions: a.getClientExtensionResults() }
}
// The same, the root read again once the passkey has signed (the prompt may have been open while another tab
// replaced it). A worker and a renewal read it later instead, after what they save and before they hand over.
const sign = async (covers) => { const a = (await signed(covers)).assertion; await stillHeld(); return a }

// Whether another tab changed the remembered workers since this one last read them (it may not have been told yet):
// if so, it is brought up to date with nothing left to sign, since what was reviewed was reviewed against the list
// as it was.
async function changedElsewhere () {
  const held = await store.get(WORKERS)
  if (text(held) === seen) return false
  adopt(held, false)
  show()
  fail(new Error('The remembered workers were changed in another tab: review again.'))
  return true
}

// Whether any of the delegations reviewed has expired since: if so the review is withdrawn, to be made again from now.
function lapsed (delegations) {
  if (delegations.every((d) => Math.floor(Date.now() / 1000) < d.body.exp)) return false
  withdraw()
  fail(new Error('What was reviewed has since expired: review again.'))
  return true
}

// Counts withdrawals: a review that waited for the witness goes on only if nothing was withdrawn meanwhile.
let withdrawals = 0
function withdraw () {
  // Stryker disable next-line UpdateOperator: equivalent; only compared with what it was
  withdrawals++
  pending.delegation = null
  pending.change = null
  pending.cosign = null
  pending.renewal = null
  pending.designation = null
  pending.recoveryCosign = null
  pending.proof = null
  pending.recover = null
  pending.rescue = null
  for (const id of ['review-panel', 'handoff', 'add-panel', 'add-handoff', 'cosign-panel', 'renew-panel', 'renew-handoffs', 'designate-panel', 'designate-handoff', 'recovery-cosign-panel', 'proof-panel', 'proof', 'recover-panel', 'rescue-panel', 'card']) $(id).hidden = true
  $('error').textContent = ''
}

async function create (joining) {
  withdraw()
  // Another tab may have made one since this page loaded: it is adopted, never overwritten.
  const now = rootOf(await store.get(KEY))
  if (now !== null) { root = now; show(); return }
  try {
    const name = $('name').value.trim() || 'muid identity'
    const c = await navigator.credentials.create({ publicKey: {
      // Stryker disable next-line StringLiteral: equivalent; authenticators may show the name, and none checks it
      rp: { id: rpId, name: 'muid' },
      user: { id: crypto.getRandomValues(new Uint8Array(16)), name, displayName: name },
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      // ES256 only (I6); rootRecord refuses any other algorithm as well.
      // Stryker disable next-line ArrayDeclaration: equivalent where the authenticator's default is ES256, as here
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
      attestation: 'none',
      // So that the passkey can give an application its secret (SPEC §8), where the platform needs it asked now.
      extensions: { prf: {} },
    } })
    const r = rootRecord(c.response.getPublicKey(), c.response.getPublicKeyAlgorithm(), rpId)
    // Kept before the witness is asked, so that a failed registration is retried with this root, not a new passkey.
    // If another tab's root is there instead, it is that tab's to register, or not: it may be joining.
    if (!await keepRoot(null, () => ({ ...r, credential: b64u(c.rawId), joining, registered: false }))) return
  } catch (e) { fail(e); return }
  if (!joining) await register()
}

// A root of its own identity not yet known to be registered with the witness (one stored before this was kept,
// too): registered by sending the same root again, which the witness accepts if it already holds it.
const unregistered = () => root !== null && root.joining !== true && root.registered !== true

async function register () {
  const r = root // the root sent: only it is marked, whatever this tab holds by the time the witness answers
  try {
    await submit(r.identity, 'root', r.text)
    if (await keepRoot(r, (kept) => ({ ...kept, registered: true }))) $('status').textContent = 'Registered with the witness.'
  } catch (e) { fail(e); return }
  // Now the witness knows the identity: what it holds for it (its designation, a recovery under notice) is asked.
  notice()
}

// SPEC §8: an identity opened with a passkey this device has (synced to it, or left when the page's storage was
// cleared). The passkey is asked first, by whatever the platform offers for this site, to sign the identity's
// possession value; the root it is, by the witness's records, is then kept with its credential id as one made here is.
$('open-button').addEventListener('click', async () => {
  withdraw()
  try {
    const identity = $('open-identity').value.trim()
    const covers = [possessionId(identity)]
    const a = await navigator.credentials.get({ publicKey: { rpId, challenge: challenge(covers), userVerification: 'required' } })
    const records = await held(identity)
    const r = opened({ identity, roots: records.roots, state: stateOf(records, identity), assertion: assertion(covers, a.response), rpId, origin: ORIGIN })
    if (!await keepRoot(null, () => ({ ...r, credential: b64u(a.rawId), joining: false, registered: true }))) return
    $('status').textContent = 'Opened with your passkey.'
  } catch (e) { fail(e); return }
  notice()
})

$('create-button').addEventListener('click', () => create(false))
$('register-retry').addEventListener('click', () => { $('error').textContent = ''; register() })
$('join-button').addEventListener('click', () => create(true))
for (const id of ['agent', 'subject', 'aud', 'scopes', 'days', 'new-root', 'cosign-payload', 'party-cards', 'recovery-days', 'recovery-cosign-payload', 'proof-code', 'recover-identity', 'rescue-request', 'rescue-card']) $(id).addEventListener('input', withdraw)

async function review () {
  withdraw()
  const asked = withdrawals
  try {
    // Read before the witness is asked: what is shown is what was in the fields when Review was pressed.
    // One audience or several, separated by spaces: one delegation to each, signed by one assertion (W0).
    const auds = $('aud').value.trim().split(/\s+/)
    const entered = { agent: $('agent').value.trim(), subject: $('subject').value.trim(),
      scopes: $('scopes').value.trim().split(/\s+/), lifetime: Math.round(Number($('days').value) * 86_400) }
    const current = await membership()
    if (asked !== withdrawals) return // withdrawn while the witness was asked
    const r = delegations(auds, { ...entered, identity: root.identity, membership: current, root: root.id, now: Math.floor(Date.now() / 1000) })
    pending.delegation = r
    const d = r.delegations[0] // the others differ from it in their audience alone
    $('show-agent').textContent = d.body.agent
    $('show-aud').textContent = r.delegations.map((x) => x.body.aud).join(' ')
    $('show-scopes').textContent = d.body.scopes.join(' ')
    $('show-exp').textContent = new Date(d.body.exp * 1000).toISOString()
    $('show-subject').textContent = d.body.subject
    // An agent has one key at a time (issue #70): signing this replaces the key remembered for it, said here first.
    const old = retired(workers, d.body)
    $('show-retires').textContent = old.length === 0 ? '' : `This replaces the key remembered for ${d.body.agent}, ${old.join()}: that key will no longer be renewed here. It keeps working until what it was given expires, unless it is revoked.`
    $('review-panel').hidden = false
  } catch (e) { if (asked === withdrawals) fail(e) } // a refusal of what was withdrawn is not shown
}
$('review').addEventListener('click', () => review())

async function signDelegation () {
  const r = pending.delegation
  if (r === null || lapsed(r.delegations) || await changedElsewhere()) return
  const d = r.delegations[0]
  $('error').textContent = ''
  // The application that asked for this worker's key, and for a secret, is given it from the same assertion, if the
  // person leaves it ticked.
  const asked = request !== null && request.subject === d.body.subject
  const secret = asked && request.sealTo !== undefined && $('give-secret').checked
  try {
    const s = await signed(r.covers, secret ? { prf: { eval: { first: secretInput(request.from) } } } : undefined)
    const a = s.assertion
    if (pending.delegation !== r || lapsed(r.delegations)) return // withdrawn while the passkey was asked
    // Remembered for renewal: what was signed, with its lifetime, never the signature. Remembered first, and only
    // if the workers are still as they were reviewed: a worker is handed nothing if the change (which may retire
    // its agent's old key) was not saved.
    const given = r.delegations.map(({ body: { agent, subject, aud, scopes, nbf, exp } }) => ({ agent, subject, aud, scopes, lifetime: exp - nbf }))
    if (await keepWorkers((list) => given.reduce((l, w) => remember(l, w), list), seen, () => pending.delegation === r) !== 'saved') return
    if (pending.delegation !== r || lapsed(r.delegations)) return // withdrawn, or expired, while it was saved
    await stillHeld()
    const lines = r.delegations.map((x) => handOff(x.payload, a)) // in the order of the audiences
    $('handoff').value = lines.join('\n')
    $('handoff').hidden = false
    // The application that asked for this worker's key is answered, at its own address; any other is not.
    if (asked) {
      // A browser that cannot evaluate prf may leave its entry out, which Chrome never does when it was asked for.
      // Stryker disable next-line OptionalChaining: equivalent in Chrome, see above
      const first = secret ? prfOutput(s.extensions.prf?.results?.first) : null
      location.assign(answer(request, lines, first === null ? null : await sealSecret(first, request)))
    }
  } catch (e) { if (pending.delegation === r) fail(e) } // nor is a late refusal of what was withdrawn
}
$('sign').addEventListener('click', () => signDelegation())

// The sign-in view's button. With no identity here, the passkey the platform offers for this site is asked first,
// over a fresh value that is no record's id; the identity it is the first root of is opened as by its id. Then the
// identity is registered if it is not yet, the request reviewed, and signed: the person is sent back with the answer.
async function discover () {
  const covers = [possessionId(freshValue())]
  const a = await navigator.credentials.get({ publicKey: { rpId, challenge: challenge(covers), userVerification: 'required' } })
  const signed = assertion(covers, a.response)
  for (const identity of firstRootIdentities(a.response, rpId)) {
    let records
    try {
      records = await held(identity)
    } catch (e) {
      if (e.unknown === true) continue
      throw e
    }
    const r = opened({ identity, record: covers[0], roots: records.roots, state: stateOf(records, identity), assertion: signed, rpId, origin: ORIGIN })
    // Kept unless another tab has stored a root meanwhile, which is then the one used. Whether a recovery of it is
    // under way is asked next, before anything is signed (proceed).
    await keepRoot(null, () => ({ ...r, credential: b64u(a.rawId), joining: false, registered: true }))
    return
  }
  throw new Error('The identity of that passkey was not found. If it was added to an identity on another device, choose More options and open that identity by its id.')
}
// What the page says of a recovery of the root held: the notice's record, that the witness could not be asked, or nothing.
const told = () => isFor(unchecked) ? 'unchecked' : isFor(noticed) ? noticed.state.recovering.record : null
// `before`: what was said when the button was pressed. The witness is asked about a recovery of the root before
// anything is signed, and what it says that was not said then is shown, not passed over: the person signs in with
// another press (R2, scenarios 107-108; the page leaves once it has signed).
async function proceed (before) {
  if (root === null) return
  if (root.joining === true) { fail(new Error('This passkey is joining an identity and can sign nothing until that change has settled.')); return }
  await notice()
  const now = told()
  if (now !== null && now !== before) {
    fail(new Error(now === 'unchecked'
      ? 'The witness could not be asked whether a recovery of this identity is under way. Ask again, or press the button again to sign in.'
      : 'A recovery of this identity is under way, shown above. Cancel it if you did not ask for it, or press the button again to sign in.'))
    return
  }
  if (unregistered()) {
    await register()
    if (unregistered()) return
  }
  await review()
  await signDelegation() // nothing, if the review was refused
}
// The sign-in shortcuts review and sign in one click. Only the visible app-request view authorises that shortcut:
// a scripted click on a hidden button must not create the review it needs (scenario 97).
// signinView shows it only for an app request; a lost store hides it with the rest.
const activeSignin = () => !$('signin').hidden
$('signin-button').addEventListener('click', async () => {
  if (!activeSignin()) return
  const before = told()
  $('error').textContent = ''
  $('signin-new').hidden = true
  if (root === null) {
    try {
      await discover()
    } catch (e) {
      $('signin-new').hidden = false
      if (e.name !== 'NotAllowedError') fail(e)
      return
    }
  }
  await proceed(before)
})
$('signin-create').addEventListener('click', async () => {
  if (!activeSignin() || $('signin-new').hidden) return
  await create(false)
  await proceed(null)
})
$('signin-more').addEventListener('click', () => { full = true; show() })

// What a box shows, copied for the user to give to the worker: the same text, and nothing else.
async function copy (box) {
  $('error').textContent = ''
  try {
    await navigator.clipboard.writeText(box.value)
    $('status').textContent = 'Copied.'
  } catch (e) { fail(e) }
}
$('handoff-copy').addEventListener('click', () => copy($('handoff')))

// Decision 3: the ticked workers' delegations, built again from now under the current membership, shown (I4), and
// signed by one assertion over them all (W0).
$('renew-review').addEventListener('click', async () => {
  withdraw()
  const asked = withdrawals
  try {
    const chosen = workers.filter((w) => !unticked.has(slot(w)))
    const current = await membership()
    if (asked !== withdrawals) return // withdrawn while the witness was asked
    const r = renewals(chosen, { identity: root.identity, membership: current, root: root.id, now: Math.floor(Date.now() / 1000) })
    pending.renewal = r
    $('renew-list').replaceChildren(...r.delegations.map((d) =>
      element('li', element('dl', ...fields(d.body).flatMap(([name, value]) => [element('dt', name), element('dd', value)])))))
    $('renew-panel').hidden = false
  } catch (e) { if (asked === withdrawals) fail(e) } // a refusal of what was withdrawn is not shown
})

$('renew-sign').addEventListener('click', async () => {
  const r = pending.renewal
  if (r === null || lapsed(r.delegations) || await changedElsewhere()) return
  $('error').textContent = ''
  try {
    const a = (await signed(r.covers)).assertion
    // A renewal takes effect at this read of storage: a change committed after it is after the renewal.
    if (pending.renewal !== r) return // withdrawn while the passkey was asked
    if (await changedElsewhere() || pending.renewal !== r || lapsed(r.delegations)) return
    await stillHeld()
    $('renew-handoffs').replaceChildren(...r.delegations.flatMap((d) => {
      const t = element('textarea')
      t.readOnly = true
      t.setAttribute('aria-label', `Give this to ${d.body.agent}`)
      t.value = handOff(d.payload, a)
      const b = element('button', 'Copy')
      b.type = 'button'
      b.className = 'copy'
      b.addEventListener('click', () => copy(t))
      return [t, b]
    }))
    $('renew-handoffs').hidden = false
  } catch (e) { if (pending.renewal === r) fail(e) } // nor is a late refusal of what was withdrawn
})

$('add-review').addEventListener('click', async () => {
  withdraw()
  const asked = withdrawals
  try {
    const rootText = $('new-root').value.trim()
    const current = await state()
    if (asked !== withdrawals) return // withdrawn while the witness was asked
    const c = addRoot({ identity: root.identity, state: current, root: rootText, rpId })
    pending.change = { ...c, rootText }
    $('add-added').textContent = c.added
    $('add-fingerprint').textContent = fingerprint(c.added)
    $('add-epoch').textContent = String(c.body.epoch)
    $('add-recovery').textContent = designation(c.body.recovery)
    $('add-panel').hidden = false
  } catch (e) { if (asked === withdrawals) fail(e) } // a refusal of what was withdrawn is not shown
})

$('add-sign').addEventListener('click', async () => {
  const c = pending.change
  if (c === null) return
  $('error').textContent = ''
  $('status').textContent = '' // what is said next is said of this signing
  try {
    const a = await sign([c.id])
    if (pending.change !== c) return
    // Once signed, the change is submitted whatever follows; only its hand-off is withheld if it was withdrawn.
    await submit(root.identity, 'membership', rootSigned(c.payload, root.id, a))
    await submit(root.identity, 'root', c.rootText)
    if (pending.change !== c) return
    $('add-handoff').value = c.payload
    $('add-handoff').hidden = false
    $('status').textContent = 'Signed. The other device co-signs this change.'
  } catch (e) { if (pending.change === c) fail(e) } // nor is a late refusal of it
})

// The change a joining passkey co-signs, shown with the passkeys it removes and adds (I4, issue #246): against the
// membership it follows, which must be the identity's current one as the witness holds it, unless the change is
// itself the one pending (this passkey's co-signature sent before, or reviewed again).
$('cosign-review').addEventListener('click', async () => {
  withdraw()
  const asked = withdrawals
  try {
    const c = changeToSign($('cosign-payload').value.trim())
    if (!c.body.roots.includes(root.id)) throw new Error('that change does not add this passkey')
    const records = await held(c.body.identity)
    const now = stateOf(records, c.body.identity)
    if (asked !== withdrawals) return // withdrawn while the witness was asked
    if (c.body.prev !== now.membership && c.id !== now.membership) throw new Error("that change does not follow the identity's current membership")
    const before = rootsOf(records, c.body.prev, c.body.identity, rpId)
    pending.cosign = c
    $('cosign-identity').textContent = c.body.identity
    $('cosign-roots').textContent = c.body.roots.join(' ')
    $('cosign-removed').textContent = listed(before.filter((x) => !c.body.roots.includes(x)))
    $('cosign-added').textContent = listed(c.body.roots.filter((x) => !before.includes(x)))
    $('cosign-recovery').textContent = designation(c.body.recovery)
    $('cosign-panel').hidden = false
  } catch (e) { if (asked === withdrawals) fail(e) } // a refusal of what was withdrawn is not shown
})

$('cosign-sign').addEventListener('click', async () => {
  const c = pending.cosign
  if (c === null) return
  $('error').textContent = ''
  const mine = root // the root whose passkey signs
  try {
    const a = await sign([c.id])
    if (pending.cosign !== c) return
    // Kept before the witness is asked, as a registration is, so that a lost answer is sent again, not lost.
    if (!await keepRoot(mine, (kept) => ({ ...kept, cosigned: rootSigned(c.payload, mine.id, a) }))) return
  } catch (e) { if (pending.cosign === c) fail(e); return } // nor is a late refusal of what was withdrawn
  await cosign()
})

// The kept co-signature, sent (again: the witness accepts one it already holds); once taken, this root is the
// identity's.
async function cosign () {
  const r = root // the root whose co-signature is sent: only it becomes the identity's
  // What the witness says of it is said while that root is held. It is said of the kept co-signature, not of a review:
  // it is sent again on load and by the button, with no review on screen, and a refusal is what the button is for.
  const mine = () => same(root, r)
  try {
    const identity = cosignedIdentity(r.cosigned, r.id)
    try {
      await submit(identity, 'membership', r.cosigned)
    } catch (e) {
      // In a recovery (R11) nobody else has given the witness this root's record: it is given, and this sent again.
      if (e.message !== 'the witness refused the membership: root-missing') throw e
      await submit(identity, 'root', r.text)
      await submit(identity, 'membership', r.cosigned)
    }
    if (await keepRoot(r, ({ cosigned, ...rest }) => ({ ...rest, identity, joining: false, registered: true }))) {
      $('status').textContent = 'Co-signed. The change settles once its contest window has passed.'
    }
  } catch (e) { if (mine()) fail(e); return }
  notice()
}
$('cosign-retry').addEventListener('click', () => { $('error').textContent = ''; cosign() })

// R11: any one root cancels the recovery under notice. What is signed is the record shown (I4); the witness says it
// is cancelled at its next pass, and the notice goes when it has.
$('notice-cancel').addEventListener('click', async () => {
  const n = noticed
  // The incoming root sees the notice but has no cancel authority; even a scripted click on its hidden button
  // must not ask that passkey to sign. Use the same current-root test that decides which panel is shown.
  if (!isFor(n) || !n.state.roots.includes(n.root)) return
  $('error').textContent = ''
  $('status').textContent = '' // what is said next is said of this signing
  // The root it is for: another tab may store another while the passkey is asked or the witness answers, and this
  // page then shows that one. What was signed is sent only for the root it was signed for, and only while this page
  // holds it; nothing is said of it after.
  const r = root
  const mine = () => same(root, r)
  try {
    const c = cancel({ identity: r.identity, state: n.state })
    const a = await sign([c.id])
    if (!mine()) return
    await submit(r.identity, 'cancel', rootSigned(c.payload, r.id, a))
    if (!mine()) return
    $('status').textContent = 'Cancel sent. The notice goes once the witness has said the recovery is cancelled. The parties that signed it are known from now on: ask them for new recovery cards and designate them again.'
    await notice()
  } catch (e) { if (mine()) fail(e) }
})
$('notice-retry').addEventListener('click', notice)

// R11, designating: the parties' cards and the wait make a membership change with the same roots, shown from its
// payload (I4). Before it is signed each party shows that it holds its passkey (SPEC §8); what they give back is
// checked here and goes nowhere. Ending a designation is the same change without one.
const lines = (id) => $(id).value.split('\n').map((t) => t.trim()).filter((t) => t !== '')
async function reviewDesignation (ending) {
  withdraw()
  const asked = withdrawals
  try {
    const cards = lines('party-cards')
    const window = Math.round(Number($('recovery-days').value) * DAY)
    const current = await state()
    if (asked !== withdrawals) return // withdrawn while the witness was asked
    const parties = ending ? [] : cards.map((t) => fromCard(t, rpId))
    const c = ending ? undesignate({ identity: root.identity, state: current })
      : designate({ identity: root.identity, state: current, parties, threshold: majority(parties.length), window })
    pending.designation = { ...c, parties, alone: current.roots.length === 1 }
    $('designate-recovery').textContent = designation(c.body.recovery)
    $('designate-roots').textContent = c.body.roots.join(' ')
    $('designate-epoch').textContent = String(c.body.epoch)
    $('designate-code').textContent = c.id
    $('designate-proofs-part').hidden = ending
    $('designate-panel').hidden = false
  } catch (e) { if (asked === withdrawals) fail(e) } // a refusal of what was withdrawn is not shown
}
$('designate-review').addEventListener('click', () => reviewDesignation(false))
$('undesignate-review').addEventListener('click', () => reviewDesignation(true))

$('designate-sign').addEventListener('click', async () => {
  const c = pending.designation
  if (c === null) return
  $('error').textContent = ''
  $('status').textContent = '' // what is said next is said of this signing
  try {
    const proofs = lines('designate-proofs')
    const unshown = c.parties.filter((p) => !proofs.some((t) => shows(p, t, { record: c.id, rpId, origin: ORIGIN }))).length
    if (unshown > 0) throw new Error(`${unshown} of the parties have not shown that they hold their passkey`)
    const a = await sign([c.id])
    if (pending.designation !== c) return
    await submit(root.identity, 'membership', rootSigned(c.payload, root.id, a))
    if (pending.designation !== c) return
    $('designate-handoff').value = c.payload
    $('designate-handoff').hidden = c.alone
    $('status').textContent = c.alone ? 'Signed. The change settles once its contest window has passed.' : 'Signed. Co-sign this change with your other passkeys.'
  } catch (e) { if (pending.designation === c) fail(e) } // a late answer to what was withdrawn is not shown
})

// The same check later, over a fresh code: a passkey shown once may be gone since.
$('recheck').addEventListener('click', async () => {
  withdraw()
  $('status').textContent = ''
  const asked = withdrawals
  const code = recheckCode
  try {
    const parties = lines('party-cards').map((t) => fromCard(t, rpId))
    const proofs = lines('recheck-proofs')
    const current = await state()
    if (asked !== withdrawals) return // withdrawn while the witness was asked
    if (parties.length === 0) throw new Error('paste the recovery cards of the parties to check')
    if (!parties.every((p) => designated(current.recovery, p))) throw new Error("a card here is not one of this identity's recovery parties")
    if (new Set(parties.map((p) => p.root)).size !== parties.length) throw new Error('a recovery party is named twice')
    const held = parties.filter((p) => proofs.some((t) => shows(p, t, { record: code, rpId, origin: ORIGIN }))).length
    // Used once: the next check is over a new code.
    recheckCode = freshValue()
    show()
    $('status').textContent = `${held} of ${parties.length} of these parties showed that they hold their passkey.`
  } catch (e) { if (asked === withdrawals) fail(e) }
})

// A change to the designation made with another of the identity's passkeys, co-signed here: only one that keeps
// the roots as they are, shown from its payload (I4).
$('recovery-cosign-review').addEventListener('click', async () => {
  withdraw()
  const asked = withdrawals
  try {
    const payload = $('recovery-cosign-payload').value.trim()
    const current = await state()
    if (asked !== withdrawals) return // withdrawn while the witness was asked
    const c = recoveryChange(payload, { identity: root.identity, state: current })
    pending.recoveryCosign = c
    $('recovery-cosign-recovery').textContent = designation(c.body.recovery)
    $('recovery-cosign-roots').textContent = c.body.roots.join(' ')
    $('recovery-cosign-epoch').textContent = String(c.body.epoch)
    $('recovery-cosign-panel').hidden = false
  } catch (e) { if (asked === withdrawals) fail(e) }
})
$('recovery-cosign-sign').addEventListener('click', async () => {
  const c = pending.recoveryCosign
  if (c === null) return
  $('error').textContent = ''
  $('status').textContent = '' // what is said next is said of this signing
  try {
    const a = await sign([c.id])
    if (pending.recoveryCosign !== c) return
    await submit(root.identity, 'membership', rootSigned(c.payload, root.id, a))
    if (pending.recoveryCosign !== c) return // sent, but a late answer to what was withdrawn is not shown
    $('status').textContent = 'Co-signed. The change settles once its contest window has passed.'
  } catch (e) { if (pending.recoveryCosign === c) fail(e) }
})

// R11, for one who has lost every passkey: a passkey made to join asks the identity's recovery parties to make it
// the identity's only root. The request is shown from its payload (I4) and given to the parties; this passkey signs
// after them, and its signature is kept and sent as a co-signature is.
$('recover-review').addEventListener('click', async () => {
  withdraw()
  const asked = withdrawals
  try {
    const identity = $('recover-identity').value.trim()
    if (!/^[0-9a-f]{64}$/.test(identity)) throw new Error('an identity is 64 lowercase hex digits')
    const current = await state({ identity })
    if (asked !== withdrawals) return // withdrawn while the witness was asked
    const c = recovery({ identity, state: current, root: root.text, rpId })
    pending.recover = c
    $('recover-shown').textContent = c.body.identity
    // Stryker disable next-line StringLiteral: equivalent; a recovery names one root
    $('recover-roots').textContent = c.body.roots.join(' ')
    $('recover-recovery').textContent = designation(c.body.recovery)
    $('recover-wait').textContent = `${wait(current.recovery.window)} after enough parties and this passkey have signed, unless a passkey the identity has now cancels it`
    $('recover-request').value = c.payload
    $('recover-panel').hidden = false
  } catch (e) { if (asked === withdrawals) fail(e) }
})
$('recover-sign').addEventListener('click', async () => {
  const c = pending.recover
  if (c === null) return
  $('error').textContent = ''
  const added = c.added // this passkey's root, as it was when the request was made
  const mine = root // held so since: the request is withdrawn when it is not
  try {
    const a = await sign([c.id])
    if (pending.recover !== c) return
    if (!await keepRoot(mine, (now) => ({ ...now, cosigned: rootSigned(c.payload, added, a) }))) return
  } catch (e) { if (pending.recover === c) fail(e); return } // nor is a late refusal of what was withdrawn
  await cosign()
})

// R11, as a party asked to recover someone: the request is read against the identity as the witness holds it, and
// shown from its payload (I4) with the fingerprints of the passkeys it would make the identity's. The salt is one
// this passkey kept, or the one on the card given back.
$('rescue-review').addEventListener('click', async () => {
  withdraw()
  const asked = withdrawals
  try {
    const payload = $('rescue-request').value.trim()
    const given = $('rescue-card').value.trim()
    const identity = changeToSign(payload).body.identity
    const mine = root
    const back = given === '' ? [] : [fromCard(given, rpId)]
    if (back.some((p) => p.root !== mine.id)) throw new Error("that recovery card is not this passkey's")
    const current = await state({ identity })
    if (asked !== withdrawals) return // withdrawn while the witness was asked
    const c = rescue(payload, { state: current, root: mine.id, salts: [...(mine.salts ?? []), ...back.map((p) => p.salt)] })
    pending.rescue = c
    // I4: what the change removes and adds, against the membership it follows (which the change names as its prev).
    // A recovery need not replace every passkey, nor add one: it may change only the designation (scenario 82).
    const removed = current.roots.filter((x) => !c.body.roots.includes(x))
    const added = c.body.roots.filter((x) => !current.roots.includes(x))
    $('rescue-identity').textContent = c.body.identity
    $('rescue-removed').textContent = listed(removed)
    $('rescue-added').textContent = listed(added)
    $('rescue-roots').textContent = c.body.roots.join(' ')
    $('rescue-fingerprints').textContent = c.body.roots.map(fingerprint).join(', ')
    $('rescue-recovery').textContent = designation(c.body.recovery)
    $('rescue-wait').textContent = `${wait(c.window)} after enough parties${added.length === 0 ? '' : ' and every passkey it adds'} have signed, unless a passkey the identity has now cancels it`
    $('rescue-panel').hidden = false
  } catch (e) { if (asked === withdrawals) fail(e) }
})
$('rescue-sign').addEventListener('click', async () => {
  const c = pending.rescue
  if (c === null) return
  $('error').textContent = ''
  $('status').textContent = '' // what is said next is said of this signing
  try {
    const a = await sign([c.id])
    if (pending.rescue !== c) return
    await submit(c.body.identity, 'membership', partySigned(c.payload, { root: root.id, salt: c.salt }, a), root.text)
    if (pending.rescue !== c) return // sent, but a late answer to what was withdrawn is not shown
    $('status').textContent = 'Signed. The recovery is under notice once enough parties, and any passkey it adds, have signed.'
  } catch (e) { if (pending.rescue === c) fail(e) }
})

// R11, as a party: a recovery card is this passkey's root record and a new salt. The salt is kept before the card
// is shown: on the day this passkey recovers someone, nobody else may have it.
$('card-make').addEventListener('click', async () => {
  $('error').textContent = ''
  const r = root
  try {
    const salt = newSalt()
    if (!await keepRoot(r, (now) => ({ ...now, salts: kept(now.salts, salt) }))) return
    if (!root.salts.includes(salt)) throw new Error(`this passkey has given out ${MAX_SALTS} recovery cards, the most it keeps`)
    $('card').value = card(r.text, salt)
    $('card').hidden = false
  } catch (e) { fail(e) }
})
// A party shows that it holds its passkey: what is signed is the code's possession value, which is no record's id
// and so signs nothing else.
$('proof-review').addEventListener('click', () => {
  withdraw()
  try {
    const record = $('proof-code').value.trim()
    pending.proof = { id: possessionId(record) }
    $('proof-shown').textContent = record
    $('proof-panel').hidden = false
  } catch (e) { fail(e) }
})
$('proof-sign').addEventListener('click', async () => {
  const p = pending.proof
  if (p === null) return
  $('error').textContent = ''
  try {
    const a = await sign([p.id])
    if (pending.proof !== p) return
    $('proof').value = JSON.stringify(a)
    $('proof').hidden = false
  } catch (e) { if (pending.proof === p) fail(e) } // nor is a late refusal of what was withdrawn
})

// A control the page does not show does nothing (I4: what is signed is what was shown), even pressed by a script:
// a click inside a hidden part is stopped before any handler hears it, and a checkbox there is not changed.
document.addEventListener('click', (e) => {
  if (e.target.closest('[hidden]') !== null) { e.preventDefault(); e.stopPropagation() }
}, true)

// SPEC §7: without its storage the page offers nothing. What another tab of this origin stores is followed here, so
// a page open since before cannot act on a stale root or a stale list.
if (REFUSAL === undefined) {
  try {
    // A store lost while the page is open (model/STATE.md: a later version of the page took it, or the browser
    // cleared it): whatever is open is withdrawn, and the page offers nothing more until it is loaded again.
    store = await openStore('muid', () => {
      withdraw()
      for (const id of ['create', 'identity', 'authorise', 'renew', 'add-root', 'joining', 'pending', 'recovery-notice', 'notice-unchecked', 'recovery', 'party', 'signin']) $(id).hidden = true
      REFUSAL = 'A newer version of this page has taken its storage, or the browser has cleared it: reload this page.'
      show()
    })
    await refresh()
    store.watch(() => refresh().then(() => { withdraw(); show(); notice() }, fail))
  } catch {
    REFUSAL = 'This browser gave the page no storage: it can do nothing here.'
  }
}
show()
// What is kept to be sent (an outbox) is sent again on load. Where the page refuses to act it has read no root.
if (unregistered()) register()
notice()
if (root?.cosigned !== undefined) cosign()
