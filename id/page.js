// The id page (SPEC §8): create an identity with a passkey and register its root with the witness; add a passkey on
// another device (a membership change, R1: signed here, co-signed there); and authorise a worker's key by one
// assertion, under the identity's current membership. Every record the passkey signs is shown first from its exact
// payload (I4); changing any input withdraws it, and a signature that returns after an edit is discarded. The root
// record and the credential id are kept in this browser only. The workers it authorised are remembered here too, so
// that one assertion renews up to eight of them at once (decision 3).
import { openStore } from './store.js'
import { rootRecord, challenge, assertion, delegation, handOff, b64u, fromB64u, currentMembership, addRoot, rootSigned, changeToSign, fingerprint, storedRoot, cosignedIdentity, storedWorkers, remember, retired, renewals } from './records.js'

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

// SPEC §7: what the page keeps (the root with its credential id, and the remembered workers) it keeps through the
// storage adapter alone. Every change is one transaction there, made to what storage holds at that moment, so no tab
// writes back a value another tab has since replaced. What is read back is untrusted: anything on the origin may
// have written it. The page's own copies are never ahead of storage: a change that was not saved is not shown as made.
let store
let root = null
let workers = []
const text = (held) => JSON.stringify(held)
const rootOf = (held) => held.absent ? null : storedRoot(held.value, rpId)
const workersOf = (held) => storedWorkers(held.absent ? null : held.value)
// `seen` is the remembered workers as this tab last read them: storage that differs was changed by another tab.
let seen
async function refresh () {
  root = rootOf(await store.get(KEY))
  const held = await store.get(WORKERS)
  seen = text(held)
  workers = workersOf(held)
}
const pending = { delegation: null, change: null, cosign: null, renewal: null }

// A change to the stored root, made only while storage holds the root this tab acts for (none, when it creates
// one): another tab's root is adopted, never overwritten.
async function keepRoot (change) {
  const mine = root === null ? null : root.id
  const held = await store.update(KEY, (now) => {
    const r = rootOf(now)
    return (r === null ? null : r.id) === mine ? { value: change(r) } : undefined
  })
  root = rootOf(held)
  show()
}

// A change to the remembered workers, made to what storage holds at that moment. Given `reviewed` (the workers as
// they were when the user reviewed what this change follows from), it is made only if storage still holds exactly
// that. 'saved'; or 'changed' (another tab changed them: this one is brought up to date, with nothing left to sign);
// or 'unsaved' (the browser could not keep it: said, and the list stays as storage holds it).
async function keepWorkers (change, reviewed) {
  let outcome = 'saved'
  try {
    const held = await store.update(WORKERS, (now) => {
      if (reviewed !== undefined && text(now) !== reviewed) { outcome = 'changed'; return undefined }
      return { value: change(workersOf(now)) }
    })
    seen = text(held)
    workers = workersOf(held)
  } catch {
    outcome = 'unsaved'
    await refresh()
  }
  if (outcome === 'changed') withdraw()
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
    forget.addEventListener('click', () => { withdraw(); keepWorkers((list) => list.filter((x) => x.agent !== w.agent || x.aud !== w.aud)) })
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
  $('renew').hidden = root === null || joining || workers.length === 0
  listWorkers()
  $('pending').hidden = !unregistered()
  $('cosign-pending').hidden = root?.cosigned === undefined
  if (root !== null) {
    $('identity-id').textContent = root.identity
    $('root-text').value = root.text
    $('join-root').value = root.text
    $('join-fingerprint').textContent = fingerprint(root.id)
  }
}

function fail (e) {
  $('error').textContent = e.name === 'NotAllowedError' ? 'The passkey request was cancelled.' : e.message
}

// The witness service: a record submitted, or the records it holds for the identity.
async function submit (identity, type, text) {
  const r = await (await fetch(WITNESS + 'v1/records', { method: 'POST', body: JSON.stringify({ identity, type, text }) })).json()
  if (!r.ok) throw new Error(`the witness refused the ${type}: ${r.reason}`)
}
async function state () {
  const res = await fetch(WITNESS + `v1/identities/${root.identity}/records`)
  const records = res.ok ? await res.json() : {}
  return currentMembership(records, { identity: root.identity, rpId, origin: ORIGIN, witnessKeys: WITNESS_KEYS })
}
// The current membership's id, for a delegation: only a root with authority (R6) signs one.
async function membership () {
  const s = await state()
  if (!s.authority.includes(root.id)) throw new Error('this passkey has no authority yet: wait for the change to settle')
  return s.membership
}

// One user-verified assertion by this identity's own passkey over the records in `covers` (W1).
async function sign (covers) {
  const a = await navigator.credentials.get({ publicKey: {
    rpId, challenge: challenge(covers), userVerification: 'required',
    allowCredentials: [{ type: 'public-key', id: fromB64u(root.credential) }],
  } })
  return assertion(covers, a.response)
}

// Whether another tab changed the remembered workers since this one last read them (it may not have been told yet):
// if so, it is brought up to date with nothing left to sign, since what was reviewed was reviewed against the list
// as it was.
async function changedElsewhere () {
  const held = await store.get(WORKERS)
  if (text(held) === seen) return false
  seen = text(held)
  workers = workersOf(held)
  withdraw()
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
  withdrawals++
  pending.delegation = null
  pending.change = null
  pending.cosign = null
  pending.renewal = null
  for (const id of ['review-panel', 'handoff', 'add-panel', 'add-handoff', 'cosign-panel', 'renew-panel', 'renew-handoffs']) $(id).hidden = true
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
    } })
    const r = rootRecord(c.response.getPublicKey(), c.response.getPublicKeyAlgorithm(), rpId)
    // Kept before the witness is asked, so that a failed registration is retried with this root, not a new passkey.
    await keepRoot(() => ({ ...r, credential: b64u(c.rawId), joining, registered: false }))
  } catch (e) { fail(e); return }
  if (!joining) await register()
}

// A root of its own identity not yet known to be registered with the witness (one stored before this was kept,
// too): registered by sending the same root again, which the witness accepts if it already holds it.
const unregistered = () => root !== null && root.joining !== true && root.registered !== true

async function register () {
  try {
    await submit(root.identity, 'root', root.text)
    await keepRoot((kept) => ({ ...kept, registered: true }))
    $('status').textContent = 'Registered with the witness.'
  } catch (e) { fail(e) }
}

$('create-button').addEventListener('click', () => create(false))
$('register-retry').addEventListener('click', () => { $('error').textContent = ''; register() })
$('join-button').addEventListener('click', () => create(true))
for (const id of ['agent', 'subject', 'aud', 'scopes', 'days', 'new-root', 'cosign-payload']) $(id).addEventListener('input', withdraw)

$('review').addEventListener('click', async () => {
  withdraw()
  const asked = withdrawals
  try {
    // Read before the witness is asked: what is shown is what was in the fields when Review was pressed.
    const entered = { agent: $('agent').value.trim(), subject: $('subject').value.trim(), aud: $('aud').value.trim(),
      scopes: $('scopes').value.trim().split(/\s+/), lifetime: Math.round(Number($('days').value) * 86_400) }
    const current = await membership()
    if (asked !== withdrawals) return // withdrawn while the witness was asked
    const d = delegation({ ...entered, identity: root.identity, membership: current, root: root.id, now: Math.floor(Date.now() / 1000) })
    pending.delegation = d
    $('show-agent').textContent = d.body.agent
    $('show-aud').textContent = d.body.aud
    $('show-scopes').textContent = d.body.scopes.join(' ')
    $('show-exp').textContent = new Date(d.body.exp * 1000).toISOString()
    $('show-subject').textContent = d.body.subject
    // An agent has one key at a time (issue #70): signing this replaces the key remembered for it, said here first.
    const old = retired(workers, d.body)
    $('show-retires').textContent = old.length === 0 ? '' : `This replaces the key remembered for ${d.body.agent}, ${old.join()}: that key will no longer be renewed here. It keeps working until what it was given expires, unless it is revoked.`
    $('review-panel').hidden = false
  } catch (e) { if (asked === withdrawals) fail(e) } // a refusal of what was withdrawn is not shown
})

$('sign').addEventListener('click', async () => {
  const d = pending.delegation
  if (d === null || lapsed([d]) || await changedElsewhere()) return
  $('error').textContent = ''
  try {
    const a = await sign([d.id])
    if (pending.delegation !== d || lapsed([d])) return // withdrawn while the passkey was asked
    // Remembered for renewal: what was signed, with its lifetime, never the signature. Remembered first, and only
    // if the workers are still as they were reviewed: a worker is handed nothing if the change (which may retire
    // its agent's old key) was not saved.
    const { agent, subject, aud, scopes, nbf, exp } = d.body
    if (await keepWorkers((list) => remember(list, { agent, subject, aud, scopes, lifetime: exp - nbf }), seen) !== 'saved' || pending.delegation !== d) return
    $('handoff').value = handOff(d.payload, a)
    $('handoff').hidden = false
  } catch (e) { fail(e) }
})

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
    const a = await sign(r.covers)
    if (pending.renewal !== r || lapsed(r.delegations) || await changedElsewhere()) return // withdrawn while the passkey was asked
    $('renew-handoffs').replaceChildren(...r.delegations.map((d) => {
      const t = element('textarea')
      t.readOnly = true
      t.setAttribute('aria-label', `Give this to ${d.body.agent}`)
      t.value = handOff(d.payload, a)
      return t
    }))
    $('renew-handoffs').hidden = false
  } catch (e) { fail(e) }
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
    $('add-panel').hidden = false
  } catch (e) { if (asked === withdrawals) fail(e) } // a refusal of what was withdrawn is not shown
})

$('add-sign').addEventListener('click', async () => {
  const c = pending.change
  if (c === null) return
  $('error').textContent = ''
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
  } catch (e) { fail(e) }
})

$('cosign-review').addEventListener('click', () => {
  withdraw()
  try {
    const c = changeToSign($('cosign-payload').value.trim())
    if (!c.body.roots.includes(root.id)) throw new Error('that change does not add this passkey')
    pending.cosign = c
    $('cosign-identity').textContent = c.body.identity
    $('cosign-roots').textContent = c.body.roots.join(' ')
    $('cosign-panel').hidden = false
  } catch (e) { fail(e) }
})

$('cosign-sign').addEventListener('click', async () => {
  const c = pending.cosign
  if (c === null) return
  $('error').textContent = ''
  try {
    const a = await sign([c.id])
    if (pending.cosign !== c) return
    // Kept before the witness is asked, as a registration is, so that a lost answer is sent again, not lost.
    await keepRoot((kept) => ({ ...kept, cosigned: rootSigned(c.payload, root.id, a) }))
  } catch (e) { fail(e); return }
  await cosign()
})

// The kept co-signature, sent (again: the witness accepts one it already holds); once taken, this root is the
// identity's.
async function cosign () {
  try {
    const identity = cosignedIdentity(root.cosigned, root.id)
    await submit(identity, 'membership', root.cosigned)
    await keepRoot(({ cosigned, ...rest }) => ({ ...rest, identity, joining: false, registered: true }))
    $('status').textContent = 'Co-signed. The change settles once its contest window has passed.'
  } catch (e) { fail(e) }
}
$('cosign-retry').addEventListener('click', () => { $('error').textContent = ''; cosign() })

// SPEC §7: without its storage the page offers nothing. What another tab of this origin stores is followed here, so
// a page open since before cannot act on a stale root or a stale list.
if (REFUSAL === undefined) {
  try {
    store = await openStore('muid')
    await refresh()
    store.watch(() => refresh().then(() => { withdraw(); show() }, fail))
  } catch {
    REFUSAL = 'This browser gave the page no storage: it can do nothing here.'
  }
}
show()
// What is kept to be sent (an outbox) is sent again on load. Where the page refuses to act it has read no root.
if (unregistered()) register()
if (root?.cosigned !== undefined) cosign()
