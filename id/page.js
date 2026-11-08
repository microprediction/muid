// The id page (SPEC §8): create an identity with a passkey and register its root with the witness; add a passkey on
// another device (a membership change, R1: signed here, co-signed there); and authorise a worker's key by one
// assertion, under the identity's current membership. Every record the passkey signs is shown first from its exact
// payload (I4); changing any input withdraws it, and a signature that returns after an edit is discarded. The root
// record and the credential id are kept in this browser only.
import { rootRecord, challenge, assertion, delegation, handOff, b64u, fromB64u, currentMembership, addRoot, rootSigned, changeToSign, fingerprint, storedRoot, cosignedIdentity } from './records.js'

const $ = (id) => document.getElementById(id)
const meta = (name) => document.querySelector(`meta[name="${name}"]`).content
// SPEC §8: the rp ID and the exact origin are deployment configuration, compared exactly. Served under any other
// origin (a hosting platform's default domain, an alias), the page would make roots for the wrong rp ID: it does nothing.
const rpId = meta('muid-rp-id')
const ORIGIN = meta('muid-origin')
const KEY = 'muid.root'
const WITNESS = meta('muid-witness')
const WITNESS_KEYS = JSON.parse(meta('muid-witness-keys'))

// The stored root, as storage holds it now: none is null; unreadable, or not of a root's form, forgotten.
function load () {
  try { return storedRoot(JSON.parse(localStorage.getItem(KEY)), rpId) } catch { return null }
}
let root = load()
const pending = { delegation: null, change: null, cosign: null }

function save () {
  try { localStorage.setItem(KEY, JSON.stringify(root)) } catch { /* kept for this visit only */ }
}

// SPEC §8: root registration and every root-signed action happen in a top-level window. The deployment's headers
// refuse framing; framed anyway, the page shows nothing to act on.
const FRAMED = window.top !== window.self
const REFUSAL = FRAMED ? 'This page acts only in its own window: open it directly.'
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

// One user-verified assertion by this identity's own passkey over the records in `covers` (W1).
async function sign (covers) {
  const a = await navigator.credentials.get({ publicKey: {
    rpId, challenge: challenge(covers), userVerification: 'required',
    allowCredentials: [{ type: 'public-key', id: fromB64u(root.credential) }],
  } })
  return assertion(covers, a.response)
}

function withdraw () {
  pending.delegation = null
  pending.change = null
  pending.cosign = null
  for (const id of ['review-panel', 'handoff', 'add-panel', 'add-handoff', 'cosign-panel']) $(id).hidden = true
  $('error').textContent = ''
}

async function create (joining) {
  withdraw()
  // Another tab may have made one since this page loaded: it is adopted, never overwritten.
  const now = load()
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
    root = { ...r, credential: b64u(c.rawId), joining, registered: false }
    save()
    show()
  } catch (e) { fail(e); return }
  if (!joining) await register()
}

// A root of its own identity not yet known to be registered with the witness (one stored before this was kept,
// too): registered by sending the same root again, which the witness accepts if it already holds it.
const unregistered = () => root !== null && root.joining !== true && root.registered !== true

async function register () {
  try {
    await submit(root.identity, 'root', root.text)
    root = { ...root, registered: true }
    save()
    show()
    $('status').textContent = 'Registered with the witness.'
  } catch (e) { fail(e) }
}

$('create-button').addEventListener('click', () => create(false))
$('register-retry').addEventListener('click', () => { $('error').textContent = ''; register() })
$('join-button').addEventListener('click', () => create(true))
for (const id of ['subject', 'aud', 'scopes', 'days', 'new-root', 'cosign-payload']) $(id).addEventListener('input', withdraw)

$('review').addEventListener('click', async () => {
  withdraw()
  try {
    const s = await state()
    if (!s.authority.includes(root.id)) throw new Error('this passkey has no authority yet: wait for the change to settle')
    const d = delegation({
      identity: root.identity, membership: s.membership, root: root.id, subject: $('subject').value.trim(),
      aud: $('aud').value.trim(), scopes: $('scopes').value.trim().split(/\s+/),
      now: Math.floor(Date.now() / 1000), lifetime: Math.round(Number($('days').value) * 86_400),
    })
    pending.delegation = d
    $('show-aud').textContent = d.body.aud
    $('show-scopes').textContent = d.body.scopes.join(' ')
    $('show-exp').textContent = new Date(d.body.exp * 1000).toISOString()
    $('show-subject').textContent = d.body.subject
    $('review-panel').hidden = false
  } catch (e) { fail(e) }
})

$('sign').addEventListener('click', async () => {
  const d = pending.delegation
  if (d === null) return
  $('error').textContent = ''
  try {
    const a = await sign([d.id])
    if (pending.delegation !== d) return // withdrawn while the passkey was asked
    $('handoff').value = handOff(d.payload, a)
    $('handoff').hidden = false
  } catch (e) { fail(e) }
})

$('add-review').addEventListener('click', async () => {
  withdraw()
  try {
    const c = addRoot({ identity: root.identity, state: await state(), root: $('new-root').value.trim(), rpId })
    pending.change = { ...c, rootText: $('new-root').value.trim() }
    $('add-added').textContent = c.added
    $('add-fingerprint').textContent = fingerprint(c.added)
    $('add-epoch').textContent = String(c.body.epoch)
    $('add-panel').hidden = false
  } catch (e) { fail(e) }
})

$('add-sign').addEventListener('click', async () => {
  const c = pending.change
  if (c === null) return
  $('error').textContent = ''
  try {
    const a = await sign([c.id])
    if (pending.change !== c) return
    await submit(root.identity, 'membership', rootSigned(c.payload, root.id, a))
    await submit(root.identity, 'root', c.rootText)
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
    root = { ...root, cosigned: rootSigned(c.payload, root.id, a) }
    save()
    show()
  } catch (e) { fail(e); return }
  await cosign()
})

// The kept co-signature, sent (again: the witness accepts one it already holds); once taken, this root is the
// identity's.
async function cosign () {
  try {
    const identity = cosignedIdentity(root.cosigned, root.id)
    await submit(identity, 'membership', root.cosigned)
    const { cosigned, ...rest } = root
    root = { ...rest, identity, joining: false, registered: true }
    save()
    show()
    $('status').textContent = 'Co-signed. The change settles once its contest window has passed.'
  } catch (e) { fail(e) }
}
$('cosign-retry').addEventListener('click', () => { $('error').textContent = ''; cosign() })

// What another tab of this origin stores is followed here, so a page open since before cannot act on a stale root.
window.addEventListener('storage', (e) => { if (e.key === KEY || e.key === null) { root = load(); withdraw(); show() } })
show()
// What is kept to be sent (an outbox) is sent again on load, never where the page refuses to act.
if (REFUSAL === undefined) {
  if (unregistered()) register()
  if (root?.cosigned !== undefined) cosign()
}
