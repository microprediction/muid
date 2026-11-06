// The id page (SPEC §8): create an identity with a passkey and register its root with the witness; add a passkey on
// another device (a membership change, R1: signed here, co-signed there); and authorise a worker's key by one
// assertion, under the identity's current membership. Every record the passkey signs is shown first from its exact
// payload (I4); changing any input withdraws it, and a signature that returns after an edit is discarded. The root
// record and the credential id are kept in this browser only.
import { rootRecord, challenge, assertion, delegation, handOff, b64u, fromB64u, currentMembership, addRoot, rootSigned, changeToSign } from './records.js'

const $ = (id) => document.getElementById(id)
const meta = (name) => document.querySelector(`meta[name="${name}"]`).content
const rpId = location.hostname
const KEY = 'muid.root'
const WITNESS = meta('muid-witness')
const WITNESS_KEYS = JSON.parse(meta('muid-witness-keys'))

let root
try { root = JSON.parse(localStorage.getItem(KEY)) } catch { root = null } // none is null; unreadable, forgotten
const pending = { delegation: null, change: null, cosign: null }

function save () {
  try { localStorage.setItem(KEY, JSON.stringify(root)) } catch { /* kept for this visit only */ }
}

function show () {
  const joining = root?.joining === true
  $('create').hidden = root !== null
  $('joining').hidden = !joining
  $('identity').hidden = root === null || joining
  $('add-root').hidden = root === null || joining
  $('authorise').hidden = root === null || joining
  $('pending').hidden = !unregistered()
  if (root !== null) {
    $('identity-id').textContent = root.identity
    $('root-text').value = root.text
    $('join-root').value = root.text
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
  return currentMembership(records, { identity: root.identity, rpId, origin: location.origin, witnessKeys: WITNESS_KEYS })
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
    await submit(c.body.identity, 'membership', rootSigned(c.payload, root.id, a))
    root = { ...root, identity: c.body.identity, joining: false, registered: true }
    save()
    show()
    $('status').textContent = 'Co-signed. The change settles once its contest window has passed.'
  } catch (e) { fail(e) }
})

show()
if (unregistered()) register()
