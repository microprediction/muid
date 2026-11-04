// The id page (SPEC §8): create an identity with a passkey, and authorise a worker's key by one assertion. The page
// shows the delegation's fields from the exact payload the passkey will sign (I4); changing any input withdraws it.
// The root record and the credential id are kept in this browser only.
import { rootRecord, challenge, assertion, delegation, handOff, b64u, fromB64u } from './records.js'

const $ = (id) => document.getElementById(id)
const rpId = location.hostname
const KEY = 'muid.root'

let root
try { root = JSON.parse(localStorage.getItem(KEY)) } catch { root = null } // none is null; unreadable, forgotten
let pending = null

function show () {
  $('create').hidden = root !== null
  $('identity').hidden = root === null
  $('authorise').hidden = root === null
  if (root !== null) {
    $('identity-id').textContent = root.identity
    $('root-text').value = root.text
  }
}

function fail (e) {
  $('error').textContent = e.name === 'NotAllowedError' ? 'The passkey request was cancelled.' : e.message
}

function withdraw () {
  pending = null
  $('review-panel').hidden = true
  $('handoff').hidden = true
  $('error').textContent = ''
}

$('create-button').addEventListener('click', async () => {
  $('error').textContent = ''
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
    root = { ...r, credential: b64u(c.rawId) }
    try { localStorage.setItem(KEY, JSON.stringify(root)) } catch { /* kept for this visit only */ }
    show()
  } catch (e) { fail(e) }
})

for (const id of ['subject', 'aud', 'scopes', 'days']) $(id).addEventListener('input', withdraw)

$('review').addEventListener('click', () => {
  withdraw()
  try {
    pending = delegation({
      identity: root.identity, membership: root.identity, root: root.id, subject: $('subject').value.trim(),
      aud: $('aud').value.trim(), scopes: $('scopes').value.trim().split(/\s+/),
      now: Math.floor(Date.now() / 1000), lifetime: Math.round(Number($('days').value) * 86_400),
    })
    $('show-aud').textContent = pending.body.aud
    $('show-scopes').textContent = pending.body.scopes.join(' ')
    $('show-exp').textContent = new Date(pending.body.exp * 1000).toISOString()
    $('show-subject').textContent = pending.body.subject
    $('review-panel').hidden = false
  } catch (e) { fail(e) }
})

$('sign').addEventListener('click', async () => {
  const d = pending
  if (d === null) return
  $('error').textContent = ''
  try {
    const a = await navigator.credentials.get({ publicKey: {
      rpId, challenge: challenge([d.id]), userVerification: 'required',
      allowCredentials: [{ type: 'public-key', id: fromB64u(root.credential) }],
    } })
    if (pending !== d) return // withdrawn while the passkey was asked
    $('handoff').value = handOff(d.payload, assertion([d.id], a.response))
    $('handoff').hidden = false
  } catch (e) { fail(e) }
})

show()
