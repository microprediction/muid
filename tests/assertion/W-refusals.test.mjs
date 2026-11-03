// W0–W6: starting from a valid assertion, one field changed at a time; each refusal carries its reason.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { make, result, rejects, clientData, challengeFor, authData, b64u, sha256, RECORD, CTX, FLAGS, ORIGIN, KEY } from './helpers.mjs'

const ok = make()

test('the base case is accepted', () => assert.deepEqual(result(ok), { ok: true }))

test('assertion-shape: not an object with exactly the four keys and the right types', () => {
  for (const sig of [undefined, null, 'x', 1, [], [ok]]) rejects(sig, 'assertion-shape', String(sig))
  const { covers, ...three } = ok
  rejects(three, 'assertion-shape', 'missing covers')
  rejects({ ...ok, extra: 1 }, 'assertion-shape', 'extra key')
  rejects({ ...ok, covers: RECORD }, 'assertion-shape', 'covers not an array')
  for (const k of ['authenticator_data', 'client_data_json', 'signature']) {
    rejects({ ...ok, [k]: 1 }, 'assertion-shape', `${k} not a string`)
    rejects({ ...ok, [k]: [ok[k]] }, 'assertion-shape', `${k} an array`)
  }
  rejects(Object.assign(Object.create({ covers: [RECORD] }), { ...three }), 'assertion-shape', 'inherited covers')
})

test('covers (W0): 1–8 sorted, distinct, lowercase 64-hex ids including the record', () => {
  const id = (c) => c.repeat(64)
  const bad = [
    ['empty', []],
    ['nine', Array.from({ length: 9 }, (_, i) => String(i).repeat(64)).map((x) => x === RECORD ? id('b') : x).sort()],
    ['unsorted', [RECORD, id('0')]],
    ['duplicate', [RECORD, RECORD]],
    ['uppercase', [RECORD.toUpperCase()]],
    ['short id', [RECORD, 'b'.repeat(63)].sort()],
    ['non-string id', [RECORD, 1]],
    ['record missing', [id('b')]],
    ['sparse', Object.assign([RECORD], { length: 2 })],
  ]
  for (const [name, covers] of bad) rejects({ ...ok, covers }, 'covers', name)
})

test('a record outside covers cannot reuse the assertion', () => {
  const other = make({ covers: ['b'.repeat(64)] })
  rejects(other, 'covers', 'replayed onto another record')
})

test('assertion-encoding: each field must be canonical unpadded base64url', () => {
  for (const k of ['authenticator_data', 'client_data_json', 'signature']) {
    const v = ok[k]
    for (const [name, w] of [['padded', v + '='.repeat((4 - v.length % 4) % 4 || 4)], ['standard alphabet', v.replace(/-/g, '+').replace(/_/g, '/') + (/[-_]/.test(v) ? '' : '+')],
      ['length 1 mod 4', v + 'A'.repeat((1 - v.length % 4 + 4) % 4 || 4)], ['space', v + ' '], ['empty', '']]) {
      if (w === v) continue
      rejects({ ...ok, [k]: w }, 'assertion-encoding', `${k} ${name}`)
    }
  }
  // Non-zero trailing bits: the last character of a 2-byte value encodes 2 unused bits.
  const two = b64u(Buffer.from([1, 2]))
  assert.equal(two.length, 3)
  const nonCanonical = two.slice(0, 2) + String.fromCharCode(two.charCodeAt(2) + 1)
  rejects({ ...ok, signature: nonCanonical }, 'assertion-encoding', 'trailing bits')
})

test('assertion-encoding: client data that is not UTF-8', () => {
  const covers = [RECORD]
  const json = clientData({ challenge: challengeFor(covers) })
  const bytes = Buffer.concat([Buffer.from(json.slice(0, -1)), Buffer.from([0x2c, 0x22, 0xff, 0x22, 0x3a, 0x31, 0x7d])])
  rejects(make({ cdjBytes: bytes }), 'assertion-encoding', 'invalid UTF-8')
})

test('client-data (W1): the prefix, one JSON object, no disagreeing duplicate, no topOrigin', () => {
  const ch = challengeFor([RECORD])
  const cases = [
    ['create', clientData({ type: 'webauthn.create', challenge: ch })],
    ['crossOrigin true', clientData({ challenge: ch, crossOrigin: 'true' })],
    ['crossOrigin absent', `{"type":"webauthn.get","challenge":"${ch}","origin":"${ORIGIN}"}`],
    ['keys reordered', `{"challenge":"${ch}","type":"webauthn.get","origin":"${ORIGIN}","crossOrigin":false}`],
    ['space after colon', `{"type": "webauthn.get","challenge":"${ch}","origin":"${ORIGIN}","crossOrigin":false}`],
    ['topOrigin', clientData({ challenge: ch, tail: ',"topOrigin":"https://evil.example"' })],
    ['later type disagrees', clientData({ challenge: ch, tail: ',"type":"webauthn.create"' })],
    ['later origin disagrees', clientData({ challenge: ch, tail: `,"origin":"https://evil.example"` })],
    ['later crossOrigin disagrees', clientData({ challenge: ch, tail: ',"crossOrigin":true' })],
    ['trailing bytes after the object', clientData({ challenge: ch }) + ' '],
    ['two objects', clientData({ challenge: ch }) + '{}'],
    ['not closed', clientData({ challenge: ch }).slice(0, -1)],
    ['bad tail', clientData({ challenge: ch, tail: ',x' })],
    ['crossOrigin false then garbage', clientData({ challenge: ch }).slice(0, -1) + 'x}'],
  ]
  for (const [name, cdj] of cases) rejects(make({ cdj }), 'client-data', name)
})

test('client-data: a later duplicate that agrees is harmless', () => {
  const ch = challengeFor([RECORD])
  assert.deepEqual(result(make({ cdj: clientData({ challenge: ch, tail: ',"type":"webauthn.get"' }) })), { ok: true })
})

test('challenge (W1): from another record set, from the signed-bytes prefix, or altered', () => {
  const covers = [RECORD]
  for (const [name, ch] of [
    ['other covers', challengeFor(['b'.repeat(64)])],
    ['signed-bytes prefix', challengeFor(covers, 'muid/v1\n')],
    ['no trailing newline', b64u(sha256('muid/v1/assert\n' + RECORD))],
    ['padded', challengeFor(covers) + '='],
    ['empty', ''],
  ]) {
    rejects(make({ covers, cdj: clientData({ challenge: ch }) }), 'challenge', name)
  }
})

test('origin (W1): exact string equality', () => {
  const ch = challengeFor([RECORD])
  for (const origin of [ORIGIN + '/', ORIGIN + ':443', 'http://id.example', 'https://ID.example', 'https://evil.id.example',
    'https://id.example.evil', 'https://id.exampl']) {
    rejects(make({ cdj: clientData({ challenge: ch, origin }) }), 'origin', origin)
  }
})

test('authenticator data (W2): length, rp id, UP, UV, flags', () => {
  rejects(make({ ad: authData().subarray(0, 36) }), 'auth-data-length', 'short')
  rejects(make({ ad: authData({ extra: Buffer.from([0]) }) }), 'auth-data-length', 'trailing byte')
  rejects(make({ ad: authData({ flags: 0x1d | FLAGS.ED, extra: Buffer.from([0xa0]) }) }), 'auth-data-length', 'extensions')
  for (const rpId of ['example', 'evil.id.example', 'id.example.', 'ID.example']) {
    rejects(make({ ad: authData({ rpId }) }), 'rp-id', rpId)
  }
  rejects(make({ ad: authData({ flags: FLAGS.UV }) }), 'user-presence', 'no UP')
  rejects(make({ ad: authData({ flags: FLAGS.UP }) }), 'user-verification', 'no UV')
  for (const [name, bit] of [['AT', FLAGS.AT], ['ED', FLAGS.ED], ['RFU1', FLAGS.RFU1], ['RFU2', FLAGS.RFU2]]) {
    rejects(make({ ad: authData({ flags: FLAGS.UP | FLAGS.UV | bit }) }), 'auth-data-flags', name)
  }
  rejects(make({ ad: authData({ flags: FLAGS.UP | FLAGS.UV | FLAGS.BS }) }), 'auth-data-flags', 'BS without BE')
})

test('every single flag bit changed from the base flags gives a refusal or an accept a passkey can produce', () => {
  for (let bit = 0; bit < 8; bit++) {
    const flags = 0x1d ^ (1 << bit)
    const r = result(make({ ad: authData({ flags }) }))
    const acceptable = (flags & 0xe2) === 0 && (flags & 0x05) === 0x05 && (!(flags & 0x10) || (flags & 0x08))
    assert.equal(r.ok, acceptable, `flags ${flags.toString(16)}: ${JSON.stringify(r)}`)
  }
})

test('the signature (K6): another key, another message, a flipped byte', () => {
  rejects(make({ secret: Uint8Array.from({ length: 32 }, (_, i) => i + 1) }), 'sig-invalid', 'another key')
  const s = Buffer.from(ok.signature, 'base64url'); s[s.length - 1] ^= 1
  rejects({ ...ok, signature: b64u(s) }, 'sig-invalid', 'flipped byte')
  rejects({ ...ok, signature: b64u(Buffer.from([0x30, 0x00])) }, 'sig-encoding', 'empty DER')
  rejects(ok, 'key-encoding', 'bad key', { ...CTX, key: KEY.slice(2) })
  rejects(ok, 'key-point', 'off curve', { ...CTX, key: '04' + '00'.repeat(64) })
})

test('a context that is not four strings is a programming error', () => {
  for (const ctx of [undefined, null, {}, { ...CTX, rpId: 1 }, { ...CTX, origin: undefined }, { ...CTX, record: [] }]) {
    assert.throws(() => result(ok, ctx), TypeError)
  }
})
