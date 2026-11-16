// The package's public surface is what package.json's `exports` names, and nothing else: each entry and every name
// it exports is listed here, so a name cannot be added, renamed or removed without this file saying so.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

const pkg = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8'))

const SURFACE = {
  './verifier': ['verifier'],
  './receipt': ['verifyReceipt'],
  './checkpoint': ['verifyCheckpoint', 'verifyNote'],
  './merkle': ['leafHash', 'verifyConsistency', 'verifyInclusion'],
  './envelope': ['EnvelopeError', 'MAX_PAYLOAD', 'open', 'seal', 'signedBytes', 'wrap'],
  './encoding': ['EncodingError', 'MAX_BYTES', 'MAX_DEPTH', 'decode', 'encode'],
  './origin': ['isCanonicalOrigin'],
  './root': ['agentIdOf', 'checkRoot', 'identityOf', 'rootIdOf'],
  './ed25519': ['checkEd25519', 'checkEd25519Key'],
  './adapter': ['relyingParty'],
  './adapter/stores': ['memoryStore', 'sqliteStore'],
  './witness': ['witness'],
  './witness/service': ['memoryHoldings', 'memoryLog', 'serial', 'witnessService'],
  './witness/holdings': ['sqliteHoldings'],
  './witness/log': ['tesseraLog', 'tileIndex'],
}

test('the entries are these, each a file of the package, and no path outside them resolves', async () => {
  assert.deepEqual(Object.keys(pkg.exports), Object.keys(SURFACE))
  for (const target of Object.values(pkg.exports)) assert.match(target, /^\.\/(src|adapter|witness)\/[a-z0-9-]+\.js$/)
  await assert.rejects(import(pkg.name + '/src/verifier.js'), { code: 'ERR_PACKAGE_PATH_NOT_EXPORTED' })
  await assert.rejects(import(pkg.name), { code: 'ERR_PACKAGE_PATH_NOT_EXPORTED' })
})

test('each entry, imported by the package\'s name as a consumer does, exports exactly its names', async () => {
  for (const [entry, names] of Object.entries(SURFACE)) {
    const m = await import(pkg.name + entry.slice(1))
    assert.deepEqual(Object.keys(m).sort(), names, entry)
  }
})
