// SPEC §7: the page touches browser storage through its one adapter. A read then a write of web storage is not one
// step between a browser's tabs, so nothing else in id/ may name a storage API at all.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync } from 'node:fs'

const DIR = new URL('../../id/', import.meta.url)
const ADAPTER = 'store.js'
const STORAGE = /\b(?:indexedDB|localStorage|sessionStorage|IDB[A-Z]\w*|caches|cookie)\b/
// Comments and string contents are not code.
const codeOnly = (text) => text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\n]*/g, '').replace(/(['"`])(?:\\.|(?!\1)[^\\])*\1/g, '""')

test('only the storage adapter names a browser storage API', () => {
  const files = readdirSync(DIR).filter((f) => f.endsWith('.js') || f.endsWith('.html'))
  assert.ok(files.includes(ADAPTER) && files.includes('page.js'))
  for (const f of files.filter((f) => f !== ADAPTER)) {
    const found = STORAGE.exec(codeOnly(readFileSync(new URL(f, DIR), 'utf8')))
    assert.equal(found, null, `id/${f} names ${found?.[0]}`)
  }
  assert.match(codeOnly(readFileSync(new URL(ADAPTER, DIR), 'utf8')), /\bindexedDB\b/, 'the adapter is where it is used')
  assert.doesNotMatch(codeOnly(readFileSync(new URL(ADAPTER, DIR), 'utf8')), /\b(?:localStorage|sessionStorage)\b/, 'and web storage nowhere')
})

test('the check fires on each API, and not on comments or strings', () => {
  for (const use of ['localStorage.getItem(k)', 'window.sessionStorage', 'indexedDB.open(n)', 'new IDBKeyRange()', 'caches.open(n)', 'document.cookie']) {
    assert.match(codeOnly(`const x = ${use}`), STORAGE, use)
    assert.doesNotMatch(codeOnly(`// ${use}\n/* ${use} */\nconst s = '${use}'`), STORAGE, use)
  }
})
