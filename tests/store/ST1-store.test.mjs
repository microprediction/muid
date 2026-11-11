// The page's storage adapter (SPEC §7) in Chrome: IndexedDB behind `get` and a transactional `update`. Two tabs of
// one browser share the database; what is proved here is what the Indexed Database standard states: read-write
// transactions on one object store run one at a time, in the order made, and each commits whole or not at all.
import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import { chromium } from 'playwright-core'
import { serve } from '../id/serve.mjs'
import { activate, handBack } from '../id/mutant.mjs'

const opened = new Set()
after(async () => { await Promise.all([...opened].map((end) => end())) })

// A site serving id/, and a browser with one tab on it; `tab()` opens another, sharing its storage.
async function open () {
  const site = await serve()
  const browser = await chromium.launch({ channel: 'chrome', headless: true })
  const pages = []
  const end = async () => { opened.delete(end); await handBack(pages); await browser.close(); site.close() }
  opened.add(end)
  const context = await browser.newContext()
  await activate(context)
  const problems = []
  const tab = async () => {
    const page = await context.newPage()
    pages.push(page)
    page.on('pageerror', (e) => problems.push(String(e)))
    await page.goto(site.origin + '/id/store.js')
    // Each tab keeps its stores by name; `s(name)` opens one once.
    await page.evaluate(async () => {
      const { openStore } = await import('/id/store.js')
      const stores = new Map()
      globalThis.s = async (name) => { if (!stores.has(name)) stores.set(name, await openStore(name)); return stores.get(name) }
      globalThis.openStore = openStore
    })
    return page
  }
  return { page: await tab(), tab, problems, close: end }
}
let n = 0
const fresh = () => `t${process.pid}-${n++}`
const get = (page, db, key) => page.evaluate(async ([db, key]) => (await globalThis.s(db)).get(key), [db, key])
// `update` with the change written as source text, since a function does not cross into the page.
const update = (page, db, key, change) => page.evaluate(async ([db, key, change]) => {
  // eslint-disable-next-line no-new-func
  try { return await (await globalThis.s(db)).update(key, new Function('now', change)) } catch (e) { return { threw: e.name, message: e.message } }
}, [db, key, change])

test('get and update: absent until set; a value is replaced or removed; undefined leaves it; all of it kept across tabs and reloads', { timeout: 120_000 }, async () => {
  const t = await open()
  try {
    const db = fresh()
    assert.deepEqual(await get(t.page, db, 'k'), { absent: true })
    assert.deepEqual(await update(t.page, db, 'k', 'return now.absent ? { value: { list: [1, "a", { b: null }] } } : undefined'), { value: { list: [1, 'a', { b: null }] } })
    assert.deepEqual(await get(t.page, db, 'k'), { value: { list: [1, 'a', { b: null }] } })
    assert.deepEqual(await get(t.page, db, 'other'), { absent: true }, 'keys are separate')
    // The change is given what is stored, and its answer is what is stored after.
    assert.deepEqual(await update(t.page, db, 'k', 'return { value: now.value.list.length }'), { value: 3 })
    assert.deepEqual(await update(t.page, db, 'k', 'return undefined'), { value: 3 }, 'undefined: left as it is')
    assert.deepEqual(await update(t.page, db, 'k', 'return { value: undefined }'), { value: undefined }, 'a stored undefined is a value')
    assert.deepEqual(await get(t.page, db, 'k'), { value: undefined })
    assert.deepEqual(await update(t.page, db, 'k', 'return { value: 0 }'), { value: 0 })
    // Another tab reads what was committed; a reload keeps it.
    const other = await t.tab()
    assert.deepEqual(await get(other, db, 'k'), { value: 0 })
    assert.deepEqual(await update(other, db, 'k', 'return { absent: true }'), { absent: true })
    assert.deepEqual(await get(t.page, db, 'k'), { absent: true })
    assert.deepEqual(await update(other, db, 'k', 'return now.absent ? undefined : { value: 1 }'), { absent: true }, 'undefined: left absent')
    assert.deepEqual(await update(other, db, 'j', 'return { value: "kept" }'), { value: 'kept' })
    await other.close()
    const again = await t.tab()
    assert.deepEqual(await get(again, db, 'j'), { value: 'kept' })
    assert.deepEqual(await get(again, db, 'k'), { absent: true })
    // A database of another name is another store.
    assert.deepEqual(await get(again, fresh(), 'j'), { absent: true })
    assert.deepEqual(t.problems, [])
  } finally {
    await t.close()
  }
})

test('update is one transaction: tabs changing one key at once lose nothing, and a change waits for a transaction before it', { timeout: 120_000 }, async () => {
  const t = await open()
  try {
    const db = fresh()
    const other = await t.tab()
    // 150 increments from each of two tabs, all begun before any has finished.
    const burst = (page) => page.evaluate(async (db) => {
      const s = await globalThis.s(db)
      await Promise.all(Array.from({ length: 150 }, () => s.update('count', (now) => ({ value: (now.absent ? 0 : now.value) + 1 }))))
    }, db)
    await get(t.page, db, 'count')
    await get(other, db, 'count')
    await Promise.all([burst(t.page), burst(other)])
    assert.deepEqual(await get(t.page, db, 'count'), { value: 300 })
    // One tab holds a read-write transaction of its own on the store open; the other's update is made only once that
    // transaction has finished, and is given what it wrote.
    await t.page.evaluate((db) => new Promise((resolve, reject) => {
      const r = indexedDB.open(db)
      r.onerror = () => reject(r.error)
      r.onsuccess = () => {
        const tx = r.result.transaction('values', 'readwrite')
        const store = tx.objectStore('values')
        globalThis.finished = new Promise((resolve) => { tx.oncomplete = () => { r.result.close(); resolve() } })
        globalThis.holding = true
        // Kept alive by one request after another until told to finish, then a last write.
        const spin = () => { if (globalThis.holding) store.get('count').onsuccess = spin; else store.put({ value: 'held' }, 'count') }
        spin()
        resolve()
      }
    }), db)
    await other.evaluate((db) => { globalThis.late = globalThis.s(db).then((s) => s.update('count', (now) => ({ value: [now.value, 'after'] }))); globalThis.late.then(() => { globalThis.done = true }) }, db)
    await other.waitForTimeout(500)
    assert.equal(await other.evaluate(() => globalThis.done === true), false, 'not made while the other transaction is open')
    await t.page.evaluate(() => { globalThis.holding = false; return globalThis.finished })
    assert.deepEqual(await other.evaluate(() => globalThis.late), { value: ['held', 'after'] })
    assert.deepEqual(await get(t.page, db, 'count'), { value: ['held', 'after'] })
    assert.deepEqual(t.problems, [])
  } finally {
    await t.close()
  }
})

test('an update that fails changes nothing and says so; a read that fails is not an absence', { timeout: 120_000 }, async () => {
  const t = await open()
  try {
    const db = fresh()
    await update(t.page, db, 'k', 'return { value: "first" }')
    // The change throws: its error is the update's, and nothing is written.
    assert.deepEqual(await update(t.page, db, 'k', 'throw new RangeError("no")'), { threw: 'RangeError', message: 'no' })
    // The change answers with something that is neither a value, an absence nor undefined.
    for (const bad of ['return null', 'return {}', 'return { value: 1, absent: true }', 'return { absent: false }', 'return { absent: 1 }', 'return 7', 'return Promise.resolve({ value: 2 })', 'return { value: 1, extra: 2 }', 'return Object.assign(() => {}, { value: 3 })']) {
      assert.deepEqual(await update(t.page, db, 'k', bad), { threw: 'TypeError', message: 'a change gives { value }, { absent: true } or undefined' }, bad)
    }
    // A value that cannot be stored.
    assert.equal((await update(t.page, db, 'k', 'return { value: () => 1 }')).threw, 'DataCloneError')
    assert.deepEqual(await get(t.page, db, 'k'), { value: 'first' }, 'as it was')
    // After a failed update, the next is made.
    assert.deepEqual(await update(t.page, db, 'k', 'return { value: now.value + "!" }'), { value: 'first!' })
    // Keys are strings, and the change a function.
    for (const key of [1, null, undefined, ['k'], {}]) {
      assert.deepEqual(await t.page.evaluate(async ([db, key]) => { const s = await globalThis.s(db); try { await s.get(key) } catch (e) { return [e.name, e.message] } }, [db, key]), ['TypeError', 'a key is a string'])
      assert.deepEqual(await t.page.evaluate(async ([db, key]) => { const s = await globalThis.s(db); try { await s.update(key, () => ({ value: 1 })) } catch (e) { return [e.name, e.message] } }, [db, key]), ['TypeError', 'a key is a string'])
    }
    assert.deepEqual(await t.page.evaluate(async (db) => { const s = await globalThis.s(db); try { await s.update('k', { value: 1 }) } catch (e) { return [e.name, e.message] } }, db), ['TypeError', 'a change is a function'])
    for (const name of ['', 1, null, undefined]) {
      assert.deepEqual(await t.page.evaluate(async (name) => { try { await globalThis.openStore(name) } catch (e) { return [e.name, e.message] } }, name), ['TypeError', 'a store has a name'])
    }
    // A store that was closed reads nothing: the failure is thrown, never reported as an absent key.
    const closed = await t.page.evaluate(async (db) => {
      const s = await globalThis.openStore(db)
      s.close()
      const out = []
      try { out.push(await s.get('k')) } catch (e) { out.push(e.name) }
      try { out.push(await s.update('k', () => ({ value: 'x' }))) } catch (e) { out.push(e.name) }
      return out
    }, db)
    assert.deepEqual(closed, ['InvalidStateError', 'InvalidStateError'])
    assert.deepEqual(await get(t.page, db, 'k'), { value: 'first!' })
    // A write whose request succeeds and whose transaction then aborts was not made: the update fails, the key is
    // as it was, and no tab is told.
    const other = await t.tab()
    await other.evaluate(async (db) => { globalThis.told = []; (await globalThis.s(db)).watch((key) => globalThis.told.push(key)) }, db)
    const aborted = await t.page.evaluate(async (db) => {
      const s = await globalThis.openStore(db)
      const real = IDBObjectStore.prototype.put
      IDBObjectStore.prototype.put = function (...args) { const r = real.apply(this, args); r.addEventListener('success', () => this.transaction.abort()); return r }
      try { return await s.update('k', () => ({ value: 'never' })) } catch (e) { return [e instanceof Error, e.name, e.message] } finally { IDBObjectStore.prototype.put = real }
    }, db)
    assert.deepEqual(aborted, [true, 'AbortError', 'the transaction was aborted'], 'an abort with no error of its own is still an error')
    assert.deepEqual(await get(t.page, db, 'k'), { value: 'first!' })
    await update(t.page, db, 'after', 'return { value: 1 }')
    await other.waitForFunction(() => globalThis.told.length >= 1)
    assert.deepEqual(await other.evaluate(() => globalThis.told), ['after'], 'not told of the write that was not made')
    // A database that cannot be opened (here, one already at a later version) fails the opening: it does not hang.
    const later = fresh()
    assert.deepEqual(await t.page.evaluate((name) => new Promise((resolve) => {
      const made = indexedDB.open(name, 2)
      made.onsuccess = async () => { made.result.close(); try { await globalThis.openStore(name); resolve('opened') } catch (e) { resolve(e.name) } }
    }), later), 'VersionError')
    // A closed store tells its watchers nothing more.
    const quiet = await other.evaluate(async (db) => {
      const s = await globalThis.openStore(db)
      globalThis.afterClose = []
      s.watch((key) => globalThis.afterClose.push(key))
      s.close()
    }, db)
    assert.equal(quiet, undefined)
    await update(t.page, db, 'closed', 'return { value: 1 }')
    await other.waitForFunction(() => globalThis.told.includes('closed'))
    assert.deepEqual(await other.evaluate(() => globalThis.afterClose), [])
    // A failing request inside a read: the transaction's failure is the get's.
    const failed = await t.page.evaluate(async (db) => {
      const s = await globalThis.openStore(db)
      const real = IDBObjectStore.prototype.get
      IDBObjectStore.prototype.get = function () { this.transaction.abort(); return real.call(this, 'k') }
      try { return await s.get('k') } catch (e) { return e.name } finally { IDBObjectStore.prototype.get = real }
    }, db)
    assert.notDeepEqual(failed, { absent: true })
    assert.equal(typeof failed, 'string')
    assert.deepEqual(t.problems, [])
  } finally {
    await t.close()
  }
})

test('writes are asked to be durable before they are reported; another tab is told of each committed change, not of one that changed nothing', { timeout: 120_000 }, async () => {
  const t = await open()
  try {
    const db = fresh()
    const other = await t.tab()
    await t.page.evaluate(() => {
      const real = IDBDatabase.prototype.transaction
      globalThis.asked = []
      IDBDatabase.prototype.transaction = function (names, mode, options) { globalThis.asked.push([names, mode, options?.durability]); return real.call(this, names, mode, options) }
    })
    await other.evaluate(async (db) => { globalThis.told = []; globalThis.stop = (await globalThis.s(db)).watch((key) => globalThis.told.push(key)) }, db)
    await t.page.evaluate(async (db) => { globalThis.own = []; (await globalThis.s(db)).watch((key) => globalThis.own.push(key)) }, db)
    await update(t.page, db, 'a', 'return { value: 1 }')
    await get(t.page, db, 'a')
    assert.deepEqual(await t.page.evaluate(() => globalThis.asked), [['values', 'readwrite', 'strict'], ['values', 'readonly', undefined]])
    await update(t.page, db, 'b', 'return undefined')
    await update(t.page, db, 'b', 'throw new Error("no")')
    await update(t.page, db, 'b', 'return { value: 2 }')
    await update(t.page, db, 'a', 'return { absent: true }')
    await other.waitForFunction(() => globalThis.told.length >= 3)
    await other.waitForTimeout(200)
    assert.deepEqual(await other.evaluate(() => globalThis.told), ['a', 'b', 'a'])
    assert.deepEqual(await t.page.evaluate(() => globalThis.own), [], 'the tab that made the change is not told of it')
    // A store of another name hears nothing of this one; a watcher that was stopped hears no more.
    const elsewhere = fresh()
    await other.evaluate(async (name) => { globalThis.far = []; (await globalThis.s(name)).watch((key) => globalThis.far.push(key)) }, elsewhere)
    await other.evaluate(() => globalThis.stop())
    await update(t.page, db, 'c', 'return { value: 3 }')
    await update(t.page, elsewhere, 'z', 'return { value: 26 }')
    await other.waitForFunction(() => globalThis.far.length >= 1)
    assert.deepEqual(await other.evaluate(() => [globalThis.told, globalThis.far]), [['a', 'b', 'a'], ['z']])
    assert.deepEqual(t.problems, [])
  } finally {
    await t.close()
  }
})
