// Issue #21's race: several instances (worker threads, one SQLite file) receive the same claim at once, released
// together by a barrier. The single atomic insert lets exactly one run the protected action.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { Worker } from 'node:worker_threads'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { DatabaseSync } from 'node:sqlite'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { urls, sqliteStore } from './impl.mjs'

const WORKER = `
import { workerData, parentPort } from 'node:worker_threads'
const { relyingParty } = await import(workerData.adapter)
const { sqliteStore } = await import(workerData.stores)
const f = await import(workerData.fixtures)
const rp = relyingParty({ verifier: f.verifier(), store: sqliteStore(workerData.file), clock: () => f.NOW })
// A barrier: every instance is loaded and connected before any presents the claim, so they race in earnest.
const count = new Int32Array(workerData.barrier)
Atomics.add(count, 0, 1)
Atomics.notify(count, 0)
while (Atomics.load(count, 0) < workerData.n0) Atomics.wait(count, 0, Atomics.load(count, 0), 1000)
const ran = []
const r = await rp.acceptClaim(f.records(), f.CALL, async () => { ran.push(workerData.n) })
parentPort.postMessage({ ok: r.ok, reason: r.reason, ran: ran.length })
`

test('eight instances sharing one database: one runs the action, seven are refused as replays', async () => {
  const file = join(mkdtempSync(join(tmpdir(), 'muid-rp-')), 'rp.db')
  const url = (p) => new URL(p, import.meta.url).href
  const data = { file, adapter: urls.adapter, stores: urls.stores, fixtures: url('./fixtures.mjs') }
  const barrier = new SharedArrayBuffer(4)
  const results = await Promise.all(Array.from({ length: 8 }, (_, n) => new Promise((resolve, reject) => {
    const w = new Worker(WORKER, { eval: true, type: 'module', workerData: { ...data, n, n0: 8, barrier } })
    w.once('message', resolve)
    w.once('error', reject)
  })))
  assert.equal(results.filter((r) => r.ok).length, 1, JSON.stringify(results))
  assert.equal(results.reduce((n, r) => n + r.ran, 0), 1)
  assert.deepEqual(results.filter((r) => !r.ok).map((r) => r.reason), Array(7).fill('replay'))
})

// Found in CI: instances that open a new database file at the same moment. SQLite does not wait, whatever the busy
// timeout, to switch a file to WAL while another connection writes to it: it answers "database is locked" at once.
// The store asks again until the lock is gone, for no longer than `busy` milliseconds.
const newFile = () => join(mkdtempSync(join(tmpdir(), 'muid-rp-open-')), 'rp.db')

const HOLDER = `
import { workerData, parentPort } from 'node:worker_threads'
import { DatabaseSync } from 'node:sqlite'
const db = new DatabaseSync(workerData.file)
db.exec('BEGIN IMMEDIATE')
parentPort.postMessage('held')
Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, workerData.hold)
db.exec('COMMIT')
db.close()
`

test('a store opened while another connection is writing a new file waits for it, then opens', async () => {
  const file = newFile()
  const w = new Worker(HOLDER, { eval: true, type: 'module', workerData: { file, hold: 300 } })
  await new Promise((resolve, reject) => { w.once('message', resolve); w.once('error', reject) })
  const began = Date.now()
  const store = sqliteStore(file)
  assert.ok(Date.now() - began >= 200, 'it waited for the writer')
  assert.equal(await store.transaction((tx) => tx.consume('a', 1)), true)
  store.close()
})

test('a store waits `busy` milliseconds for a locked new file, and no longer', () => {
  const file = newFile()
  const holder = new DatabaseSync(file)
  holder.exec('BEGIN IMMEDIATE')
  const began = Date.now()
  assert.throws(() => sqliteStore(file, { busy: 300 }), { message: 'database is locked' })
  const waited = Date.now() - began
  assert.ok(waited >= 300 && waited < 5000, `waited ${waited} ms`)
  const none = Date.now()
  assert.throws(() => sqliteStore(file, { busy: 0 }), { message: 'database is locked' })
  assert.ok(Date.now() - none < 250, 'no wait at all')
  holder.exec('COMMIT')
  sqliteStore(file, { busy: 300 }).close()
  holder.close()
})

// Issue #76: the wait is a duration, so it is measured by a clock that only moves forward (performance.now), not by
// the wall clock, which a resumed machine or a corrected time steps either way.
test('the wait for a locked new file is not lengthened or cut short by the wall clock being set back or forward', () => {
  const file = newFile()
  const holder = new DatabaseSync(file)
  holder.exec('BEGIN IMMEDIATE')
  const real = Date.now
  try {
    for (const step of [-3_600_000, 3_600_000]) {
      // The first reading is true; every later one is an hour off. Should the store wait on the wall clock set back,
      // it is let go after some seconds, so that this fails rather than hangs.
      let readings = 0
      Date.now = () => (readings++ === 0 ? real() : readings > 4000 ? real() + 86_400_000 : real() + step)
      const began = performance.now()
      assert.throws(() => sqliteStore(file, { busy: 300 }), { message: 'database is locked' })
      const waited = performance.now() - began
      assert.ok(waited >= 300 && waited < 2500, `clock stepped ${step} ms: waited ${waited} ms`)
    }
  } finally {
    Date.now = real
    holder.exec('COMMIT')
    holder.close()
  }
})

test('a file that is not a database is refused at once, not waited for', () => {
  const file = newFile()
  writeFileSync(file, 'not a database, not at all. '.repeat(40))
  const began = Date.now()
  assert.throws(() => sqliteStore(file, { busy: 5000 }), { message: 'file is not a database' })
  assert.ok(Date.now() - began < 2500)
})

test('busy must be a whole number of milliseconds, zero or more', () => {
  for (const busy of [-1, 1.5, NaN, Infinity, '300', null, 2 ** 53, '0; DROP TABLE heads']) {
    assert.throws(() => sqliteStore(newFile(), { busy }), { name: 'TypeError', message: 'busy must be a number of milliseconds' })
  }
})
