// Issue #21's race: several instances (worker threads, one SQLite file) receive the same claim at once, released
// together by a barrier. The single atomic insert lets exactly one run the protected action.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { Worker } from 'node:worker_threads'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { urls } from './impl.mjs'

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
