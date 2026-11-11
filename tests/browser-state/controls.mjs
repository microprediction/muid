// Non-vacuity and host contract controls. These must pass before a search can
// count a missing handoff or suppressed UI action as a successful defence.
import assert from 'node:assert/strict'
import { Host, WORKERS, worker } from './harness.mjs'
import { operations, run, History } from './histories.mjs'
import { readFile } from 'node:fs/promises'
import { dir } from '../id/impl.mjs'

export async function controls() {
  for (const [name, output] of [['authorise', 'handoff'], ['renew', 'renew-handoffs'], ['add', 'add-handoff']]) {
    const h = await run(operations()[name])
    assert.deepEqual(h.failures, [], `${name}: the ordinary workflow must remain possible`)
    assert.equal(h.host.tabs[0].$(output).hidden, false, `${name}: a workflow which does nothing is not a passing control`)
  }
  const host = new Host()
  await host.open(0); await host.open(1)
  const tab = host.tabs[0]
  await host.click(0, 'review', 'review-worker', {}, true)
  assert.equal(tab.$('review-panel').hidden, true, 'the witness response is actually held')
  assert.equal(host.requests.filter(r => !r.done).length, 1)
  await host.resolve(tab, 'witness')
  assert.equal(tab.$('review-panel').hidden, false)
  await host.click(0, 'sign', 'sign-worker')
  assert.equal(tab.$('handoff').hidden, true, 'the signature completion is actually held')
  await host.resolve(tab, 'signature')
  assert.equal(tab.$('handoff').hidden, false)
  assert.equal(host.verify(tab.$('handoff').value).ok, true, 'handoffs contain actual core-accepted signatures')
  assert.equal(host.tabs[1].$('workers').querySelectorAll('code')[0].textContent, worker(1).subject, 'a write does not synchronously refresh another tab')
  assert.equal(host.notifications.length, 1, 'the writing document receives no storage event of its own')
  await host.deliver(1)
  assert.ok(host.tabs[1].$('workers').querySelectorAll('code').some(e => e.textContent === worker(2).subject))
  const saved = host.values.get(WORKERS)
  host.failWrite = true
  await host.forget(0, 0)
  assert.equal(host.values.get(WORKERS), saved, 'a failed setItem is atomic and leaves persisted storage unchanged')
  assert.equal(host.notifications.length, 0, 'a failed write emits no storage notification')
  const notified = await run([
    ...operations(0).authorise, { type: 'deliver', tab: 1 }, ...operations(1).forgetOther,
  ])
  assert.deepEqual(notified.failures, [], 'the oracle must accept a non-stale cross-tab Forget')
  const cancelled = await run([
    { type: 'review', family: 'worker', tab: 0 }, ...operations(0).editScope,
    { type: 'reply', kind: 'witness', tab: 0 }, { type: 'sign', family: 'worker', tab: 0 },
  ])
  assert.deepEqual(cancelled.failures, [], 'a correctly discarded worker-review completion is accepted')
  const selected = await run([
    ...operations(0).untick, ...operations(0).forgetOther, ...operations(0).retick, ...operations(0).renew,
  ])
  assert.deepEqual(selected.failures, [], 'selection survives redraw and a deliberately reticked worker can be renewed')
  const subset = await run([...operations(0).untick, ...operations(0).renew])
  assert.deepEqual(subset.failures, [], 'the reviewed and signed batch contains precisely the selected worker')
  console.log('Host controls: ordinary workflows, core signatures, delayed effects and atomic write failure passed')
}

export async function freshReadRepairControl() {
  // Historical calibration only: test an attractive but insufficient repair to
  // PR #71's implementation. A real lock/transaction must protect read + write.
  const source = await readFile(new URL('page.js', dir), 'utf8')
  const target = 'workers = change(workers)'
  assert.equal(source.split(target).length, 2, 'update this historical repair control when the storage implementation changes')
  const h = await new History({ source: source.replace(target, 'workers = change(loadWorkers())') }).open()
  let interleaved = false
  h.host.afterRead = { tab: 0, key: WORKERS, run() {
    interleaved = true
    h.trace.push({ type: 'forget', tab: 1, row: 1, after: 'tab 0 storage read' })
    h.host.forgetNow(1, 1)
  } }
  await h.step({ type: 'forget', tab: 0, row: 0 })
  assert.equal(interleaved, true, 'the second writer actually ran between the first read and write')
  assert.ok(h.failures.some(f => f.contract === 'storage-history'))
  console.log('Repair control: fresh-read-before-write still loses an update under a cross-agent read/write interleaving')
}
