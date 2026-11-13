// The witness service's durable holdings (witness/holdings.js): one SQLite file, held by one process. What
// model/tla/WitnessOutbox.tla assumes of the store is checked of it here: an update of one identity at a time, kept
// whole when it ends or not at all, and still there after the process is gone. The in-memory store is its oracle.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { DatabaseSync } from 'node:sqlite'
import fc from 'fast-check'
import { runs } from '../runs.mjs'
import { envelope } from '../impl.mjs'
import { witnessService, memoryHoldings, memoryLog, sqliteHoldings } from './impl.mjs'
import { w, IDENTITY, BASE, WINDOW, M2, mBody, mId, signed, rootText } from './fixtures.mjs'

const CHILD = fileURLToPath(new URL('./holdings-child.mjs', import.meta.url))
const dirs = []
const fresh = () => { const d = mkdtempSync(join(tmpdir(), 'muid-holdings-')); dirs.push(d); return join(d, 'holdings.db') }
test.after(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }) })

function service (holdings, log = memoryLog(), headInterval = 60) {
  let now = BASE
  const svc = witnessService({ witness: w, holdings, log, clock: () => now, headInterval })
  const call = async (method, path, body) => {
    const res = await svc.handle(new Request('https://witness.example' + path, { method, headers: { 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) }))
    return { status: res.status, body: JSON.parse(await res.text()) }
  }
  return { svc, log, call, submit: (type, text) => call('POST', '/v1/records', { identity: IDENTITY, type, text }), at: (t) => { now = t },
    records: async () => (await call('GET', `/v1/identities/${IDENTITY}/records`)).body, head: () => call('GET', `/v1/identities/${IDENTITY}/head`) }
}
// A log that takes an entry and loses its answer, once each time `lose` is set.
function lossy () {
  const inner = memoryLog()
  const log = { lose: false, entries: inner.entries, append: async (t) => { await inner.append(t); if (log.lose) { log.lose = false; throw new Error('answer lost') } } }
  return log
}
// The child process: opens the file, does what `mode` says, and reports each line it prints.
function child (file, mode) {
  const p = spawn(process.execPath, [CHILD, file, mode], { stdio: ['ignore', 'pipe', 'inherit'] })
  let out = ''
  const waiting = []
  p.stdout.on('data', (d) => { out += d; for (const x of [...waiting]) if (out.includes(x.line)) { waiting.splice(waiting.indexOf(x), 1); x.resolve() } })
  return { said: (line) => new Promise((resolve) => { if (out.includes(line)) resolve(); else waiting.push({ line, resolve }) }),
    exited: new Promise((resolve) => p.on('close', (code, signal) => resolve({ code, signal, out }))), kill: () => p.kill('SIGKILL') }
}

test('holdings outlive the process that kept them: records, a cached head, revocations and what a tick settles', async () => {
  const file = fresh()
  let h = sqliteHoldings(file)
  const log = memoryLog()
  let s = service(h, log)
  await s.submit('root', rootText('a'))
  await s.submit('membership', signed('membership', M2, 'a'))
  await s.submit('root', rootText('b'))
  assert.equal((await s.submit('membership', signed('membership', M2, 'b'))).body.signed.length, 1)
  const rev = signed('revocation', { identity: IDENTITY, target: 'e'.repeat(64), at: BASE }, 'a')
  assert.equal((await s.call('POST', '/v1/revocations', { identity: IDENTITY, text: rev })).status, 200)
  const before = await s.records()
  const head = (await s.head()).body.head
  h.close()

  h = sqliteHoldings(file)
  s = service(h, log)
  assert.deepEqual(await h.identities(), [IDENTITY])
  assert.deepEqual(await s.records(), before)
  assert.deepEqual(before.revocations, [rev])
  assert.equal((await s.head()).body.head, head, 'the head signed before is reused, not signed again')
  s.at(BASE + WINDOW)
  const settled = await s.svc.tick()
  assert.equal(settled.length, 1, 'the tick finds the identity and settles it')
  assert.equal(envelope.open(settled[0], 'settlement').body.outcome, mId(M2))
  h.close()

  h = sqliteHoldings(file)
  assert.deepEqual((await service(h, log).records()).settlements, settled)
  h.close()
})

test('a restart with a record signed and its log answer lost: the same text is appended again before a rival is decided', async () => {
  const file = fresh()
  let h = sqliteHoldings(file)
  const log = lossy()
  let s = service(h, log)
  await s.submit('root', rootText('a'))
  const X = mBody(2, ['a'], IDENTITY)
  const Y = mBody(2, ['a', 'b'], IDENTITY)
  log.lose = true
  assert.deepEqual((await s.submit('membership', signed('membership', X, 'a'))).body, { ok: false, reason: 'log' })
  assert.equal(log.entries().length, 1, 'the log has the anchor of X')
  assert.notEqual((await h.get(IDENTITY)).outbox, undefined, 'and it waits in the outbox')
  h.close()

  h = sqliteHoldings(file)
  s = service(h, log)
  assert.deepEqual((await h.get(IDENTITY)).outbox.texts, [log.entries()[0]], 'the outbox is there after the restart')
  assert.deepEqual((await s.submit('membership', signed('membership', Y, 'a'))).body, { ok: false, reason: 'prev' })
  assert.deepEqual(log.entries(), [log.entries()[0], log.entries()[0]], 'the same text again, and nothing else')
  assert.deepEqual((await s.records()).anchors, [log.entries()[0]])
  assert.equal(envelope.open(log.entries()[0], 'anchor').body.record, mId(X))
  h.close()
})

test('a process killed inside an update keeps nothing of it; one killed after its outbox was kept leaves the outbox', async () => {
  const file = fresh()
  const first = child(file, 'die-inside-update')
  const a = await first.exited
  assert.equal(a.signal, 'SIGKILL', a.out)
  assert.match(a.out, /kept root/)
  let h = sqliteHoldings(file)
  let e = await h.get(IDENTITY)
  assert.equal(e.held.roots.length, 1, 'the update that ended is kept')
  assert.equal(e.held.memberships.length, 0, 'the one it died in is not')
  assert.equal(e.outbox, undefined)
  h.close()

  const second = child(file, 'die-in-log')
  const b = await second.exited
  assert.equal(b.signal, 'SIGKILL', b.out)
  h = sqliteHoldings(file)
  e = await h.get(IDENTITY)
  assert.equal(e.outbox.texts.length, 1, 'the anchor signed waits in the outbox')
  assert.equal(e.held.memberships.length, 0, 'and the holding served is still the one before it')
  const log = memoryLog()
  const s = service(h, log)
  assert.deepEqual((await s.records()).anchors, [], 'nothing is served that the log has not taken')
  assert.equal((await s.head()).status, 200)
  assert.deepEqual(log.entries().slice(0, 1), e.outbox.texts, 'the next request appends it first')
  assert.deepEqual((await s.records()).anchors, e.outbox.texts)
  h.close()
})

test('one process holds the file: a second is refused, in this process or another, until the first lets go', async () => {
  const file = fresh()
  const h = sqliteHoldings(file)
  await h.update('a'.repeat(64), async () => ({ entry: { held: { identity: 'a'.repeat(64) } }, value: 1 }))
  assert.throws(() => sqliteHoldings(file), { message: 'the holdings are held by another process' })
  const other = await child(file, 'open').exited
  assert.match(other.out, /refused: the holdings are held by another process/)
  h.close()
  const held = child(file, 'hold')
  await held.said('holding')
  assert.throws(() => sqliteHoldings(file), { message: 'the holdings are held by another process' })
  held.kill()
  await held.exited
  const again = sqliteHoldings(file)
  assert.deepEqual(await again.identities(), ['a'.repeat(64)], 'what the first kept is there')
  again.close()
})

test('a stored holding that cannot be read is a failure, never an absent identity: 503, and nothing is written over it', async () => {
  const other = 'b'.repeat(64)
  for (const [name, bad, how] of [['not JSON', '{"held":', SyntaxError], ['of another identity', JSON.stringify({ held: { ...w.empty(other) } }), { message: "a stored holding is not its identity's" }],
    ['no holding', '{}', TypeError], ['null', 'null', TypeError], ['a number', '7', TypeError]]) {
    const file = fresh()
    let h = sqliteHoldings(file)
    await service(h).submit('root', rootText('a'))
    h.close()
    const db = new DatabaseSync(file)
    db.prepare('UPDATE holdings SET entry = ?').run(bad)
    db.close()
    h = sqliteHoldings(file)
    const s = service(h)
    await assert.rejects(h.get(IDENTITY), how, name)
    assert.deepEqual(await s.submit('root', rootText('a')), { status: 503, body: { ok: false, reason: 'storage' } }, name)
    assert.equal((await s.head()).status, 503, name)
    assert.equal((await s.call('GET', `/v1/identities/${IDENTITY}/records`)).status, 503, name)
    await assert.rejects(s.svc.tick(), undefined, name)
    h.close()
    const check = new DatabaseSync(file)
    assert.equal(check.prepare('SELECT entry FROM holdings').get().entry, bad, name + ': left as it was')
    check.close()
  }
})

test('an update that cannot be saved keeps nothing, in the file or in memory, and says so', async () => {
  const file = fresh()
  let h = sqliteHoldings(file)
  const id = 'c'.repeat(64)
  assert.equal(await h.update(id, async (e) => { assert.equal(e, undefined); return { entry: { held: { identity: id }, n: 1 }, value: 'one' } }), 'one')
  await assert.rejects(h.update(id, async () => ({ entry: { held: { identity: id }, n: 10n }, value: 'two' })), TypeError, 'a value that cannot be written')
  assert.equal((await h.get(id)).n, 1, 'the entry before is still the entry')
  await assert.rejects(h.update(id, async () => { throw new Error('x') }), /x/)
  assert.equal(await h.update(id, async (e) => ({ value: e.n })), 1, 'an update that gives no entry changes nothing')
  h.close()
  await assert.rejects(h.update(id, async () => ({ entry: { held: { identity: id }, n: 3 }, value: 'three' })), 'a closed store fails')
  await assert.rejects(h.get(id))
  await assert.rejects(h.identities())
  const s = service(h)
  assert.deepEqual(await s.submit('root', rootText('a')), { status: 503, body: { ok: false, reason: 'storage' } })
  h = sqliteHoldings(file)
  assert.deepEqual(await h.get(id), { held: { identity: id }, n: 1 })
  h.close()
})

for (const [name, make] of [['memory', () => memoryHoldings()], ['sqlite', () => sqliteHoldings(fresh())]]) {
  test(`${name} holdings: one identity's updates run one at a time, in order, failures included; other identities do not wait`, async () => {
    const h = make()
    const order = []
    let release
    const gate = new Promise((resolve) => { release = resolve })
    const first = h.update('i', async () => { await gate; order.push(1); return { entry: { held: { identity: 'i' }, n: 'one' }, value: 1 } })
    const second = h.update('i', async (e) => { order.push(e.n); throw new Error('x') })
    const third = h.update('i', async (e) => { order.push(e.n); return { value: 3 } })
    for (let i = 0; i < 20; i++) await h.update('u' + i, async () => ({ value: 0 }))
    await new Promise((resolve) => setImmediate(resolve))
    assert.equal(h.inFlight(), 1, 'the twenty done are dropped; one identity still waits')
    assert.equal(await h.get('i'), undefined, 'nothing is kept before the update ends')
    release()
    assert.equal(await first, 1)
    await assert.rejects(second, /x/)
    assert.equal(await third, 3)
    assert.deepEqual(order, [1, 'one', 'one'])
    await new Promise((resolve) => setImmediate(resolve))
    assert.equal(h.inFlight(), 0)
    assert.deepEqual(await h.identities(), ['i'], 'an identity is listed once it has an entry, and only then')
    h.close?.()
  })
}

test('entries in memory: the one kept is given back as it is; at most `cache` are held, and one dropped is read again, equal and frozen', async () => {
  const file = fresh()
  const h = sqliteHoldings(file, { cache: 2 })
  const ids = ['1', '2', '3'].map((c) => c.repeat(64))
  const made = {}
  for (const id of ids) {
    made[id] = { held: { identity: id, roots: ['r' + id[0]] }, head: { text: 't', at: 5 } }
    await h.update(id, async () => ({ entry: made[id], value: 0 }))
  }
  assert.equal(await h.get(ids[2]), made[ids[2]], 'the newest is the very object kept')
  assert.equal(await h.get(ids[1]), made[ids[1]])
  const read = await h.get(ids[0])
  assert.notEqual(read, made[ids[0]], 'the oldest was dropped from memory')
  assert.deepEqual(read, made[ids[0]])
  assert.ok(Object.isFrozen(read) && Object.isFrozen(read.held) && Object.isFrozen(read.held.roots) && Object.isFrozen(read.head))
  assert.equal(await h.get(ids[0]), read, 'and is held again once read')
  // Reading the first dropped the second (the oldest held); the third, read since, stays.
  assert.equal(await h.get(ids[2]), made[ids[2]])
  assert.notEqual(await h.get(ids[1]), made[ids[1]])
  assert.deepEqual(await h.identities(), ids)
  h.close()

  // An entry kept again takes the newest place: the other one held is the next dropped.
  const g = sqliteHoldings(fresh(), { cache: 2 })
  const kept = {}
  const keep = async (id) => { kept[id] = { held: { identity: id } }; await g.update(id, async () => ({ entry: kept[id], value: 0 })) }
  await keep(ids[0])
  await keep(ids[1])
  await keep(ids[0])
  await keep(ids[2])
  assert.equal(await g.get(ids[0]), kept[ids[0]], 'kept again, so not the oldest')
  assert.equal(await g.get(ids[2]), kept[ids[2]])
  assert.notEqual(await g.get(ids[1]), kept[ids[1]], 'the one dropped')
  g.close()
})

test('the file: made on first use, refused if it is another format or cannot be journalled, and its options checked', () => {
  for (const bad of [[undefined], [7], [fresh(), null]]) assert.throws(() => sqliteHoldings(...bad), TypeError, JSON.stringify(bad))
  for (const cache of [0, -1, 1.5, '2', null, 2 ** 53]) {
    assert.throws(() => sqliteHoldings(fresh(), { cache }), { name: 'TypeError', message: 'cache must be a positive number of entries' }, String(cache))
  }
  assert.throws(() => sqliteHoldings(':memory:'), { message: 'the holdings file cannot be journalled ahead of its writes (WAL)' })
  const text = fresh()
  writeFileSync(text, 'not a database, but long enough to be read as one: ' + 'x'.repeat(200))
  assert.throws(() => sqliteHoldings(text))
  for (const sql of ['PRAGMA user_version = 2', 'CREATE TABLE other (x)', 'CREATE TABLE holdings (identity TEXT PRIMARY KEY, entry TEXT NOT NULL) STRICT']) {
    const file = fresh()
    const db = new DatabaseSync(file)
    db.exec(sql)
    db.close()
    assert.throws(() => sqliteHoldings(file), { message: 'the holdings file is of another format' }, sql)
    const after = new DatabaseSync(file)
    assert.equal(after.prepare("SELECT count(*) AS n FROM sqlite_master WHERE name = 'holdings'").get().n, sql.includes('holdings') ? 1 : 0, 'and is left as it was')
    after.close()
  }
  const file = fresh()
  sqliteHoldings(file).close()
  const made = new DatabaseSync(file)
  assert.equal(made.prepare('PRAGMA user_version').get().user_version, 1)
  assert.equal(made.prepare('PRAGMA journal_mode').get().journal_mode, 'wal')
  made.close()
  const again = sqliteHoldings(file)
  again.close()
})

// The in-memory store as oracle: the same requests, in the same order, to a service over each store, with the same
// log faults; the SQLite one is closed and opened again at steps drawn at random. Every answer, the log and the
// holding kept are the same.
const R = { a: rootText('a'), b: rootText('b') }
const X = mBody(2, ['a'], IDENTITY)
const TEXTS = {
  rootA: ['root', R.a], rootB: ['root', R.b],
  m2a: ['membership', signed('membership', M2, 'a')], m2b: ['membership', signed('membership', M2, 'b')],
  xa: ['membership', signed('membership', X, 'a')],
  freeze: ['freeze', signed('freeze', { identity: IDENTITY, membership: IDENTITY }, 'a')],
}
const REV = signed('revocation', { identity: IDENTITY, target: 'e'.repeat(64), at: BASE }, 'a')
const step = fc.oneof(
  { weight: 8, arbitrary: fc.constantFrom(...Object.keys(TEXTS)).map((k) => ({ do: 'submit', k })) },
  { weight: 3, arbitrary: fc.constant({ do: 'head' }) },
  { weight: 2, arbitrary: fc.constant({ do: 'records' }) },
  { weight: 2, arbitrary: fc.constant({ do: 'tick' }) },
  { weight: 1, arbitrary: fc.constant({ do: 'revoke' }) },
  { weight: 2, arbitrary: fc.constantFrom(1, 61, WINDOW).map((by) => ({ do: 'wait', by })) },
  { weight: 3, arbitrary: fc.constant({ do: 'lose' }) },
  { weight: 3, arbitrary: fc.constant({ do: 'restart' }) },
)

test('the same requests over memory and over SQLite with restarts: the same answers, log and holding', async () => {
  let restarts = 0
  let lost = 0
  await fc.assert(fc.asyncProperty(fc.array(step, { minLength: 4, maxLength: 24 }), async (steps) => {
    const file = fresh()
    const logs = [lossy(), lossy()]
    const stores = [memoryHoldings(), sqliteHoldings(file, { cache: 1 })]
    let now = BASE
    const make = (i) => { const s = service(stores[i], logs[i]); s.at(now); return s }
    const svc = [make(0), make(1)]
    try {
      for (const [n, c] of steps.entries()) {
        if (c.do === 'restart') { stores[1].close(); stores[1] = sqliteHoldings(file, { cache: 1 }); svc[1] = make(1); restarts++; continue }
        if (c.do === 'wait') { now += c.by; for (const s of svc) s.at(now); continue }
        if (c.do === 'lose') { for (const l of logs) l.lose = true; continue }
        const answers = []
        for (const s of svc) {
          if (c.do === 'submit') answers.push(await s.submit(...TEXTS[c.k]))
          else if (c.do === 'head') answers.push(await s.head())
          else if (c.do === 'records') answers.push(await s.call('GET', `/v1/identities/${IDENTITY}/records`))
          else if (c.do === 'revoke') answers.push(await s.call('POST', '/v1/revocations', { identity: IDENTITY, text: REV }))
          else answers.push(await s.svc.tick().then((texts) => ({ texts }), (e) => ({ failed: e.message })))
        }
        if (answers[0].status === 503 || answers[0].failed !== undefined) lost++
        assert.deepEqual(answers[1], answers[0], `step ${n} ${JSON.stringify(c)}`)
        assert.deepEqual(logs[1].entries(), logs[0].entries(), `the log after step ${n}`)
        assert.deepEqual(JSON.parse(JSON.stringify(await stores[1].get(IDENTITY) ?? null)), JSON.parse(JSON.stringify(await stores[0].get(IDENTITY) ?? null)), `the holding after step ${n}`)
      }
    } finally {
      stores[1].close()
    }
  }), { numRuns: runs(150) })
  assert.ok(restarts > 0 && lost > 0, 'the runs restart the store and lose log answers')
})
