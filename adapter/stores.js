// Stores for the relying-party adapter. `transaction(fn)` runs fn atomically with synchronous operations: lastHead
// reads { head, at }; advanceHead replaces an identity's head only with a later one; replaceHead replaces it with
// another of the same time only if it is still the one given (compare-and-set); consume inserts a claim id only if
// absent, returning whether it did. Each is the database's own guarantee (a unique key, a conditional upsert,
// a serialising transaction), not read-then-write in the adapter.
import { DatabaseSync } from 'node:sqlite'

// A claim id is kept `grace` seconds past its `until`, so an instance whose clock is behind the one expiring it (by
// up to the verifier's skew) still refuses a replay. 60 s by default: set it to the largest clock difference allowed.

// One process: JavaScript runs fn to completion, with no await inside it.
export function memoryStore ({ grace = 60 } = {}) {
  const consumed = new Map()
  const heads = new Map()
  const tx = {
    lastHead: (identity) => heads.get(identity),
    advanceHead (identity, head, at) {
      const old = heads.get(identity)
      if (old === undefined || at > old.at) heads.set(identity, { head, at })
    },
    replaceHead (identity, head, at, was) {
      const old = heads.get(identity)
      if (old !== undefined && old.at === at && old.head === was) heads.set(identity, { head, at })
    },
    consume (id, until) {
      if (consumed.has(id)) return false
      consumed.set(id, until)
      return true
    },
  }
  return {
    async lastHead (identity) { return tx.lastHead(identity) },
    async transaction (fn) { return fn(tx) },
    async expire (now) {
      for (const [id, until] of consumed) if (until + grace <= now) consumed.delete(id)
    },
  }
}

// Several processes or threads sharing one SQLite file: BEGIN IMMEDIATE takes the write lock, so transactions run
// one at a time across them; WAL and a busy timeout of `busy` milliseconds let each wait for the others.
export function sqliteStore (file, { grace = 60, busy = 10000 } = {}) {
  if (!Number.isSafeInteger(busy) || busy < 0) throw new TypeError('busy must be a number of milliseconds')
  const db = new DatabaseSync(file)
  // SQLite does not wait to switch a file to WAL while another connection writes to it (others opening a new file at
  // the same moment): it answers SQLITE_BUSY (5) at once. So this is asked again, for as long as `busy`.
  const until = Date.now() + busy
  for (let made = false; !made;) {
    try {
      db.exec(`PRAGMA busy_timeout = ${busy}; PRAGMA journal_mode = WAL;
        CREATE TABLE IF NOT EXISTS consumed (id TEXT PRIMARY KEY, until INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS heads (identity TEXT PRIMARY KEY, head TEXT NOT NULL, at INTEGER NOT NULL);`)
      made = true
    } catch (e) {
      // Stryker disable next-line EqualityOperator: equivalent; at the very millisecond, one more try or none
      if (e.errcode !== 5 || Date.now() >= until) throw e
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1) // a millisecond's sleep
    }
  }
  const get = db.prepare('SELECT head, at FROM heads WHERE identity = ?')
  const advance = db.prepare(`INSERT INTO heads (identity, head, at) VALUES (?, ?, ?)
    ON CONFLICT (identity) DO UPDATE SET head = excluded.head, at = excluded.at WHERE excluded.at > heads.at`)
  const replace = db.prepare('UPDATE heads SET head = ? WHERE identity = ? AND at = ? AND head = ?')
  const insert = db.prepare('INSERT INTO consumed (id, until) VALUES (?, ?) ON CONFLICT (id) DO NOTHING')
  const remove = db.prepare('DELETE FROM consumed WHERE until <= ?')
  const read = (identity) => {
    const row = get.get(identity)
    return row === undefined ? undefined : { head: row.head, at: row.at }
  }
  const tx = {
    lastHead: read,
    advanceHead (identity, head, at) { advance.run(identity, head, at) },
    replaceHead (identity, head, at, was) { replace.run(head, identity, at, was) },
    consume: (id, until) => insert.run(id, until).changes === 1,
  }
  return {
    async lastHead (identity) { return read(identity) },
    async transaction (fn) {
      db.exec('BEGIN IMMEDIATE')
      try {
        const value = fn(tx)
        db.exec('COMMIT')
        return value
      } catch (e) {
        db.exec('ROLLBACK')
        throw e
      }
    },
    async expire (now) { remove.run(now - grace) },
    close () { db.close() },
  }
}
