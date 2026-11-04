// Stores for the relying-party adapter. `transaction(fn)` runs fn atomically with synchronous operations: lastHead
// reads { head, at }; advanceHead replaces an identity's head only with a later one; consume inserts a claim id only
// if absent, returning whether it did. Each is the database's own guarantee (a unique key, a conditional upsert,
// a serialising transaction), not read-then-write in the adapter.
import { DatabaseSync } from 'node:sqlite'

// One process: JavaScript runs fn to completion, with no await inside it.
export function memoryStore () {
  const consumed = new Map()
  const heads = new Map()
  const tx = {
    lastHead: (identity) => heads.get(identity),
    advanceHead (identity, head, at) {
      const old = heads.get(identity)
      if (old === undefined || at > old.at) heads.set(identity, { head, at })
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
      for (const [id, until] of consumed) if (until <= now) consumed.delete(id)
    },
  }
}

// Several processes or threads sharing one SQLite file: BEGIN IMMEDIATE takes the write lock, so transactions run
// one at a time across them; WAL and a busy timeout let each wait for the others.
export function sqliteStore (file) {
  const db = new DatabaseSync(file)
  db.exec(`PRAGMA busy_timeout = 10000; PRAGMA journal_mode = WAL;
    CREATE TABLE IF NOT EXISTS consumed (id TEXT PRIMARY KEY, until INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS heads (identity TEXT PRIMARY KEY, head TEXT NOT NULL, at INTEGER NOT NULL);`)
  const get = db.prepare('SELECT head, at FROM heads WHERE identity = ?')
  const advance = db.prepare(`INSERT INTO heads (identity, head, at) VALUES (?, ?, ?)
    ON CONFLICT (identity) DO UPDATE SET head = excluded.head, at = excluded.at WHERE excluded.at > heads.at`)
  const insert = db.prepare('INSERT INTO consumed (id, until) VALUES (?, ?) ON CONFLICT (id) DO NOTHING')
  const remove = db.prepare('DELETE FROM consumed WHERE until <= ?')
  const read = (identity) => {
    const row = get.get(identity)
    return row === undefined ? undefined : { head: row.head, at: row.at }
  }
  const tx = {
    lastHead: read,
    advanceHead (identity, head, at) { advance.run(identity, head, at) },
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
    async expire (now) { remove.run(now) },
    close () { db.close() },
  }
}
