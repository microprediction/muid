// Stores for the relying-party adapter. Each operation is atomic on its own: `consume` inserts a claim id only if
// absent, and `advanceHead` replaces an identity's head only with a later one. Both are the database's own
// guarantees (a unique key; a conditional upsert), not read-then-write in the adapter.
import { DatabaseSync } from 'node:sqlite'

// One process: JavaScript runs each operation to completion, with no await inside it.
export function memoryStore () {
  const consumed = new Map()
  const heads = new Map()
  return {
    async lastHead (identity) { return heads.get(identity)?.head },
    async advanceHead (identity, head, at) {
      const old = heads.get(identity)
      if (old === undefined || at > old.at) heads.set(identity, { head, at })
    },
    async consume (id, until) {
      if (consumed.has(id)) return false
      consumed.set(id, until)
      return true
    },
    async expire (now) {
      for (const [id, until] of consumed) if (until <= now) consumed.delete(id)
    },
  }
}

// Several processes or threads sharing one SQLite file: the unique key and the conditional upsert make each
// operation atomic across them; WAL and a busy timeout let them wait for each other's writes.
export function sqliteStore (file) {
  const db = new DatabaseSync(file)
  db.exec(`PRAGMA busy_timeout = 10000; PRAGMA journal_mode = WAL;
    CREATE TABLE IF NOT EXISTS consumed (id TEXT PRIMARY KEY, until INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS heads (identity TEXT PRIMARY KEY, head TEXT NOT NULL, at INTEGER NOT NULL);`)
  const get = db.prepare('SELECT head FROM heads WHERE identity = ?')
  const advance = db.prepare(`INSERT INTO heads (identity, head, at) VALUES (?, ?, ?)
    ON CONFLICT (identity) DO UPDATE SET head = excluded.head, at = excluded.at WHERE excluded.at > heads.at`)
  const insert = db.prepare('INSERT INTO consumed (id, until) VALUES (?, ?) ON CONFLICT (id) DO NOTHING')
  const remove = db.prepare('DELETE FROM consumed WHERE until <= ?')
  return {
    async lastHead (identity) { return get.get(identity)?.head },
    async advanceHead (identity, head, at) { advance.run(identity, head, at) },
    async consume (id, until) { return insert.run(id, until).changes === 1 },
    async expire (now) { remove.run(now) },
    close () { db.close() },
  }
}
