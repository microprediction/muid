// The witness service's holdings in one SQLite file, held by one process (SPEC §5). What the service asks of its
// store (service.js), and model/tla/WitnessOutbox.tla assumes of it:
//   one update of an identity at a time   the process's own queue (serial), and no other process: the file is locked
//                                         for as long as it is open, so a second witness on it is refused at once;
//   kept whole when it ends, or not at all   an entry is written by one statement, which is one transaction;
//   still there after a restart           the transaction is in the write-ahead log, synced to disk, before the
//                                         update answers (synchronous = FULL).
// An entry is the JSON of what the service keeps: the holding, a cached head, an outbox. One that cannot be read is a
// failure (the service answers 503), never an absent identity. The witness key is not kept here.
import { DatabaseSync } from 'node:sqlite'
import { serial } from './service.js'

const FORMAT = 1
// Every object and array read is frozen, as those the witness makes are (freezing a string or number does nothing).
const frozen = (_, v) => Object.freeze(v)

// `cache` entries at most are also held in memory, as the objects the service kept, so the witness's state of a
// holding (computed once for each object) is not computed again for every request; the one kept or read from the
// file longest ago is dropped first.
export function sqliteHoldings (file, { cache = 1024 } = {}) {
  if (!Number.isSafeInteger(cache) || cache < 1) throw new TypeError('cache must be a positive number of entries')
  const db = new DatabaseSync(file)
  try {
    db.exec('PRAGMA locking_mode = EXCLUSIVE; PRAGMA synchronous = FULL')
    if (db.prepare('PRAGMA journal_mode = WAL').get().journal_mode !== 'wal') throw new Error('the holdings file cannot be journalled ahead of its writes (WAL)')
    db.exec('BEGIN IMMEDIATE')
    const version = db.prepare('PRAGMA user_version').get().user_version
    const tables = db.prepare('SELECT count(*) AS n FROM sqlite_master').get().n
    if (version === 0 && tables === 0) {
      db.exec(`CREATE TABLE holdings (identity TEXT PRIMARY KEY, entry TEXT NOT NULL) STRICT; PRAGMA user_version = ${FORMAT}`)
    } else if (version !== FORMAT) {
      throw new Error('the holdings file is of another format')
    }
    db.exec('COMMIT')
  } catch (e) {
    db.close()
    throw e.errcode === 5 ? new Error('the holdings are held by another process') : e
  }
  const select = db.prepare('SELECT entry FROM holdings WHERE identity = ?')
  const upsert = db.prepare('INSERT INTO holdings (identity, entry) VALUES (?, ?) ON CONFLICT (identity) DO UPDATE SET entry = excluded.entry')
  const all = db.prepare('SELECT identity FROM holdings ORDER BY identity')
  const held = new Map()
  const queue = serial()

  function hold (identity, entry) {
    held.delete(identity)
    held.set(identity, entry)
    if (held.size > cache) held.delete(held.keys().next().value)
  }
  function read (identity) {
    if (held.has(identity)) return held.get(identity)
    const row = select.get(identity)
    if (row === undefined) return undefined
    // Text that is not JSON, or not an entry at all, throws here too.
    const entry = JSON.parse(row.entry, frozen)
    if (entry.held.identity !== identity) throw new Error('a stored holding is not its identity\'s')
    hold(identity, entry)
    return entry
  }

  return Object.freeze({
    async get (identity) { return read(identity) },
    async identities () { return all.all().map((row) => row.identity) },
    update (identity, fn) {
      return queue.run(identity, async () => {
        const r = await fn(read(identity))
        if (r.entry !== undefined) {
          upsert.run(identity, JSON.stringify(r.entry))
          hold(identity, r.entry)
        }
        return r.value
      })
    },
    inFlight: queue.size,
    // Lets the file go. Nothing is answered from memory afterwards: every later call fails.
    close () {
      held.clear()
      db.close()
    },
  })
}
