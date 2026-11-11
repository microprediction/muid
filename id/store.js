// The page's storage (SPEC §7): values by key in one IndexedDB object store. `get(key)` gives { value } or
// { absent: true }; a read that fails throws, and is never reported as absence. `update(key, change)` reads the key,
// gives what it holds to `change`, and stores its answer ({ value }, { absent: true }, or undefined to leave it), all
// in one read-write transaction. By the Indexed Database standard such transactions on one object store run one at a
// time, in the order made, across every tab and worker of the origin, and each is committed whole or not at all: so
// no update is made from a value another update has since replaced. `change` is called once, synchronously, and must
// not wait: a transaction ends when its task does. Nothing else in the page touches browser storage.
const VALUES = 'values'
const read = (record) => record === undefined ? { absent: true } : { value: record.value }

function checkKey (key) {
  if (typeof key !== 'string') throw new TypeError('a key is a string')
}

// A change's answer: undefined, or an object with one field, `value` or `absent: true`.
function answer (x) {
  if (x === undefined) return undefined
  const fields = x !== null && typeof x === 'object' ? Object.keys(x) : []
  if (fields.length === 1 && (fields[0] === 'value' || x.absent === true)) return x
  throw new TypeError('a change gives { value }, { absent: true } or undefined')
}

export function openStore (name) {
  return new Promise((resolve, reject) => {
    if (typeof name !== 'string' || name === '') throw new TypeError('a store has a name')
    const opening = indexedDB.open(name, 1)
    opening.onupgradeneeded = () => { opening.result.createObjectStore(VALUES) }
    opening.onerror = () => reject(opening.error)
    opening.onsuccess = () => resolve(store(name, opening.result))
  })
}

function store (name, db) {
  // Tells the origin's other holders of this store which key a committed update changed.
  const channel = new BroadcastChannel(`muid-store:${name}`)

  // One transaction on the values. `work` is given the object store, `done` to name the result, and `fail` to abort
  // with an error. Resolves with the result once the transaction has committed; rejects if it did not.
  const transact = (mode, options, work) => new Promise((resolve, reject) => {
    const tx = db.transaction(VALUES, mode, options)
    let result
    let error
    tx.oncomplete = () => resolve(result)
    tx.onabort = () => reject(error ?? tx.error ?? new DOMException('the transaction was aborted', 'AbortError'))
    work(tx.objectStore(VALUES), (r) => { result = r }, (e) => { error = e; tx.abort() })
  })

  return Object.freeze({
    async get (key) {
      checkKey(key)
      return transact('readonly', undefined, (values, done) => {
        const got = values.get(key)
        got.onsuccess = () => done(read(got.result))
      })
    },

    async update (key, change) {
      checkKey(key)
      if (typeof change !== 'function') throw new TypeError('a change is a function')
      // Durable before it is reported: what the page says it has kept, it has.
      const r = await transact('readwrite', { durability: 'strict' }, (values, done, fail) => {
        const got = values.get(key)
        got.onsuccess = () => {
          const now = read(got.result)
          try {
            const next = answer(change(now))
            if (next === undefined) return done({ state: now, changed: false })
            if (next.absent) values.delete(key)
            else values.put({ value: next.value }, key)
            done({ state: read(next.absent ? undefined : next), changed: true })
          } catch (e) { fail(e) }
        }
      })
      if (r.changed) channel.postMessage(key)
      return r.state
    },

    // Calls `told(key)` for each update another holder of this store commits; returns a function that stops it.
    watch (told) {
      const hear = (e) => told(e.data)
      channel.addEventListener('message', hear)
      return () => channel.removeEventListener('message', hear)
    },

    close () {
      db.close()
      channel.close()
    },
  })
}
