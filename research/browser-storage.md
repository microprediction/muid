# Browser storage shared by tabs

What a page can rely on when several tabs of one origin read and change the same stored state.

## Findings

### Web storage (`localStorage`)

1. The HTML standard defines no locking for `localStorage` between the processes of a multi-process browser: "This
   specification does not define the interaction with other agent clusters in a multiprocess user agent, and authors
   are encouraged to assume that there is no locking mechanism." Its own example of the hazard is a value read,
   incremented and written back, giving two windows the same "unique" identifier.
   https://html.spec.whatwg.org/multipage/webstorage.html
2. The `storage` event is queued as a task on each other same-origin document holding the storage; the writing
   document gets none, and none is sent when a value is set to what it already was. It is a notification, delivered
   later. https://html.spec.whatwg.org/multipage/webstorage.html
3. Chromium keeps, in each renderer process, a complete cache of the origin's key/value pairs; "Mutations originating
   in other processes are applied to the cache via StorageAreaObserver callbacks." A read is served from the cache.
   https://github.com/chromium/chromium/blob/main/third_party/blink/renderer/modules/storage/cached_storage_area.h
4. An earlier draft of the standard had a "storage mutex"; multi-process implementers did not implement it, and the
   2009 discussion of alternatives is on the WHATWG list.
   https://lists.w3.org/Archives/Public/public-whatwg-archive/2009Sep/0133.html

### Web Locks

5. A lock orders work between the tabs and workers sharing a storage bucket, and says nothing of any stored data: "A
   resource name has no external meaning beyond the scheduling algorithm". https://w3c.github.io/web-locks/
6. The standard names deadlock between holders as possible, a holder that never releases as permitted, and `steal` as
   leaving "code previously holding a lock ... executing without guarantees that it is the sole context".
   https://w3c.github.io/web-locks/ ; https://github.com/w3c/web-locks/blob/main/EXPLAINER.md
7. The explainer notes that wrapping an IndexedDB transaction around a lock is the hard direction, "since you can't
   keep an IndexedDB transaction alive arbitrarily". https://github.com/w3c/web-locks/blob/main/EXPLAINER.md

### IndexedDB

8. Read-write transactions with overlapping scopes do not run together, and go in the order made: "Multiple
   "readwrite" transactions can't be started at the same time if their scopes are overlapping"; "the transaction that
   was created first is the transaction which gets access to the object store first".
   https://w3c.github.io/IndexedDB/ (§2.7, §2.7.2)
9. A transaction is atomic: "The implementation must atomically write any changes to the database made by requests
   placed against the transaction", all of them or, on an error, none. https://w3c.github.io/IndexedDB/ (§2.7.1)
10. The database is shared across the origin's tabs and workers: "A single database can be used by multiple clients
    (pages and workers) simultaneously — transactions ensure they don't clash while reading and writing."
    https://w3c.github.io/IndexedDB/ (§1)
11. A transaction cannot be held across other asynchronous work: it is inactive once control returns to the event loop
    and is committed when its requests are done. "Transactions are expected to be short lived."
    https://w3c.github.io/IndexedDB/ (§2.7.1)
12. Durability is a hint with three values; under `strict` the browser reports a commit "only after verifying that all
    outstanding changes have been successfully written to a persistent storage medium". https://w3c.github.io/IndexedDB/ (§2.7)

### What deployed libraries do

13. Supabase's `auth-js` took a Web Lock around session changes and is removing it (the default since v2.107, the
    option to go in v3). Its migration note lists callbacks that "previously deadlocked through the lock"; races
    between tabs are now settled by the server, and the client re-reads storage before writing and discards its
    result if storage changed meanwhile.
    https://cdn.jsdelivr.net/npm/@supabase/auth-js@2.118.0/migrations/lockless-coordination.md
14. Reports against that lock include a sign-in deadlock with several tabs and locks left held after a page error.
    https://github.com/supabase/supabase-js/issues/2013 ; https://github.com/supabase/supabase-js/issues/2111
15. Firebase's Firestore keeps its data in IndexedDB and uses `localStorage` only to tell other tabs that something
    changed, after which they read IndexedDB again. https://firebase.google.com/docs/auth/web/auth-state-persistence
    (Auth's persistence types); the Firestore mechanism is described in the SDK's source comments (see Unverified).

## Consequences for the spec

- §7: state that is read and then written is kept in IndexedDB and changed in one read-write transaction (findings
  8–10). The guarantee is the standard's, so it is cited rather than re-proved; the tests show the adapter uses it.
- §7: `localStorage` is not used for such state (1, 3), and no Web Lock is taken beside it (5): a lock would order the
  tabs without making one tab's read see another's write.
- §7, §8: a transaction cannot span a passkey prompt or a request to the witness (11). What the user reviews is
  decided before the update, and the update checks that what it finds is what was reviewed.
- §7: writes are asked for with `strict` durability (12), since the page tells the user what it has kept.
- §7: the notice to other tabs is a prompt to read again (2, 15); nothing depends on its arriving.
- K3 (non-extractable delegate keys): a `CryptoKey` that cannot be exported cannot be written as text, so IndexedDB is
  the only browser storage that can hold one. not yet in spec as a storage rule.

## Unverified

- That Firebase Auth moved its default persistence from `localStorage` to IndexedDB in version 4.12.0: stated in a
  Firebase forum reply, not checked against release notes. https://groups.google.com/g/firebase-talk/c/wgSvjniKPQI
- Firestore's use of `localStorage` as the notification channel: read from a third-party copy of the SDK's type
  declarations, not from the SDK repository.
- Firefox's `localStorage` gives each task a snapshot, so that a script sees a consistent view even with several
  content processes; read from a summary of `dom/localstorage/LSObject.h`, not verbatim.
  https://searchfox.org/firefox-main/source/dom/localstorage/LSObject.h
- That what one IndexedDB transaction wrote is read by the next transaction in another process: this follows from
  findings 8–10 taken together, and the two-tab tests observe it in Chrome; the standard's scheduling text does not
  use the words "across tabs".
- What happens to a transaction open when its tab is closed or crashes: the standard says transactions "offer some
  protection from application and system failures" and that an aborted transaction is rolled back, but does not
  state this case.
