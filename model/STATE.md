# Where state is kept, and what checks it

Every part of this repository that keeps state between two steps, with: who alone may change it (authority), the
step at which a change has happened (commit point), what is assumed of a restart, what model covers it, and what no
model covers. A model check here is exhaustive only within the bounds its configuration states, and is about the
model; the tie to the code is by tests, named in [`TESTING.md`](../TESTING.md). Gaps are listed, not excused.

## 1. Mixed versions of the id page in one browser (not covered)

Two tabs of the id origin may run different versions of `id/page.js`: one opened before a deployment, one after.
Nothing models this, and the code does not yet handle it.

- What is stored has no format version. A stored root that is not of the form the running code knows is read as no
  root (`storedRoot`), and stored workers not of its form as none (`storedWorkers`). That is right for a value
  something else on the origin wrote. For a value a *newer* page wrote in a newer form it is wrong: the older tab
  shows Create, and its Create, finding "none", writes a new root over the stored one; any change to the workers
  writes back only the entries it understood.
- The database is opened at a fixed version 1, with no `versionchange` or `blocked` handling. If a later page
  raised the version, an older tab's open connection would block the upgrade and the new tab would wait without
  saying why; an older page opening the raised database is refused by the browser (`VersionError`) and says it has
  no storage, which is the safe outcome.
- The page has been used by nobody, so no stored value of an older form exists today.

The mechanism to adopt is the Indexed Database standard's own: a change of stored form raises the database version;
every connection handles `versionchange` by closing, after which that tab has no storage and offers nothing until
reloaded; an open that is `blocked` is reported. Then the standard, not this code, guarantees that code of an older
version never writes to a database of a newer form. To do before the stored form first changes; the handlers
themselves can be added and tested in Chrome now.

## 2. The components

| State | Authority | Commit point | Restart | Model | Not covered |
|---|---|---|---|---|---|
| **Id page: remembered workers** (`id/page.js`, IndexedDB `{ rev, workers }`) | the one read-write transaction of `store.update`, in any tab | the transaction's `complete` (durability `strict`) | a reload reads storage; a tab's copy, open review and pending replies are dropped | `tla/IdPage.tla`: ten invariants; one tab and two tabs exhaustively, three larger bounds sampled nightly | two agents and two audiences beyond sampling; more than two tabs; mixed versions (§1); the passkey and the witness are any answer at any time, not their protocols |
| **Id page: stored root** (same store; root, credential id, `joining`, `registered`, `cosigned`) | the same transaction, made only while storage holds the root decided for | `complete` | a reload reads storage and sends again what is kept unsent (registration, co-signature) | `tla/IdRoot.tla`: four invariants, two tabs, storage cleared between any two steps | the witness refusing or answering differently on a resend; more than two tabs; mixed versions (§1) |
| **Browser store** (`id/store.js`) | the browser | as the Indexed Database standard states: overlapping read-write transactions run one at a time, in the order made, each whole or not at all | committed values survive; a notice to other tabs may be lost (nothing depends on it) | assumed by `IdPage` and `IdRoot` as one atomic step (`Transactional`), with the notice a separate, losable step | the standard's guarantee is taken, not checked, beyond the Chrome tests (`ST1`); other browsers are not run; version handling (§1) |
| **Relying party: consumed claims and head memory** (`adapter/`) | one store transaction (`BEGIN IMMEDIATE` in SQLite; one synchronous function in memory) | `COMMIT`; the action runs after it | consumed ids and heads survive in the database store; the memory store forgets both, so serves one process that does not restart inside a claim's life | `tla/Adapter.tla`: two instances, differing clocks, cleanup and restarts; at most once, no authority past any deadline, the freshness bound reached | the action itself (at most once, not exactly once); more than two instances beyond the eight-instance race test; a store that loses a committed transaction |
| **Witness: one identity's holding** (`witness/witness.js`, pure) | the witness's decisions: `admit`, `log`, `revoke`, `advance` | none of its own: it returns a new holding | none: it holds nothing | `settled.mjs`, `recovery.mjs` (membership and settlement, bounded explorers and random walks); `timing.mjs` (time and revocation); Tamarin `Claims.spthy` (the authentication chain against a network attacker) | an explorer's bound; a dishonest witness is a stated residual of SPEC, not ruled out |
| **Witness service: holdings and outbox** (`witness/service.js`) | `holdings.update`, one identity's changes one at a time | two: the outbox kept (decided), then the holding kept after the log took every text (effective) | assumed of the holdings store: an update is kept whole or not at all, and survives. Only `memoryHoldings` exists, which survives nothing | **none** | everything: a crash between the two commits, a lost log answer, two service instances on one store, `tick` beside a request. Tested by example only (`S1`: a lost answer then a rival). No durable holdings store exists to make the restart assumption true |
| **Transparency log** (`log/`, Tessera's POSIX server; `witness/log.js` reads it) | Tessera | an entry's index once sequenced; a checkpoint once its witnesses cosigned it | Tessera's own | none here: Tessera's guarantees are taken; every proof is checked by the core's `verifyInclusion` against a verified checkpoint | `append` is not idempotent: a retry after a lost answer adds the entry again (harmless to the witness's outbox, which only needs each text present) |
| **Demo service: contributions, receipts, questions, earnings** (`demo/forecasts.js`) | the service process; a claim is consumed by the adapter first | `kept.push` in memory, after the adapter's transaction; the receipt's index, then its bundle | **nothing survives**: a restart loses contributions whose claims stay consumed (if the adapter's store is a database) | none; the claim's consumption is `Adapter.tla`'s | the receipt outbox (append, index kept, bundle); `collect` beside `resolve`; that a restart loses paid-for work. It is a demo and is in memory by design, but nothing states that as a limit |
| **The core** (`src/`) | none | none | none | pure functions of their inputs: no state | not applicable |

## 3. What this leaves to do, in order

1. Version handling in the browser store (§1): the handlers and their Chrome tests.
2. The witness service's outbox: a TLA+ model of decide, stage, append, keep, with a crash and a lost log answer
   between any two, and two requests for one identity; the invariant that the witness never signs two rivals and
   serves nothing the log lacks. It is the same shape as the id page's outbox and the adapter's transaction.
3. A durable holdings store, so the service's restart assumption is true of something; chosen by the same rule as
   the adapter's (the database's own transaction).
4. The demo's limit stated in SPEC §8a, or its state kept through the same store.
