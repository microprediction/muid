# Where state is kept, and what checks it

Every part of this repository that keeps state between two steps, with: who alone may change it (authority), the
step at which a change has happened (commit point), what is assumed of a restart, what model covers it, and what no
model covers. A model check here is exhaustive only within the bounds its configuration states, and is about the
model; the tie to the code is by tests, named in [`TESTING.md`](../TESTING.md). Gaps are listed, not excused.

## 1. Mixed versions of the id page in one browser (handled by the standard's rule; not modelled)

Two tabs of the id origin may run different versions of `id/page.js`: one opened before a deployment, one after.

- What is stored has no format version of its own. A stored root that is not of the form the running code knows is
  read as no root (`storedRoot`), and stored workers not of its form as none (`storedWorkers`). That is right for a
  value something else on the origin wrote; for a value a *newer* page wrote in a newer form it would let the
  older tab's Create write a new root over the stored one.
- So a change of stored form must raise the database's version, and the rest is the Indexed Database standard's:
  every open connection is sent `versionchange` and the upgrade waits until each has closed; a database of a later
  version cannot be opened at an earlier one. The store (`id/store.js`) closes when asked, or when the browser
  closes it, and says so; the page then withdraws what is open, offers nothing and says to reload; reloaded, the
  older code is refused the database and has no storage. Code of an older version never writes to a database of a
  newer form. Tested in Chrome (`ST1`, `P2`), with broken twins.
- Not covered: no model has two versions in it; the rule that a change of form raises the version is a rule for
  whoever makes that change, checked by nothing; an open that is `blocked` by a connection that does not close
  (not this code's) is not reported, since at a fixed version it cannot happen.
- The page has been used by nobody, so no stored value of an older form exists today.

## 2. The components

| State | Authority | Commit point | Restart | Model | Not covered |
|---|---|---|---|---|---|
| **Id page: remembered workers** (`id/page.js`, IndexedDB `{ rev, workers }`) | the one read-write transaction of `store.update`, in any tab | the transaction's `complete` (durability `strict`) | a reload reads storage; a tab's copy, open review and pending replies are dropped | `tla/IdPage.tla`: ten invariants; one tab and two tabs exhaustively, three larger bounds sampled nightly; the page itself run through random two-tab histories in Chrome and judged by those invariants (`P2`; TESTING, "Histories of the page") | two agents and two audiences beyond sampling; more than two tabs; mixed versions (§1); the passkey and the witness are any answer at any time, not their protocols |
| **Id page: stored root** (same store; root, credential id, `joining`, `registered`, `cosigned`) | the same transaction, made only while storage holds the root decided for | `complete` | a reload reads storage and sends again what is kept unsent (registration, co-signature) | `tla/IdRoot.tla`: four invariants, two tabs, storage cleared between any two steps | the witness refusing or answering differently on a resend; more than two tabs; mixed versions (§1) |
| **Browser store** (`id/store.js`) | the browser | as the Indexed Database standard states: overlapping read-write transactions run one at a time, in the order made, each whole or not at all | committed values survive; a notice to other tabs may be lost (nothing depends on it) | assumed by `IdPage` and `IdRoot` as one atomic step (`Transactional`), with the notice a separate, losable step | the standard's guarantee is taken, not checked, beyond the tests (`ST1`: Chrome, and Playwright's builds of Firefox and WebKit, which are those engines and not the shipped Firefox or Safari); the page itself (`P2`) is run in Chrome only, its passkeys being Chrome's virtual authenticator; version handling (§1) |
| **Relying party: consumed claims and head memory** (`adapter/`) | one store transaction (`BEGIN IMMEDIATE` in SQLite; one synchronous function in memory) | `COMMIT`; the action runs after it | consumed ids and heads survive in the database store; the memory store forgets both, so serves one process that does not restart inside a claim's life | `tla/Adapter.tla`: two instances, differing clocks, cleanup and restarts; at most once, no authority past any deadline, the freshness bound reached | the action itself (at most once, not exactly once); more than two instances beyond the eight-instance race test; a store that loses a committed transaction |
| **Witness: one identity's holding** (`witness/witness.js`, pure) | the witness's decisions: `admit`, `log`, `revoke`, `advance` | none of its own: it returns a new holding | none: it holds nothing | `settled.mjs`, `recovery.mjs` (membership and settlement, bounded explorers and random walks); `timing.mjs` (time and revocation); Tamarin `Claims.spthy` (the authentication chain against a network attacker) | an explorer's bound; a dishonest witness is a stated residual of SPEC, not ruled out |
| **Witness service: holdings and outbox** (`witness/service.js`) | `holdings.update`, one identity's changes one at a time | two: the outbox kept (decided), then the holding kept after the log took every text (effective) | assumed of the holdings store: an update is kept whole or not at all, and survives. Only `memoryHoldings` exists, which survives nothing | `tla/WitnessOutbox.tla`: no rivals in the log, nothing answered or served that the log lacks; three requests in flight, a death at any step, any log answer lost; six controls, one the store's one-at-a-time update | what the decisions are (witness.js's own models); more than one identity; that anything is ever logged (liveness). No durable holdings store exists to make the assumptions true of something: `memoryHoldings` survives nothing, and serves one process |
| **Transparency log** (`log/`, Tessera's POSIX server; `witness/log.js` reads it) | Tessera | an entry's index once sequenced; a checkpoint once its witnesses cosigned it | Tessera's own | none here: Tessera's guarantees are taken; every proof is checked by the core's `verifyInclusion` against a verified checkpoint | `append` is not idempotent: a retry after a lost answer adds the entry again (harmless to the witness's outbox, which only needs each text present) |
| **Demo service: contributions, receipts, questions, earnings** (`demo/forecasts.js`) | the service process; a claim is consumed by the adapter first | `kept.push` in memory, after the adapter's transaction; the receipt's index, then its bundle | **nothing survives**: a restart loses contributions whose claims stay consumed (if the adapter's store is a database) | none; the claim's consumption is `Adapter.tla`'s | the receipt outbox (append, index kept, bundle); `collect` beside `resolve`; that a restart loses paid-for work. It is a demo and is in memory by design, but nothing states that as a limit |
| **The core** (`src/`) | none | none | none | pure functions of their inputs: no state | not applicable |

## 3. What this leaves to do, in order

1. When the stored form first changes: raise the database version, and report a `blocked` open.
2. A durable holdings store, so what `WitnessOutbox` assumes of the store (an update of one identity at a time,
   kept whole when it ends or not at all) is true of something; chosen by the same rule as the adapter's (the
   database's own transaction).
3. The demo's limit stated in SPEC §8a, or its state kept through the same store.

## 4. Boundaries raised by the review of the web-storage page (#72)

That review generated histories against the page as it was on web storage and found seven faults; each is now
ruled out on IndexedDB by a rule of the page, a test in Chrome (`P2`) and, where the model has the step, an
invariant of `IdPage.tla`:

| Fault found | Rule now | Model |
|---|---|---|
| a stale tab's Forget restores a replaced key; two Forgets undo each other | every change is one read-write transaction on what storage holds, of the row shown | NoLostUpdate, NoResurrection |
| a hand-off shown though its save failed | handed over only after the transaction completes | SavedBeforeHandover |
| a withdrawn add-passkey review returns with the witness's answer | a reply for a withdrawn review is dropped | NoRevival |
| a forgotten worker renewed by a late signature | a renewal takes effect at its read of storage after the passkey answers | ReviewedStateIsCurrent |
| an expired delegation handed over | expiry checked again after the passkey answers | Unexpired |
| a withdrawn add-passkey hand-off restored by a late POST answer | as above: dropped | none: the add-passkey flow is not modelled, tests only |
| a withdrawn request's failure written over newer state | as above: dropped | none: tests only |

Its harness simulated web storage, which the page no longer uses, so it is not kept. The boundaries its audit
listed, and where each stands:

| Boundary | Standing |
|---|---|
| read and write atomic across tabs | the Indexed Database standard's; §2, browser store |
| root creation and registration across tabs | `IdRoot.tla`; §2 |
| mixed versions | §1 |
| a page frozen and resumed (the back/forward cache) with its state kept | by the model a resumed page is a tab not yet told of a change, which is covered: nothing it does depends on a notice, and every save is against what storage holds. Seen in Chrome by a probe, not by a test of the suite: a cached page that a notice, a raised version or a deletion of the database would reach is discarded and loaded afresh; one that nothing reached, or that another connection wrote beside without a notice, is resumed with its state and its database open. Other browsers **not seen** |
| the model's host against a real browser | the store's tests run in Chrome, Firefox and WebKit; the page's in Chrome only |
| clocks | `Adapter.tla` has differing clocks per instance; `IdPage.tla` has one clock, the page's own |
| the protected action after a claim is consumed | at most once, not exactly once; §2, relying party |
| a durable store restored to an older state | **not covered** for any store |
| witness and log commit | `WitnessOutbox.tla`; no durable holdings store exists (§3, 2) |
| capacity: 32 remembered workers, 8 to a renewal | each limit has its test (`P1`, `P2`); rotation, Forget and expiry together at the limit are **not covered**, and the models have two agents |
| a valid but old witness answer delivered late | the page's replies are any answer at any time in `IdPage.tla`; across a membership settlement, **not covered** |
| one agent name authorised on two devices | one key per agent is a rule of one browser's remembered list, not of the protocol: two devices may each authorise a key for the same name, and both delegations verify |
| the verifier judged by tests that use the verifier | independent vectors and differential checks of the core, in `TESTING.md` |
