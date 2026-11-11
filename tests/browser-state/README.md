# Browser history checks

This suite runs the **actual `id/page.js` ES module**, with a separate VM context
and module lexical state for every document. It links the actual records module;
it does not rewrite the page, replace its controller, or compare the page to a
copy of `remember()`. A small independent oracle interprets successful user
authorizations and Forget actions and checks the effects the page publishes.

The PR introducing this suite is deliberately a **draft with failing regression
checks**. The reviewed code has outstanding contract violations. A successful
search is not made into a passing regression test by expecting those violations.
Production code is unchanged.

## Running

```sh
node --test tests/browser-state/B1-histories.test.mjs
```

This is included in the normal `npm test` glob. The wrapper starts a child with
`--experimental-vm-modules`; that flag is confined to the test host. A finding
fails the test. Host errors and failed non-vacuity controls also fail the test.

For the **historical PR #71 revision `8d21b2c`**, this diagnostic additionally
requires the search to rediscover the three previously missed contract classes:

```sh
node --experimental-vm-modules tests/browser-state/run.mjs --calibrate
```

Calibration is not the CI command. After the page is fixed, calibration should be
run against a checkout of the historical page, using `MUID_ID_DIR=/path/to/id/`,
rather than requiring the current page to retain the bugs. This uses the same
implementation override as the existing id tests.

`FC_SEED` and `FC_RUNS` configure the supplementary generated search (defaults
71071 and 100). A failed generated search prints the seed, shrink path and
counterexample. The systematic search always runs, independent of `FC_RUNS`.

## What is explored

The initial shared state is a registered identity and two remembered agents:
alpha/K1 and beta/K3. Both tabs load it. Alpha's form proposes K2. Each tab has
independent cached workers, fields, review state, and pending callbacks.

The operation catalog contains authorization, renewal and add-passkey workflows,
a failing review, field edits, checkbox selection, Forget, reload, storage notification delivery, a
failed write and clock advancement. The systematic search enumerates all
order-preserving interleavings of a workflow with each catalog operation in
either tab, retaining unique prefixes up to **eight transitions**. It stops each
history at its first violating transition. Counts include guarded/no-op command
attempts. This is bounded schedule enumeration,
not exhaustive exploration of the whole browser or of unbounded histories.
Fast-check also generates and shrinks longer mixed sequences up to 24 commands.

The user operations and effect completions are separate commands. Resolving a
witness response, resolving a passkey signature, and resolving each submission
response can be interleaved with another user action. `storage` notifications
are queued separately and remain FIFO for each receiving document. A write never
synchronously refreshes another tab's memory.

The oracle checks:

- Persisted worker mutations agree with the committed authorization/Forget
  history, including preservation of unrelated agents and current keys.
- A replacement handoff is not observable after a failed persistence operation.
- A cancelled generation does not restore a review/handoff or overwrite the UI
  with a late error.
- A renewal does not name a grant absent from current committed history.
- User selections survive redraw while an entry remains listed, and the renewed
  batch is precisely the selection captured at Review.
- A handoff corresponds to its Review input snapshot and is accepted by the
  actual core at publication time, after adding the test worker's consent.

The host produces real P-256 assertions and Ed25519 consent signatures. Native
authenticator interaction is simulated, not proved by those signatures.

## Controls and remaining assumptions

Ordinary authorization, renewal and add-passkey must successfully complete before
the search runs. Controls also check held witness/signature promises, delayed
storage refresh, absence of an event on the writing document, atomic write
failure, a notification delivered before a second mutation, and a worker review
which is correctly discarded. A controller which simply does nothing cannot
pass the controls.

Historical calibration also tries the candidate repair `change(loadWorkers())`
in place of `change(workers)`. A storage-read hook executes another document's
normal Forget handler after the first read has taken its snapshot and before
its caller writes. The candidate still loses an update. This control establishes
why a fresh read alone is insufficient; it requires no production source change.
The main pairwise search does not enumerate every synchronous read/write
interleaving between browser agent clusters. Its default callbacks run to
completion, so this boundary must remain explicit when assessing a proposed fix.

The host deliberately makes the following assumptions explicit:

| Boundary | Represented here | Still outside this suite |
| --- | --- | --- |
| Storage | Shared values, separate tab caches, FIFO notifications, next-write failure, reload | Browser disk flushing, read failures, eviction, backup rollback, schema migration and mixed versions of the page |
| DOM | Elements read from the real HTML, used event handlers, review/handoff visibility and values | Layout, CSS, focus, accessibility, native event propagation/default actions, iframe and origin enforcement |
| Lifecycle | Reload abandons the old document's pending effects | BFCache/pageshow, freeze/resume, process crash, offline restore, service workers |
| Authenticator | Held/rejected completions, credential selection, UV option, real signature bytes; a second pending request in one document is rejected | Native prompt/focus policy, credential creation, credential deletion/sync, user-presence hardware behavior |
| Witness | Held/rejected records responses and held successful POST responses, real membership reconstruction | Witness admission, logging, settlement, lost POST responses, HTTP streaming/JSON failure, witness restarts or changing membership |
| Time | Deterministic page clock, advancement while a ceremony is outstanding, core check at publication | Independent server/device clocks, backward steps, dynamic drift and time passage during protected actions |
| Data | Two agents, three valid worker keys, two possible audiences, valid fields | Capacity/eviction interactions, broad input generation and arbitrary storage corruption |

These are boundaries to test, not guarantees inferred from a passing run. In
particular this suite does not replace the actual Chrome/virtual-authenticator
tests. It does not prove eventual completion; its liveness controls are the
ordinary successful workflows. Longer histories and additional environments can
still contain failures. See [the broader audit](../../research/browser-state-audit.md).
