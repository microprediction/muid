# State and mechanics beyond the browser history model

This audit accompanies the generated id-page history checks. It separates
observed counterexamples from assumptions which deserve additional testing.
The code under review is PR #71, `8d21b2c674420a8daf7c59b436d1f4e1eae0cbd1`.
The framework PR changes tests and documentation only.

## Observed counterexamples

The bounded search rediscovers the three previous review findings:

| Contract | Counterexample family |
| --- | --- |
| Persisted history survives another tab's mutation | Authorize alpha/K2 in A, then Forget beta in B before B receives the storage notification. K1 is restored. |
| A successful replacement is persisted | Let the signature complete with the next write throwing. The replacement handoff is displayed, but reload restores the old remembered key. |
| A withdrawn review stays withdrawn | Begin Add Review, perform an invalidating action, then deliver the old witness response. The add-root review reappears. |

It also finds the following behaviors without adding their exact traces to the
operation catalog. These are distinct contract failures; some share a cause
with an earlier finding.

| Behavior | Mechanism and interpretation |
| --- | --- |
| Two concurrent Forget actions undo each other | A forgets alpha and B forgets beta from its stale snapshot. Alpha returns. The generated counterexample reaches its first failure after two commands; a shrunk input may retain an unexecuted suffix. This is another manifestation of the stale whole-list write. |
| A forgotten worker can receive a late renewal handoff | A waits for its passkey while B forgets a worker. Before A receives the storage event, its signature completes and the old grant is handed over. Forget is not revocation; this violation concerns a **new renewal** of a forgotten grant. |
| An expired delegation is published | The page clock passes the reviewed expiry while the signature is outstanding. The handoff still appears; the core refuses it as `expired`. The pure core's time checks do not establish freshness at an asynchronous publication boundary. |
| A cancelled add-root handoff reappears | Once a signature has returned, add-sign awaits two submissions. A new Review withdraws the old operation, then its final POST response restores `add-handoff`. The earlier signature may already have been submitted; this finding does not claim cancellation can undo that submission. |
| A late failure overwrites newer UI state | Start another review before a previous witness request rejects. The old catch handler writes the current error field. This is a UI/state-isolation failure, not a forged signature or demonstrated privilege escalation. |

Seven named contracts fail in the baseline search; the first two rows above
include additional manifestations of the same storage/synchronization problems.
The exact traces and generated-search seed are in
[the baseline output](browser-state-baseline.txt).

A separate focused replay moves the clock past the expiry **before** Sign is
pressed, then immediately resolves the signature. It fails the same contract;
this finding does not require a native authenticator prompt to last for hours.

## Where the existing abstractions stop

| Boundary | Evidence in the current code/model | What an additional check should do |
| --- | --- | --- |
| Read/write atomicity across browser agents | The default VM schedule runs each synchronous callback to completion. A browser can have separate agent clusters. | Historical calibration includes a read-boundary interleaving that defeats the candidate repair `change(loadWorkers())`. Do not infer atomicity from a fresh read passing ordinary single-threaded histories; test the actual lock/transaction protocol across separate writers. |
| Root creation and registration | `id/page.js` reads storage before awaiting credential creation; registration and co-sign retry callbacks also span awaits and mutate `root`. The new model starts with an already registered root. | Hold two credential-creation completions across tabs; check that one does not overwrite an identity created meanwhile. Reorder registration/co-sign responses against storage changes, and bind callbacks to captured root/identity generations. This is an audit target, not a reproduced finding here. |
| Mixed versions and migration | The host opens every document with the same source and worker schema. | Keep a tab on the old source while another uses the new source; prove an old writer cannot silently reverse a newer schema's security decision. Versioning alone is not an atomic compare-and-set. |
| Freeze/resume and BFCache | Reload here destroys the old document. A real resumed page can retain JavaScript state. | Suspend a document across another tab's mutation, then resume it with pending ceremonies. Exercise pageshow, notification delivery and revalidation before publishing effects. |
| Browser/host correspondence | The actual page module runs, but a minimal host supplies its DOM and APIs. | Replay minimized histories in a real browser with controlled request gates and storage exceptions. Cross-check the host's storage-task and authenticator assumptions. The existing browser suite remains necessary; local Chromium could not launch in the review environment. |
| Clock model | `model/tla/Adapter.tla` uses a monotone real clock and a fixed offset per worker. The page model uses one virtual clock. | Move clocks independently within the promised skew; include suspension, backward correction and deadline crossing at each effect boundary. Explicitly separate violations of configured clock assumptions from implementation failures. |
| Authorization versus the protected action | `adapter/relying-party.js` runs the action after consuming the claim in a transaction. `Adapter.tla` explicitly excludes the action itself. SPEC says at most once, not exactly once. | Crash between commit and action, and while the action is pending. Check the intended at-most-once contract; if delivery is required, introduce an application outbox/idempotency contract rather than infer exactly-once execution from the authorization model. |
| Persistence versus restart | The adapter model's Restart abandons a request and leaves the store intact. SQLite and witness holdings have their own persistence contracts. | Test backend crashes and reopening separately from memory-store tests. An older restored database can lose replay/head memory; decide whether backup rollback is outside the deployment contract or needs an external monotonic anchor. |
| Witness/log commit | `witness/service.js` stages an outbox, appends remotely, and commits through `holdings.update`. Its memory backend serializes a process's updates. | Kill/restart a durable backend around each staged-write/append boundary and lose responses after remote acceptance. Keep the existing outbox/error tests; do not assume the memory backend establishes multi-process crash durability. |
| Capacity and retention | The page limits remembered workers to 32 and batches to 8; the new model has two agents. Other layers have record/revocation/body bounds. | Compose rotation, Forget, expiry and retries at capacity. Track what knowledge is evicted and whether that eviction permits an old key/grant or replay to return. Unit boundary tests alone do not check those histories. |
| Protocol freshness versus valid records | `model/settled.mjs` abstracts signatures and assumes an honest witness. The page host returns one fixed valid records set. | Delay a genuinely old valid response across membership settlement or revocation. Check both the page's output and the relying party's eventual acceptance, without assuming that valid bytes imply current authority. |
| Cross-device agent state | Remembered workers are browser-local; the protocol accepts independently authorized delegations. | Model two devices authorizing different keys under one agent name. State explicitly whether “one key” is a local renewal policy or a global protocol rule; the former cannot prove the latter. |
| Shared verifier assumptions | The new host uses the actual core to validate handoffs. | Keep independent vectors/differential checks for the core. A controller and its verifier agreeing does not independently prove the verifier's cryptographic or protocol rules. |

The next framework extensions should be chosen from this table and given both
positive controls and explicit scope. A model which silently assumes successful
storage, current responses, atomic workflows, or permanent document destruction
can prove a useful subproblem while omitting the behavior that breaks the user
promise.
