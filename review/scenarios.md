# Scenarios

Each line is a single claim about this system that should be true. [`README.md`](README.md) says how one is chosen,
checked and reported. Each group's heading names the files to read for it; state the scenario's number in anything
filed about it.

## Verifier and signed heads — `src/verifier.js`, `src/merkle.js`, `src/note.js`

1. A claim verified against a head signed by a key not in the pinned witness keys is refused.
2. A head signed by a pinned key before its `nbf` or after its `exp` is refused.
3. Given the last membership head it accepted (`lastHead`), a verifier refuses a later head that is not consistent with it: a lower settled epoch, another settled membership, another pending successor. (A membership head has no tree size or Merkle root; those are a log checkpoint's, scenario 5.)
4. A membership head older than `lastHead` or `minHeadAt` is refused when the caller supplies either; with neither, a head older than the configured freshness window is refused. (The verifier remembers nothing itself: the caller keeps the last head.)
5. Integration obligation: wherever an inclusion proof is checked, its `size` and `root` both come from one authenticated checkpoint, never from the party presenting the proof. (A root does not commit to its size: the same proof can verify under two sizes, which is tested and intended.)
6. An inclusion proof with one extra, missing or reordered hash is refused.
7. A consistency proof between two heads that are not consistent is refused.
8. A proof for leaf index ≥ tree size is refused without an exception escaping.
9. A tree of size 0 and a tree of size 1 are each handled, with no proof accepted for a leaf that is not there.
10. A leaf hash can never be accepted as an interior node hash, nor the reverse (domain separation).
11. A signed note with a trailing extra line, a missing final newline or a second signature block is refused or read one way only.
12. A note's signature line whose name and key id do not both match a pinned key never counts as that key; the note is accepted only if a recognised signature verifies, and every recognised one is valid.
13. The verifier's decision does not depend on the order of the members of the objects it is given, nor on members it does not read. (Order-freedom over an identity's records is scenario 71.)
14. The verifier never makes a network request: everything it decides on is passed in.
15. A verification that fails says why in a fixed, enumerable set of reasons, none carrying attacker-chosen text unescaped.
16. A value that is not an object (null, an array, a string, a number) where a record is expected is refused, not thrown on.
17. A delegation is refused if the membership it names is not among the verified head's settled or pending memberships, or if its root is not in that head's authority. (There are no chains: one root delegates to one subject key. A pending successor's membership is valid for a root it retains.)
18. A claim at a time before the delegation's `nbf` less the allowed skew, or at or after its `exp`, is refused, at the exact second either side of each.

## Encoding and envelope — `src/encode.js`, `src/envelope.js`, `src/bytes.js`

19. A record with a duplicate key is refused.
20. A record whose keys are not in canonical order is refused, not re-sorted.
21. A number written as `1.0`, `1e0`, `01`, `-0` or beyond the safe integer range is refused where an integer is expected.
22. A string containing a lone surrogate is refused.
23. Two strings that differ only by Unicode normalisation are two different values, never treated as equal.
24. Hex in upper case is refused in every record field where lower-case hex is specified. (`fromHex` in `src/bytes.js` is an unchecked conversion: each caller checks the form first.)
25. Hex of odd length, or of the wrong length for its field, is refused.
26. Bytes after the end of a record are refused.
27. A record is hashed and verified over the bytes received, never over bytes produced by serialising it again.
28. `open(text, type)` refuses a payload whose own `type` is not the type asked for. What a record of that type must hold in its body is checked by that type's own checker (`checkRoot`, `checkDelegation` and the rest), not by `open`.
29. A key that does not belong in the envelope, or in the payload's `{ body, type, v }`, is refused by `open`; a key that does not belong in a record's body or signature is refused by that type's own checker before the record is accepted. (`seal` and `open` do not judge a body.)
30. A record nested deeper than the format allows is refused without exhausting the stack.
31. A very long string or list in a record is refused by a stated size limit before it is processed.
32. `__proto__` is not a legal key and is refused. `constructor` and `prototype` are legal keys and ordinary data: no prototype and no lookup table is reachable through a decoded record.

## Roots, passkey assertions — `src/root.js`, `src/assertion.js`, `src/p256.js`, `src/origin.js`

33. An assertion whose client data `type` is not `webauthn.get` is refused.
34. An assertion whose client data origin is not exactly the configured origin is refused (a different port, scheme, trailing dot, sub-domain, or case).
35. An assertion whose authenticator data rpIdHash is not the hash of the configured rp ID is refused.
36. Every root assertion missing the user-verified flag is refused.
37. An assertion without the user-present flag is refused.
38. An assertion whose challenge is not exactly the challenge derived from the record ids it covers is refused.
39. An assertion covering record ids A and B cannot be presented as covering only A, or A and C.
40. A P-256 signature with s in the upper half of the range, r or s of zero, or r or s ≥ n is handled as the spec states, the same way everywhere.
41. A P-256 public key is accepted only as a valid uncompressed `04 || x || y` point. Compressed or hybrid forms and the `00` point-at-infinity encoding are refused as `key-encoding`; an `04` point with invalid curve coordinates is refused as `key-point`.
42. A DER signature with trailing bytes, a non-minimal length or a negative integer is refused.
43. Client data JSON with any repeated reserved member (`type`, `challenge`, `origin`, `crossOrigin`, `topOrigin`) is refused, even when values agree. `topOrigin` is refused even without a duplicate.
44. `crossOrigin: true` in client data is refused.
45. A root record names one key and one rp ID; a root for another rp ID is never accepted here.
46. An identity's public id is derived from its first root alone. Another root may name that id but gains no authority by naming it or publishing a root record; authority requires a valid membership or recovery transition.

## Ed25519 delegate keys and delegations — `src/ed25519.js`, `src/delegation.js`

47. An Ed25519 signature with a non-canonical S is refused.
48. A small-order or non-canonical Ed25519 public key is refused as a subject key.
49. A delegation with a lifetime longer than the maximum is refused, at the maximum plus one second.
50. A delegation names its audience; a claim presented to another audience is refused, with no prefix, case or trailing-slash match.
51. A delegation's scopes are a set; a claim for a scope not in it is refused, with no prefix or wildcard match.
52. A delegation presented is refused unless its root is in the authenticated head's authority now and the membership it names is one the head gives; the witness applies the same rule when asked to log it. (What the root could do when it signed is not the question: a root added by a pending change may sign for the successor, which is refused while pending and taken once it settles.)
53. A delegation naming a membership that has since been replaced is treated as the spec states, the same by the witness and the verifier.
54. Authorising a new key for an agent at the id page removes the old key from that browser's renewals, and says so; what the old key was given works until it expires or is revoked. Revoking the old key refuses it and whatever is renewed for it; revoking the agent id refuses the new key too.
55. A delegation's subject is a validated Ed25519 public key (64 hex digits), never a root's P-256 key: the two encodings cannot be equal, and neither is read as the other.
56. One passkey assertion signs the ids of up to eight renewal payloads. Each becomes a delegation that verifies alone once its own subject has consented and the witness has logged it; a payload changed is no longer one the assertion covers.
57. A ninth renewal in one assertion is refused.
58. A delegation with `nbf` in the future beyond the allowed skew is refused by the witness.

## Membership: adding roots, contests, settlement — `src/membership.js`, `witness/witness.js`

59. A change adding a root takes effect only with the signatures the spec requires, including the added root's own.
60. A pending successor becomes the settled membership only once its contest window has passed uncontested, to the second. From the moment it is anchored, a root it removes has no authority; a root it adds has none until it settles.
61. A contest ends the identity only if a strict majority of the settled roots have signed it and the witness anchors it strictly before the successor's anchor time plus the contest window; at or after that moment the successor settles instead. Signing or submitting a contest earlier is not enough on its own.
62. A contest signed by a root that is not in the settled membership has no effect.
63. Two changes with the same `prev` cannot both settle.
64. A change whose `epoch` is not exactly its predecessor's plus one is refused.
65. A change whose `prev` is not the settled membership is refused, or held as the spec states, never applied.
66. A change that removes every root is refused.
67. A change with a root listed twice, or roots not in canonical order, is refused.
68. An identity that has ended accepts no further record of any type, root records included (one already held is held again, and changes nothing), and nothing is signed for it again.
69. A frozen identity authorises nothing new, and the conditions for freezing and unfreezing are exactly the spec's.
70. A replaced proposal cannot be submitted again, and the list of such tombstones cannot be made to grow without bound.
71. The state computed from the witness's records is the same on the witness, in the verifier and in the id page for every history the tests generate.
72. A root removed from the membership cannot sign a contest, a cancel, a delegation or a change as a root of it. It may sign a later change that adds it back, once the current roots have authorised that change: as every added root must, to show that it holds its key.
73. Authority is empty during any period the spec says no root has it, and nothing is authorised then.

## Recovery — `witness/witness.js` (R11), `src/membership.js`, `id/records.js`, `model/recovery.mjs`

74. A designation with zero parties, more than three parties, or a threshold that is not a strict majority is refused.
75. A designation with a waiting period below the minimum or above the maximum is refused, at one second either side.
76. The id page refuses to designate a party whose card names a current root. The core and witness cannot tell which root a salted commitment hides, so they do not refuse the designation on that basis; an existing member root never counts as a recovery party when it opens the commitment.
77. A designation naming the same party twice (the same root under two salts) is refused or counted once.
78. A published salted commitment does not identify the party's root to an observer without the salt or recovery card. A holder of the card can identify it before any recovery, and a party's published recovery signature reveals the opening.
79. A recovery signed by fewer parties than the threshold never gets notice.
80. A recovery signed by parties of an earlier, replaced designation never gets notice.
81. A party signature is accepted only with the salt that opens that party's commitment in the designation in force.
82. Notice is given only once every root the recovery adds has itself signed and its root record is held. A recovery that adds no root (one that keeps or removes roots, or changes only the designation) needs the parties' threshold alone and gets notice like any other; the owner's cancel within the wait answers it.
83. The roots change no earlier than the notice time plus the full waiting period.
84. A cancel signed by any one root of the settled membership, any time before the wait ends, stops the recovery and is acknowledged even while an ordinary successor is pending.
85. A cancel signed by the incoming root, a party, or a removed root does nothing.
86. After a cancel, no recovery is put under notice during the cooling-off period. Afterwards one may be while the notices held under the settled membership number fewer than 256 (`MAX_RECORDS`); once they reach it, none is given until an ordinary change settles and clears them.
87. Two different recoveries for one identity cannot both be under notice.
88. A recovery cannot be contested into ending the identity by anyone but those the spec allows.
89. An ordinary change signed by the roots while a recovery is under notice has the effect the spec states, and cannot be used by the parties to shorten the wait.
90. A recovery carries the designation forward or ends it exactly as its payload states, and that is what was shown to each signer.
91. The witness's notice, cancelled and matured statements cannot be given for a record it does not hold.
92. A verifier checks the signature, shape, freshness and usual consistency of a head carrying a notice, but `lastHead` alone cannot detect a backdated notice. Recovery timing trusts the witness; auditing such timing requires independent monitoring of logged heads.
93. A party that has given out the maximum number of recovery cards gives no more and loses none.
94. A recovery card for one rp ID is refused at another.

## The id page — `id/page.js`, `id/index.html`, `id/records.js`

95. Every panel shows fields taken from the payload that will be signed, not from the form.
96. Every input that feeds a review withdraws that review when edited.
97. A signing button that requires a pending review does nothing without that review, even when clicked by script while hidden. The one-click application-request sign-in path creates its own review and may sign only while its sign-in view is visible; its Create fallback is available only after that prompt is offered. Recovery cancellation is instead authorised by an active notice for a current root.
98. A review that expires before signing is not signed; one that expires during signing is not handed over.
99. An answer from the witness arriving after its review was withdrawn changes nothing on screen, including its answer to a signed record already sent.
100. A signature completed after its review was withdrawn is not sent, stored or shown.
101. The root held changing in another tab mid-request never causes this tab to act for the wrong root, including when a passkey prompt is pending and the change reaches IndexedDB without a BroadcastChannel notice; the root is re-read after the prompt.
102. Framed, or at an origin other than its configured one, the page offers nothing to act on.
103. The page's Content-Security-Policy admits no inline script but the one whose hash it names, and that hash matches.
104. No text from the witness, the store, or an input reaches the document as HTML.
105. A joining passkey can authorise no worker, designate no party and be nobody's party.
106. A registration or co-signature whose answer was lost is retried with the same record, never a new passkey or signature.
107. A recovery notice is shown on load, in every tab, to a current root with a cancel button and to the incoming root without one.
108. When the witness cannot be asked about a recovery, the page says so rather than showing nothing.
109. The page never shows a notice, designation or code that was read for a root it no longer holds.
110. The fingerprint shown on the joining device and on the adding device is derived the same way from the same root, and is long enough that a second root matching it is infeasible to find.
111. Worker keys are accepted only when their bytes form a canonical, prime-order Ed25519 public point; malformed key encodings are refused before storage or submission. A raw 32-byte private seed can accidentally encode such a point, so its bytes alone cannot reliably distinguish it from a public key.
112. Nothing the page stores is a secret: taking a copy of its IndexedDB gives no signing power.

## The page's store — `id/store.js`

113. Two tabs updating the same key at once never lose one update silently.
114. When a newer page changes the stored form, it must raise the IndexedDB version: the older page then closes on `versionchange`, says so, writes nothing further, and cannot reopen that database. A new script deployment without a database-version increase does not by itself stop an older tab.
115. A write that fails (quota, a blocked transaction, private mode) is reported and leaves the page showing what is actually stored.
116. A tab that missed a change notice still acts on what is stored, not on what it last saw. In particular, if the stored root changes without notice, the page withdraws a stale review before asking the passkey, and hands over no delegation or renewal whose prompt was in flight when it changed.

## The witness service — `witness/service.js`, `witness/holdings.js`, `witness/log.js`

117. A request body over the size limit is refused before it is parsed.
118. A request that is not JSON, or JSON of the wrong shape, gets a refusal with a fixed reason, never a stack trace.
119. One identity's records are never returned in answer to a request about another.
120. The number of records held per identity and per type is bounded, and reaching the bound refuses the next rather than dropping an earlier one.
121. Revocation admission applies a per-root token bucket (an initial burst, replenished at one token per day); the service does not enforce per-request-source rate limits.
122. A record accepted is in durable holdings before the client is told it was accepted.
123. A crash between writing holdings and appending to the log leaves a state the next start repairs or refuses to run on, never a silent fork.
124. The log is append-only: no code path rewrites or truncates an entry already covered by a signed head.
125. Two instances of the service started on the same holdings cannot both sign heads.
126. An identity membership head is derived from that identity's committed holding and signed only after its pending outbox has been appended. A cached head is reused within `headInterval` while the holding is unchanged. It is not a transparency-log checkpoint.
127. The service's clock going backwards produces no statement dated earlier than one already signed for the same identity, including after a restart on the same holdings.
128. Submitting the same record twice is accepted once and changes nothing the second time.
129. Identity ids, record ids and file names derived from request input cannot reach outside the storage directory or name a special file.
130. Unknown paths and methods are refused; no path exposes holdings wholesale or any signing key.
131. The witness signs only statements of the types the spec lists, each over a domain-separated encoding.
132. When the log loses an append acknowledgement, the next submission, head request or tick for that identity retries the exact outbox texts before deciding or signing anything new. This service has no timed retry wait.

## Relying parties and the demo — `adapter/relying-party.js`, `adapter/stores.js`, `demo/`

133. A signed request's claim is consumed at most once: the same claim presented again to an adapter sharing the same store is refused, for as long as it could otherwise be accepted. (At most once, not exactly once: an action that fails leaves its claim consumed.)
134. A claim signed for one method, origin or path is refused when any of them differs (query and fragment are not bound). Where the relying party requires a digest of the received body, a claim with no `content_digest`, or one that does not match, is refused.
135. A request older or newer than the allowed time window is refused.
136. A consumed claim id is kept for its whole acceptance window plus clock grace: accepting any number of other claims never evicts an unexpired one. (There is no bound on the count of entries, only on their lifetime; whether there should be one is open question Q7 in `briefs.md`.)
137. Credit goes to the identity that delegated to the signing key, and to no identity named anywhere in the request by its sender.
138. Integration check of scenario 50: a request whose delegation is for a different audience is refused before the protected action runs.
139. A delegation that has expired is refused at the moment of authorisation, including one that expired while the request waited. Once the adapter has seen a revocation in a verified head, no other valid head presented later restores that authority while the revocation must be kept. (Replacing an agent's key at the id page stops renewal; it does not itself revoke what was already issued.)
140. A submitted record cannot be altered; a standing forecast may be superseded only until its question closes; a balance cannot be collected twice or by an identity other than its beneficiary. (Within one process: the demo does not claim persistence across a restart.)
141. The adapter verifies the head a request presents under its own pinned witness keys and against the head and revocations it remembers itself; a caller cannot supply or replace that remembered state.
142. An ordinary refusal by the adapter is one of a fixed set of reason codes, and carries no stored record content and no identifier of anything unrelated to the request.

## Receipts and attestations — `src/receipt.js`, `src/attestation.js`

143. A receipt verifies only for the exact record, issuer and time it names.
144. A receipt from one issuer cannot be presented as another's, or for another record.
145. An attestation's fields are each checked; none is accepted on the strength of the signature alone.

## Tests, models and the build — `tests/`, `model/`, `.github/workflows/`, `package.json`

146. Every `.test.mjs` file anywhere under `tests/` is run by CI. The CI guard inventories files recursively, so a new suite at any depth that the runner does not execute makes the guard fail.
147. No test is silently skipped, marked todo, or exits early on a condition CI always meets. The guard rejects conditional skip/todo/only options and test-context skip/todo calls, apart from the single pinned Chrome-DevTools-only test in `tests/store/ST1-store.test.mjs` that is intentionally skipped on Firefox/WebKit and run on Chrome.
148. Every source module under `src/`, `adapter/`, `worker/`, `witness/`, `id/` and `demo/`, including modules in subdirectories, is mutated by exactly one mutation configuration, or by contiguous parts covering all of it.
149. Every mutant excluded by a `Stryker disable` comment is truly equivalent, for the reason the comment gives. An inclusive array-copy loop that appends an observable `undefined` element must not be excluded.
150. Every "twin" (a deliberately broken copy of the code) still applies to the current source and is caught by a test for the reason it names.
151. Every check that something did not happen waits long enough for it to have happened.
152. The witness service's staged outbox and settled holding follow the transitions and guards of `model/tla/WitnessOutbox.tla`; the witness's `admit`, `log`, `revoke` and `advance` decisions are checked separately against the JavaScript models in `model/`, not that TLA+ model.
153. Every invariant claimed in `model/STATE.md` remains defined in the model and selected by a TLC configuration that CI runs. An independent test pins the promised invariant names, so deleting an invariant from both the model and its checked configuration is detected.
154. The Tamarin authentication-chain model permits a Dolev–Yao network adversary to intercept, forge, replay and reorder messages and to learn root and delegate signing keys; its claims do not model corrupted browser storage, provider responses or witness state from `SPEC.md` section 1.
155. Each fuzz target in `fuzz/` reaches the code it names, and its seeds include at least one input its checker actually accepts; the `verify` seed test requires positive verdicts on the unchanged target fixture so an all-refusing verifier setup cannot silently satisfy it.
156. Every GitHub Action is pinned to a commit, and no workflow requests a write-scoped token for an untrusted pull request. The CI guard catches write permissions in YAML whether bare or quoted (including job-level overrides).
157. Every dependency is pinned to an exact version with an integrity hash, and none runs an install script. The `.npmrc` settings requiring scripts to be ignored and versions to be saved exactly each have one unambiguous declaration.
158. The packable npm artifact includes every public export target but excludes `tests/`, `model/` and `research/`, checked by `tests/guards/package-pack.test.mjs`. Publication itself is disabled by `package.json`'s `private: true`.
159. The code in `src/` uses no clock, no randomness, no network and no global state of its own.
160. Each number in `SPEC.md` (a window, a limit, a maximum) is the same number in the code and in the model.
