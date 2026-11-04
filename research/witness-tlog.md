# Witness as a transparency log — design proposal (for review)

Goal: replace muid's home-grown equivocation rule (decision 10, `forked()`) with the established mechanism —
a Merkle transparency log with signed checkpoints, inclusion and consistency proofs, and outside cosigners —
using standard formats so standard tools and witnesses work with it. Sources: research/prior-art.md §B.

## 1. What changes, in one paragraph

The witness keeps one append-only log (C2SP tlog-tiles). Every record it signs — heads, anchors, settlements,
attestations, admitted revocations — is appended as an entry. Periodically it publishes a **checkpoint** (C2SP
tlog-checkpoint: origin line, tree size, root hash) signed as a C2SP **signed note** with its Ed25519 key, and
cosigned by independent **witnesses** (C2SP tlog-cosignature, collected via the tlog-witness protocol). A delegate
staples to each request: its delegation, its root record, the current head, and a **tlog-proof** (entry, inclusion
proof, cosigned checkpoint). A relying party stores the newest checkpoint it has accepted (one per log, not one per
identity) and, given a consistency proof, checks that a newer checkpoint extends it.

## 2. What the relying party verifies (synchronous, pure, inside the core)

Given `(head, tlogProof, consistencyProof?)` and stored `lastCheckpoint?`:

1. The checkpoint note: the witness's Ed25519 signature (key pinned in config, as `witnessKeys` today), and at least
   `k` of the configured `n` cosigner signatures (type 0x04, timestamped), each cosigned time within
   `maxStaleness` of `now`. Unknown signature lines are ignored (C2SP signed-note rule).
2. Inclusion: the head's entry hash is in the checkpoint's tree (RFC 9162 §2.1.3.2).
3. Consistency, when `lastCheckpoint` is given: the new tree extends the stored one (RFC 9162 §2.1.4.2). A
   checkpoint of the same size must have the same root. A smaller one is refused as stale.
4. The head's own fields, as F5 does today (identity, memberships, authority, revoked).

Refusal reasons replace `equivocation`: `checkpoint` (signature or cosigner quorum), `inclusion`, `consistency`
(the evidence of a split view is the two signed checkpoints — keep them).

Asynchronous work stays outside the core: fetching tiles to build consistency proofs, as Go's sumdb client does.

## 3. What gets deleted

Decision 10 and `forked()`; F5's `lastHead`, its identity check and `equivocation`; the rule against removing
witness keys; probably the head's `epoch` field and its 2^32 bound; the residuals about backdating (decisions 8, 10)
narrow to "a colluding quorum of cosigners". `minHeadAt` becomes the stored checkpoint's cosigned time.

## 4. Named deviation kept

The head stays a signed per-identity record inside a log entry. Proving that an entry is the *newest* for its
identity would need KEYTRANS's prefix tree (a second, sparse Merkle structure), which is much more code. Freshness of
the head is still bounded by its `at` and `maxStaleness` (TUF's timestamp role), and a stale-but-included head is at
most `maxStaleness` old. KEYTRANS (architecture draft in IESG evaluation; protocol draft -06) is the path if that
bound ever proves too loose.

## 5. Contest window from cosigned time

Today `CONTEST_WINDOW` starts at the witness's own `at`, so a leaked witness key can backdate (residual). With
cosigners, the window starts at the cosigned time of the first checkpoint that includes the anchor — time the
witness alone cannot forge. This is the change that closes the backdating residual.

## 5a. Acceptance receipts: durable attribution

C1's claims are ephemeral: they prove authority at the moment of checking, and stop being checkable when their
delegation expires. "Was this forecast submitted under this identity before the outcome was known?" needs evidence
that outlives the delegation. The established pattern is Sigstore's: short-lived signing credentials, with the
evidence of validity at signing time kept in a transparency log.

- A **receipt** `{ service, identity, delegation, claim, digest, at }` is signed by the receiving service's key after
  `verifyClaim` accepted the claim: `claim` is the claim's id, `digest` the SHA-256 of the contribution, `at` the
  service's time. It states only what that service attests: that it verified this claim under that delegation at
  that time.
- The service appends the receipt to the witness log (or its own tlog-tiles log). The cosigned checkpoint that
  first includes it bounds `at` from outside the service: the contribution existed no later than that checkpoint.
- Later verification needs no live delegation: the receipt's signature, its inclusion in a cosigned checkpoint, and
  the service's key as pinned by the verifying application. Each application decides whose receipts it trusts.
- Expiry ends the right to make new submissions; it does not erase the attribution of accepted ones.
- Receipts are not endorsements. A delegation grants authority to act; a receipt records that software acting under
  it submitted something. Neither says the identity's owner reviewed it.

## 5b. Long histories: a checkpoint in the log

Decision 9 caps an identity at about 85 settled changes because R8 replays from the first root. With a log, the
witness can publish a **membership checkpoint** for an identity — its settled membership at a log position — and a
verifier can start R8 from the newest checkpoint included in a cosigned log checkpoint, as TUF clients start from a
trusted root and walk forward. The trust added is bounded: the checkpoint is in the public log, so a wrong one is
visible to anyone replaying the identity's records. This should exist before valuable histories accumulate.

## 5c. Delegations in the log (decision 12, option c)

If the witness logs every delegation it learns of, as certificate transparency logs every certificate, a verifier
can require a delegation's inclusion, and the witness then knows every delegation that a subject-key revocation must
outlive. This closes decision 12 without a retention heuristic, at the cost of a log entry per delegation.

## 6. Cost

Verifier code, estimated from reference implementations: signed-note and cosignature checks 150–250 lines; inclusion
80–100; consistency 40–60; total about 300–400 lines in the core, against about 300 lines of headroom (1,500 of
1,800) before deletions. Section 3's deletions (and the encoder simplification, if accepted) pay for part of it.

## 7. Test vectors to pin (same discipline as today: committed, hashed, counted)

- transparency-dev/merkle `testdata/inclusion` (7 sets) and `testdata/consistency` (6 sets), Apache-2.0: each set is
  a valid proof plus about a dozen corruptions (wrong leaf, index ±1, XOR'd index, size ×2 and ÷2, garbage before
  or after, wrong root) that must all fail — exactly our broken-twin style.
- RFC 9162 / RFC 6962 reference hashes (empty tree, leaf and node prefixes 0x00/0x01).
- C2SP signed-note and cosignature examples from the specs, and Go's `golang.org/x/mod/sumdb/note` tests
  (BSD-3-Clause): parsing edge cases, key IDs, unknown-key lines, more than 16 signatures.
- A differential: our inclusion/consistency verifier against Go's or sigstore-js's on random trees (dev only).

## 8. Service side (outside the core) — decisions for the owner

- **Log implementation:** Tessera (transparency-dev, Go) writes tlog-tiles natively and is what Sigstore's Rekor v2
  is built on. Writing our own log is the opposite of prior art. Recommendation: Tessera, in Go, for the log only;
  muid's own witness logic (which records to admit, OAuth binding) can stay JS and append through Tessera's API.
- **Cosigners:** use existing public witnesses that speak tlog-witness rather than running our own (UNVERIFIED which
  operators accept new logs and on what terms — to check before relying on it). Quorum k ≥ 1 + ⌊2n/3⌋.
- **Rollout:** the log can start before cosigners (checkpoints signed by the witness alone still give relying parties
  consistency between their own views); cosigners then close the split-view and backdating gaps.

## 8a. Measured so far

`src/merkle.js` (proposal branch) implements §2's steps 2 and 3, RFC 9162 inclusion and consistency, in 148 lines,
at 100% coverage and mutation score, with ten broken twins. It agrees with all 196 of transparency-dev/merkle's
vectors but one, a pinned difference (it requires 32-byte hashes where upstream compares placeholder roots of any
length). Checking it found one precondition that is not redundant: without `size1 > size2` refused, a genuine proof
from 6 to 11 also verifies from 11 to 6. Trees up to 2^53 − 1 entries are tested with identical leaves.

`src/note.js` (204 lines) implements §2's step 1: C2SP signed notes with Ed25519 log signatures and timestamped
Ed25519 cosignatures, checkpoints with a configured origin, and a k-of-n cosigner quorum whose times are returned.
Keys are configured as standard verifier keys. It verifies the Go checksum database's live checkpoint under the key
published in Go's source, matches Go's note-package vectors with one pinned difference (a repeated line from one key
is refused, where Go skips it; the checkpoint format forbids such lines), and is at 100% coverage and mutation score
with thirteen broken twins. Deviations kept: extension lines are refused; a cosignature time of 2^53 or more cannot
be checked and is refused; signature lines are capped at 64 and notes at 65,536 characters.

`src/receipt.js` (about 95 lines) implements §5a as SPEC C2 (proposal): a receipt signed by a pinned service key,
included in a cosigned checkpoint, with `existedBy` the quorum-th earliest cosignature. 100% coverage and mutation
score, ten broken twins. jscpd caught the first draft copying three helpers from `src/attestation.js`; they are now
shared.

## 9. Order of work (approved 2026-11-04: integration first)

The owner approved judging progress by a working integration: a minimal witness (log, heads, receipts,
checkpoints; cosigners later), then the id page, then a two-application demo (one service accepts forecasts and
issues receipts; another verifies contribution history under its own policy), with the relying-party adapter
(issue #21) built inside it. Within the witness:

1. Pin the vectors; write the inclusion and consistency verifiers test-first (pure functions, small).
2. Signed-note and cosignature verification, test-first, with the C2SP/Go vectors.
3. Spec: replace decision 10 and F5's `lastHead` with checkpoint, inclusion and consistency; model check that an
   honest log never fails consistency (trivial) and a forked one always does.
4. Delete `forked()` and its tests and twins; mutation, twins, review.
5. Service: Tessera log, then cosigners.
