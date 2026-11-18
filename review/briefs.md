# Briefs and open questions

Each brief is one self-contained way to look for a defect in one area; each open question, at the end, is something
not settled or worth challenging. [`README.md`](README.md) says how one is chosen and how what is found is reported.
For a brief, read only the files it names.

## B1. A witness that lies

`src/verifier.js`, `src/merkle.js`, `src/note.js`, `id/records.js` (`currentMembership`).

The witness is trusted to order records, not to tell the truth about them. Look for any answer a dishonest witness
could give that a verifier or the id page accepts when it should not: two signed heads that are not consistent with
one another, a head older than one already seen, an inclusion proof for a different tree size, records omitted from
a list, a statement (settled, notice, cancelled, matured) about a record the witness never showed, a signature by a
key outside its validity period.

## B2. Recovery without the owner's chance to stop it

`witness/witness.js` (search `R11`), `src/membership.js`, `id/records.js`, `model/recovery.mjs`, `SPEC.md` section 5.

Recovery parties can replace an identity's roots only after a waiting period under public notice, which any one
current root can cancel. Look for any sequence in which: the roots change before the wait has passed; notice is never
given or cannot be seen by the owner; a cancel signed by a current root is refused, lost or outrun; fewer parties than
the threshold suffice; a party is accepted without opening its commitment; a second recovery is put under notice
sooner after a cancel than the cooling-off allows.

## B3. What is shown is what is signed

`id/page.js`, `id/index.html`.

Every passkey signature on the id page is made over a record whose fields were shown to the user from the exact
payload to be signed, and any edit after the review withdraws it. For each handler that calls `sign(`, look for a way
the signed bytes can differ from what the panel showed: a field read again after the review, an edit that does not
withdraw, a review superseded by another, an answer from the witness that arrives after a withdrawal and is used, a
signature made after an edit that is still sent, kept or shown.

## B4. Stored state is untrusted

`id/records.js` (`storedRoot`), `id/store.js`, `id/page.js` (everything read from the store).

Anything in the page's IndexedDB may have been written by another tab, an older or newer version of the page, or by
hand. Look for a stored value that makes the page show a section it should not, sign something not reviewed, send a
record for an identity other than the stored root's, throw an error that leaves the page unusable, or put stored
text into the document as anything but text.

## B5. One meaning per byte string

`src/encode.js`, `src/envelope.js`, `src/bytes.js`, `SPEC.md` sections 3 and 4.

A record has exactly one encoding and an encoding exactly one reading. Look for two different byte strings accepted
as the same record, or one byte string read differently by two parts of the code: duplicate keys, key order, number
forms, Unicode normalisation, surrogates, trailing bytes, case of hex, nesting depth, a record re-serialised before
it is hashed or verified.

## B6. Limits at their edges

`src/delegation.js`, `src/verifier.js`, `src/membership.js`, `witness/witness.js`.

Every lifetime, window, epoch, count and size has a stated bound. For each comparison against one, check the exact
boundary value and one either side: expiry at the second it falls due, clock skew applied in the wrong direction,
a contest or recovery window that is one second short, a list one longer than its maximum, an integer beyond the
safe range, a negative or fractional value where a count is expected.

## B7. The witness service under load and abuse

`witness/service.js`, `witness/holdings.js`, `witness/log.js`.

Look for a request, or a cheap stream of them, that makes the service use unbounded memory, time or storage; that
lets one identity's records crowd out another's; that leaves holdings and log disagreeing after a failure between
two writes; or that returns an answer for one identity containing anything of another's.

## B8. A requirement with no test

`SPEC.md`, `tests/`.

Pick one numbered section of `SPEC.md` (a different one each time this brief comes up). List each sentence that
says the code must or must not do something. For each, find the test that would fail if the code stopped doing it.
A finding is a requirement for which no such test exists, or one the code does not meet.

## B9. A test that cannot fail

`tests/` (take one test file each time this brief comes up, largest first).

Look for assertions that pass whatever the code does: a check that something did not happen made before it could
have happened, a wait that returns at once, a value compared with itself or with a value computed by the same code
under test, an error expected by a pattern loose enough to match a different error, a loop over a list that may be
empty.

## B10. The models and the code say the same thing

`model/STATE.md`, `model/tla`, `model/tamarin`, `model/*.mjs`, against `witness/witness.js`, `src/membership.js`,
`id/page.js`.

For one stateful part each time, list the transitions the code can make and the transitions the model has. A finding
is a transition in the code that the model lacks, a guard the model has and the code does not, or a state variable in
the code that the model does not represent.

## B11. Requests replayed or re-addressed

`adapter/relying-party.js`, `adapter/stores.js`, `demo/forecasts.js`, `SPEC.md` sections 8 and 8a.

A relying party credits the identity that owns the key that signed a request. Look for a signed request accepted
twice, accepted by a service or path other than the one it was signed for, accepted after its delegation expired or
its key was retired, or credited to an identity other than the delegating one.

## B12. The build and what it trusts

`.github/workflows/`, `package.json`, `package-lock.json`, `tests/guards/`.

Look for an action, tool or dependency not pinned to an exact version or digest, a workflow step that runs code from
a pull request with more permission than it needs, a test file CI never runs, a guard in `tests/guards/` that can be
satisfied without the property it names holding.

## Open questions

Thinking wanted, not defect hunting. Each is something the maintainers have not settled or would like challenged.
Answer one as an `idea:` issue; say plainly if the answer is that the current approach is right.

- **Q1. Testing the witness as an adversary.** The plan is a set of dishonest witnesses (forked log, withheld
  records, replayed heads, backdated notices) run nightly against the verifier and the id page. Which lies are
  missing from that list, and which of them can no offline verifier catch without a second witness or a monitor?
- **Q2. Faults in the witness service.** The plan is to kill the service at each storage write, duplicate and
  reorder requests, and jump the clock, then check that the log never forked and nothing accepted was lost. What
  other invariants should hold after a crash, and what is the cheapest established way to check implementation
  traces against the TLA+ model in `model/tla`?
- **Q3. A second verifier.** An independent small verifier, fed the same fuzzed records as `src/verifier.js`, would
  expose ambiguities in `SPEC.md`. Which parts of the spec are most likely to be read two ways by two implementers?
- **Q4. Mutation testing of the id page is slow** (each mutant re-runs a 40-test browser suite). What would make it
  an order of magnitude faster without weakening what a surviving mutant means?
- **Q5. What is missing from the threat model** in `SPEC.md` section 1: an attacker, an asset or an assumption that
  the rest of the design quietly depends on?
- **Q6. What would you remove?** Name a mechanism, record type or rule that could be deleted, or replaced by a
  better-understood one, with nothing of value lost.
