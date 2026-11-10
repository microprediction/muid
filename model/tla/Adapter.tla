---------------------------- MODULE Adapter ----------------------------
(* The relying-party adapter (SPEC §7) against an attacker who holds a delegate's key, checked by TLC.

   An honest witness signs heads as time passes and may revoke the delegation once; a head signed at or after the
   revocation carries it, and none before does (R9, the witness keeps a subject-key revocation for good). The
   attacker signs claims under the delegation with any time it likes (C1's residual) and presents any claim with any
   head the witness has signed, to either worker, at any moment. Each worker has its own clock, within MaxOffset of
   real time, and they share one durable store: the claim ids consumed, each kept until `until` plus Grace, and the
   newest head remembered (decision 10). A request is verified without memory first, outside any lock, then in one
   transaction against the store as it stands then, where its head is remembered if newer and its claim consumed if
   absent; only then is it dispatched. Between the two steps anything may happen: the other worker's requests, a
   cleanup of expired ids, a restart that abandons the request, or time passing.

   Checked: each claim is dispatched at most once (AtMostOnce); nothing is dispatched once the store remembers a
   revoking head (NoRevival); and a request is verified at most MaxStaleness + MaxOffset after the revocation, the
   limit no offline verifier can beat, since a withheld newer head leaves it with inputs identical to a world in
   which nothing was revoked (FreshnessBound). Negative controls, each of which TLC must report: with Grace below the
   largest difference between the workers' clocks, or without the claim's until checked at the transaction (the
   adapter's own bug, which this model found), AtMostOnce fails; with FreshnessBound's limit one second tighter, it
   fails, so the limit is reached. *)
EXTENDS Integers, FiniteSets

CONSTANTS
  Workers,        \* the relying party's instances
  Names,          \* claims the attacker may sign, before their times are chosen
  MaxTime,        \* the last real second explored
  DelegExp,       \* the delegation is valid from 0 to DelegExp - 1 (D1, with nbf = 0)
  MaxStaleness,   \* R9
  MaxClaimAge,    \* C1
  Skew,           \* how far after a verifier's now a signer's time may be (F5, C1)
  MaxOffset,      \* each worker's clock is within this of real time
  Grace,          \* a consumed id is kept until `until` plus this (SPEC §7)
  Offset,         \* the workers' clock offsets: a function Workers -> -MaxOffset..MaxOffset
  CheckAtCommit,  \* TRUE in the adapter: the claim's until checked by the clock at the transaction (negative control: FALSE)
  Tighten         \* 0; 1 in the negative control that shows FreshnessBound's limit is reached

NONE == -1
Times == 0..MaxTime
NoHead == [at |-> -1, rev |-> FALSE]                                \* an empty memory: older than any head
Idle == [claim |-> [name |-> 0, at |-> -1], head |-> NoHead, t |-> -1] \* a worker between requests

VARIABLES
  now,          \* real time
  revokedAt,    \* when the witness revoked the delegation, or NONE
  consumed,     \* the store's consumed ids: a function from claims to their kept-until time, or NONE
  last,         \* the store's remembered head, or NoHead
  pc,           \* each worker's request between its two steps: [claim, head, t], or Idle
  count,        \* how many times each claim has been dispatched, counted to 2
  late,         \* TRUE once a dispatch was verified past FreshnessBound's limit
  revSeen       \* TRUE once the store has remembered a revoking head

vars == <<now, revokedAt, consumed, last, pc, count, late, revSeen>>

Local(w) == now + Offset[w] \* a worker's clock

AllClaims == [name : Names, at : Times]
AllHeads == [at : Times, rev : BOOLEAN]

\* What the attacker can present, derived rather than stored: the honest witness signs a head every second, and the
\* attacker may withhold any; a head carries the revocation from its second on, and one signed in that second before
\* it does not. The attacker holds the delegate's key, so every claim is signed.
Heads == {[at |-> t, rev |-> revokedAt # NONE /\ t >= revokedAt] : t \in 0..now}
         \cup (IF revokedAt = NONE THEN {} ELSE {[at |-> revokedAt, rev |-> FALSE]})

TypeOK ==
  /\ now \in Times
  /\ revokedAt \in {NONE} \cup Times
  /\ DOMAIN consumed = AllClaims /\ \A c \in AllClaims : consumed[c] = NONE \/ consumed[c] \in Int
  /\ last \in {NoHead} \cup AllHeads
  /\ DOMAIN pc = Workers
  /\ \A w \in Workers : pc[w] = Idle \/ (pc[w].claim \in AllClaims /\ pc[w].head \in AllHeads /\ pc[w].t \in Int)
  /\ count \in [AllClaims -> 0..2] /\ late \in BOOLEAN
  /\ revSeen \in BOOLEAN

Init ==
  /\ now = 0
  /\ revokedAt = NONE
  /\ consumed = [c \in AllClaims |-> NONE]
  /\ last = NoHead
  /\ pc = [w \in Workers |-> Idle]
  /\ count = [c \in AllClaims |-> 0]
  /\ late = FALSE
  /\ revSeen = FALSE

\* Real time passes.
Tick == /\ now < MaxTime /\ now' = now + 1 /\ UNCHANGED <<revokedAt, consumed, last, pc, count, late, revSeen>>

\* The witness revokes the delegation, once.
Revoke == /\ revokedAt = NONE /\ revokedAt' = now /\ UNCHANGED <<now, consumed, last, pc, count, late, revSeen>>

\* F5 and C1 without memory, at the worker's time t: the head fresh and not revoking, the claim's time within its age
\* and the skew, both inside the delegation's window.
VerifiesAlone(c, h, t) ==
  /\ h.at >= t - MaxStaleness /\ h.at <= t + Skew /\ ~h.rev
  /\ t < DelegExp
  /\ c.at >= t - MaxClaimAge /\ c.at <= t + Skew /\ c.at < DelegExp

\* Step one: any claim with any head reaches a worker, which verifies it without memory.
Begin(w, c, h) ==
  /\ pc[w] = Idle /\ h \in Heads
  /\ VerifiesAlone(c, h, Local(w))
  /\ pc' = [pc EXCEPT ![w] = [claim |-> c, head |-> h, t |-> Local(w)]]
  /\ UNCHANGED <<now, revokedAt, consumed, last, count, late, revSeen>>

\* Decision 10's order for heads of one identity and membership: a later at, or of one at, one holding every
\* revocation of the other.
Newer(h, l) == h.at > l.at \/ (h.at = l.at /\ (h.rev \/ ~l.rev))

\* Step two, one transaction: remember the head if newer; refuse a head older than memory, or any request once memory
\* holds a revocation (R10), or a claim whose until has passed by the worker's clock now (not at step one: a request
\* that waited may otherwise outlive its id's stay in the store, which TLC found); consume the claim if absent;
\* dispatch.
Commit(w) ==
  /\ pc[w] # Idle
  /\ LET r == pc[w]
         mem == IF Newer(r.head, last) THEN r.head ELSE last
     IN /\ last' = mem
        /\ revSeen' = (revSeen \/ mem.rev)
        /\ pc' = [pc EXCEPT ![w] = Idle]
        /\ IF r.head.at >= mem.at /\ ~mem.rev /\ (CheckAtCommit => Local(w) < r.claim.at + MaxClaimAge + 1) /\ consumed[r.claim] = NONE
           THEN /\ consumed' = [consumed EXCEPT ![r.claim] = r.claim.at + MaxClaimAge + 1 + Grace]
                /\ count' = [count EXCEPT ![r.claim] = IF @ < 2 THEN @ + 1 ELSE 2]
                /\ late' = (late \/ (revokedAt # NONE /\ r.t - Offset[w] > revokedAt + MaxStaleness + MaxOffset - Tighten))
           ELSE UNCHANGED <<consumed, count, late>>
  /\ UNCHANGED <<now, revokedAt>>

\* A worker drops the ids whose kept-until time has passed by its own clock.
Cleanup(w) ==
  /\ consumed' = [c \in AllClaims |-> IF consumed[c] # NONE /\ consumed[c] <= Local(w) THEN NONE ELSE consumed[c]]
  /\ UNCHANGED <<now, revokedAt, last, pc, count, late, revSeen>>

\* A worker restarts: the request between its steps is abandoned; the store is durable.
Restart(w) == /\ pc[w] # Idle /\ pc' = [pc EXCEPT ![w] = Idle] /\ UNCHANGED <<now, revokedAt, consumed, last, count, late, revSeen>>

Next ==
  \/ Tick \/ Revoke
  \/ \E w \in Workers : \/ Commit(w) \/ Cleanup(w) \/ Restart(w)
                       \/ \E c \in AllClaims, h \in Heads : Begin(w, c, h)

Spec == Init /\ [][Next]_vars

\* Each claim is dispatched at most once, across every worker.
AtMostOnce == \A c \in AllClaims : count[c] <= 1

\* Nothing is dispatched once the store remembers a revoking head: an action property.
NoRevival == [][revSeen => count' = count]_vars

\* The limit an offline verifier cannot beat: a request is verified at most MaxStaleness + MaxOffset after the
\* revocation, in real time. A head without it was signed no later than its second (in that second, before it), and
\* a worker whose clock is behind accepts that head until its own time passes its at + MaxStaleness; TLC showed the
\* bound is reached, so it is inclusive.
FreshnessBound == ~late
=============================================================================
