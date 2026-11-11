---------------------------- MODULE WitnessOutbox ----------------------------
(* The witness service's outbox (witness/service.js, SPEC §5), for one identity, checked by TLC.

   The service keeps one entry for the identity: the records held, and at most one outbox (the entry a decision
   made, with the texts it signed, not yet known to be logged). A request runs as the service's `commit` does:
     first update   what the outbox holds is appended to the log (again, if need be), the decision is made against
                    the entry the outbox held, and its own entry and texts are kept as the new outbox;
     second update  the outbox is appended and its entry kept; only then is the request answered.
   An update is the store's: one at a time for the identity, and kept whole when it ends or not at all. Between any
   two steps another request's steps may come; a request may die at any step (a crash, a failing store, a log that
   refuses), keeping nothing of the update it was in; and the log may take an entry and lose its answer, which the
   request sees as a failure.

   A text is [v, id]: the v-th record of the identity, from the decision numbered id. Two texts of one v from two
   decisions are rivals: the witness signed two histories.

   Checked, of every reachable state:
     NoRival          the log never holds two rivals;
     ServedIsLogged   every text a request was answered with is in the log;
     HeldIsLogged     every record of the kept entry (what GET .../records serves) is in the log;
     LogInOrder       a text is in the log only after a text of every earlier v;
     HeldIsChain      the kept entry is the identity's records in order, one of each v.

   Bounds: the requests in flight at once (Procs); MaxSign texts signed; MaxLog log entries (retries repeat them).

   Not modelled: what the decisions are (witness.js, and its own models); more than one identity (each has its own
   entry and its own queue); that anything is ever logged at all (a log that always fails logs nothing).

   Negative controls: each switch is TRUE in the service; FALSE, it is the service with one fault, and TLC must
   report the invariant the script names beside it. *)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
  Procs, MaxSign, MaxLog,
  SettleFirst,        \* a decision is made against the outbox's entry, once the outbox is appended (FALSE: against
                      \* the records held, the outbox ignored: the fault review round 8 found)
  AppendOutbox,       \* the outbox is appended before its entry is taken as the entry (FALSE: taken unappended)
  StageFirst,         \* what is signed is kept in the outbox before it is appended (FALSE: appended, then kept)
  AnswerAfterLogged,  \* a request is answered with what it signed only after the second update
  ServeSettled,       \* while an outbox waits, the records held are those before it (FALSE: those it would make)
  Serialised          \* the store runs one update of the identity at a time

VARIABLES
  store,   \* the kept entry: [held, outbox], the outbox a sequence of none or one [entry, texts]
  log,     \* the transparency log: the texts appended, in order
  lock,    \* the requests inside an update
  pc,      \* each request's step
  loc,     \* each request's own: the texts still to append, the entry it works on, what it will answer
  next,    \* texts signed so far
  served   \* the texts requests were answered with

vars == <<store, log, lock, pc, loc, next, served>>
Range(s) == {s[i] : i \in DOMAIN s}
Idle == [todo |-> <<>>, e |-> <<>>, val |-> <<>>]

Init ==
  /\ store = [held |-> <<>>, outbox |-> <<>>]
  /\ log = <<>> /\ lock = {} /\ next = 0 /\ served = {}
  /\ pc = [p \in Procs |-> "idle"]
  /\ loc = [p \in Procs |-> Idle]

CanEnter == ~Serialised \/ lock = {}
Leave(p) == lock' = lock \ {p}
\* What an update is given: the outbox to append and the entry it holds, or nothing to append and the records held.
Given(settle) ==
  IF settle /\ store.outbox # <<>> THEN [todo |-> IF AppendOutbox THEN store.outbox[1].texts ELSE <<>>, e |-> store.outbox[1].entry, val |-> <<>>]
  ELSE [todo |-> <<>>, e |-> store.held, val |-> <<>>]

\* A request enters its first update.
Begin(p) ==
  /\ pc[p] = "idle" /\ CanEnter
  /\ lock' = lock \cup {p}
  /\ pc' = [pc EXCEPT ![p] = "first"]
  /\ loc' = [loc EXCEPT ![p] = Given(SettleFirst)]
  /\ UNCHANGED <<store, log, next, served>>

\* The log takes the next text and says so.
Logged(p) ==
  /\ pc[p] \in {"first", "second", "direct"} /\ loc[p].todo # <<>>
  /\ log' = Append(log, Head(loc[p].todo))
  /\ loc' = [loc EXCEPT ![p].todo = Tail(@)]
  /\ UNCHANGED <<store, lock, pc, next, served>>

\* The log takes the next text and its answer is lost: the update fails, and nothing of it is kept.
AppendLost(p) ==
  /\ pc[p] \in {"first", "second", "direct"} /\ loc[p].todo # <<>>
  /\ log' = Append(log, Head(loc[p].todo))
  /\ Leave(p) /\ pc' = [pc EXCEPT ![p] = "idle"] /\ loc' = [loc EXCEPT ![p] = Idle]
  /\ UNCHANGED <<store, next, served>>

\* A request that signs nothing (a head still fresh, a record already held, a refusal): the entry is kept as
\* settled, and the answer is of it.
Read(p) ==
  /\ pc[p] = "first" /\ loc[p].todo = <<>>
  /\ store' = [held |-> loc[p].e, outbox |-> <<>>]
  /\ served' = served \cup Range(loc[p].e)
  /\ Leave(p) /\ pc' = [pc EXCEPT ![p] = "idle"] /\ loc' = [loc EXCEPT ![p] = Idle]
  /\ UNCHANGED <<log, next>>

\* A request that signs k texts: kept in the outbox with the entry they make, and the first update ends.
Sign(p, k) ==
  /\ pc[p] = "first" /\ loc[p].todo = <<>> /\ next + k <= MaxSign
  /\ LET e == loc[p].e
         texts == [i \in 1..k |-> [v |-> Len(e) + i, id |-> next + 1]]
         new == e \o texts
     IN IF StageFirst
        THEN /\ store' = [held |-> IF ServeSettled THEN e ELSE new, outbox |-> <<[entry |-> new, texts |-> texts]>>]
             /\ Leave(p) /\ pc' = [pc EXCEPT ![p] = "between"]
             /\ loc' = [loc EXCEPT ![p] = [todo |-> <<>>, e |-> <<>>, val |-> texts]]
             /\ served' = IF AnswerAfterLogged THEN served ELSE served \cup Range(texts)
        ELSE /\ pc' = [pc EXCEPT ![p] = "direct"]
             /\ loc' = [loc EXCEPT ![p] = [todo |-> texts, e |-> new, val |-> texts]]
             /\ UNCHANGED <<store, lock, served>>
  /\ next' = next + k
  /\ UNCHANGED log

\* Without an outbox: once appended, the entry is kept and the request answered.
Keep(p) ==
  /\ pc[p] = "direct" /\ loc[p].todo = <<>>
  /\ store' = [held |-> loc[p].e, outbox |-> <<>>]
  /\ served' = served \cup Range(loc[p].val)
  /\ Leave(p) /\ pc' = [pc EXCEPT ![p] = "idle"] /\ loc' = [loc EXCEPT ![p] = Idle]
  /\ UNCHANGED <<log, next>>

\* The request enters its second update: whatever outbox is there (its own, or a later request's) is to be appended.
Again(p) ==
  /\ pc[p] = "between" /\ CanEnter
  /\ lock' = lock \cup {p}
  /\ pc' = [pc EXCEPT ![p] = "second"]
  /\ loc' = [loc EXCEPT ![p] = [Given(TRUE) EXCEPT !.val = loc[p].val]]
  /\ UNCHANGED <<store, log, next, served>>

\* The second update ends: the settled entry is kept, and the request is answered with what it signed.
Finish(p) ==
  /\ pc[p] = "second" /\ loc[p].todo = <<>>
  /\ store' = [held |-> loc[p].e, outbox |-> <<>>]
  /\ served' = served \cup Range(loc[p].val)
  /\ Leave(p) /\ pc' = [pc EXCEPT ![p] = "idle"] /\ loc' = [loc EXCEPT ![p] = Idle]
  /\ UNCHANGED <<log, next>>

\* A request dies where it is: a crash, a store that fails, a log that refuses. Nothing of its update is kept.
Die(p) ==
  /\ pc[p] # "idle"
  /\ Leave(p) /\ pc' = [pc EXCEPT ![p] = "idle"] /\ loc' = [loc EXCEPT ![p] = Idle]
  /\ UNCHANGED <<store, log, next, served>>

Next == \E p \in Procs : \/ Begin(p) \/ Logged(p) \/ AppendLost(p) \/ Read(p) \/ Sign(p, 1) \/ Sign(p, 2)
                         \/ Keep(p) \/ Again(p) \/ Finish(p) \/ Die(p)
Spec == Init /\ [][Next]_vars
Bounded == Len(log) <= MaxLog

NoRival == \A i, j \in DOMAIN log : log[i].v = log[j].v => log[i] = log[j]
ServedIsLogged == served \subseteq Range(log)
HeldIsLogged == Range(store.held) \subseteq Range(log)
LogInOrder == \A i \in DOMAIN log : \A k \in 1..(log[i].v - 1) : \E j \in 1..(i - 1) : log[j].v = k
HeldIsChain == \A i \in DOMAIN store.held : store.held[i].v = i
=============================================================================
