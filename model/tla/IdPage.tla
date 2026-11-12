---------------------------- MODULE IdPage ----------------------------
(* The id page's remembered workers (SPEC §8) across the tabs of one browser, checked by TLC.

   The tabs share one stored value: a list of rows (an agent, an audience, a key) and a count, one more with every
   change. Each tab has its own copy of that value (what it last read), at most one review open, requests in flight
   to the witness and to the passkey, and a queue of operations on the store. As in IndexedDB, a tab's operations
   run in the order it made them, each one transaction, and the tab hears of each, in that order, some time after it
   ran: what ran and what the tab then does about it are separate steps, and anything may come between them. The
   other tab's steps, a notice of a change arriving late or never, an edit that withdraws a review, a reload, a
   transaction that aborts, and time passing may all come between any two steps of a tab. An answer to a review
   since withdrawn can arrive after a newer review has begun.

   That a read-write transaction runs alone and commits whole or not at all is the Indexed Database standard's
   statement, taken as given: here it is one step (Exec).

   When a change takes effect: when its transaction commits. When a renewal takes effect: at its read of storage
   after the passkey has answered. A change committed after that read is after the renewal, whenever the renewal's
   hand-off appears; no guarantee is made about the moment of appearing, which no transaction can cover.

   Checked, of every reachable state:
     OneKeyPerAgent        the stored list never holds one agent under two keys;
     NoLostUpdate          the stored list is each committed change applied, in the order committed, to the list as
                           it then was: a Forget removes the row it named and no other, a worker's saving replaces
                           what its agent had under another key or at that audience, and nothing else is touched;
     NoResurrection        no stored row is of a key that was replaced, or is a row that was forgotten, unless it
                           was authorised again since;
     ViewHonest            a tab's copy differs from storage only while a notice or an answer to it is outstanding:
                           it is never a value storage did not hold;
     NoRevival             nothing is handed over for a review that was withdrawn;
     ShownIsSaved          a worker's saving retires exactly the keys its review said it would;
     ReviewedStateIsCurrent   a worker is saved, and a renewal takes effect, only if no change was committed
                           between the state the user reviewed against and that moment, even one that left the list
                           as it was;
     SavedBeforeHandover   no worker is handed its delegation unless its row was committed;
     Unexpired             nothing is handed over that had expired when it was handed over.

   Bounds (the configuration's constants): the tabs, agents, audiences and keys; MaxOps reviews begun by each tab
   (and, in MCIdPage, MaxTotal by the tabs together); MaxIO operations queued by a tab at once; MaxRev committed
   changes; the clock from 0 to MaxTime. What TLC reports is of the model within these bounds, not of the page's
   code: the two are tied by the faults (tests/guards/model-faults.test.mjs).

   Negative controls: each switch is TRUE in the page; FALSE, it is the page with one fault, and TLC must report the
   invariant the script that runs these names beside it. *)
EXTENDS Integers, FiniteSets, Sequences

CONSTANTS
  Tabs, Agents, Auds, Keys,
  InitRows,           \* the list both tabs start with
  MaxTime, Life,      \* the last second explored; a delegation reviewed at t expires at t + Life
  MaxOps, MaxIO, MaxRev,
  Transactional,      \* an update's read and write are one step (FALSE: web storage, a read and then a write)
  FreshWrite,         \* a change is made to what storage holds (FALSE: to the tab's own copy, written over storage)
  ForgetExact,        \* a Forget removes the row shown (FALSE: whatever row has its agent and audience)
  CheckReviewed,      \* a worker is saved only if storage is still the state it was reviewed against
  CheckChanged,       \* storage is read again before the passkey is asked and before a renewal takes effect
  CompareRev,         \* "still the state" means no change was committed (FALSE: the list reads the same)
  CheckExpiry,        \* signed and handed over only while unexpired
  GuardReplies,       \* an answer for a review since withdrawn is dropped
  PublishAfterCommit, \* a worker is handed over only once its transaction has committed
  WithdrawOnChange,   \* whenever a tab's copy changes, what it has open is withdrawn (but for a review's own saving)
  ViewFromStore       \* after an operation, the tab's copy is what storage held (FALSE: what it meant to write)

Rows == [agent : Agents, aud : Auds, key : Keys]
ARow == CHOOSE r \in Rows : TRUE
NoVal == [rev |-> 0, rows |-> {}, g |-> 0]
None == [kind |-> "none", id |-> 0, rows |-> {}, stage |-> "none", exp |-> 0, retires |-> {}]
Flags == {"revived", "unshown", "stale", "unsaved", "expired"}

\* The list with worker w: in place of its agent's rows under another key, and of its own audience's row.
Remember(L, w) == {r \in L : ~(r.agent = w.agent /\ (r.key # w.key \/ r.aud = w.aud))} \cup {w}
\* The keys of w's agent that remembering w replaces.
Retires(L, w) == {r.key : r \in {x \in L : x.agent = w.agent /\ x.key # w.key}}
Without(L, r) == IF ForgetExact THEN L \ {r} ELSE {x \in L : ~(x.agent = r.agent /\ x.aud = r.aud)}
\* Whether two readings of storage are the same state. `g` is the true count of committed changes, which the page
\* cannot see: it sees `rev`.
Same(u, v) == IF CompareRev THEN u.rev = v.rev /\ u.rows = v.rows ELSE u.rows = v.rows

VARIABLES
  now,        \* the time
  store,      \* what is stored: [rev, rows, g]
  view,       \* each tab's copy of it
  told,       \* each tab: a notice of a change is on its way
  pend,       \* each tab's open review, or None
  ops,        \* reviews each tab has begun
  wreq, sreq, \* each tab's requests in flight to the witness and to the passkey
  io,         \* each tab's operations on the store, in the order made: queued, or run and not yet heard of
  ideal,      \* the committed changes applied in order (NoLostUpdate)
  retired,    \* agent and key pairs replaced and not authorised again
  forgotten,  \* rows forgotten and not authorised again
  bad         \* the hand-over rules broken so far

vars == <<now, store, view, told, pend, ops, wreq, sreq, io, ideal, retired, forgotten, bad>>

Init ==
  /\ now = 0 /\ store = [rev |-> 0, rows |-> InitRows, g |-> 0] /\ ideal = InitRows
  /\ view = [t \in Tabs |-> [rev |-> 0, rows |-> InitRows, g |-> 0]] /\ told = [t \in Tabs |-> FALSE]
  /\ pend = [t \in Tabs |-> None] /\ ops = [t \in Tabs |-> 0]
  /\ wreq = [t \in Tabs |-> {}] /\ sreq = [t \in Tabs |-> {}] /\ io = [t \in Tabs |-> <<>>]
  /\ retired = {} /\ forgotten = {} /\ bad = {}

Live(t, q, stage) == pend[t].kind # "none" /\ pend[t].id = q.id /\ pend[t].stage = stage
TellOthers(t) == [u \in Tabs |-> IF u = t THEN told[u] ELSE TRUE]
Op(kind, q, r, reviewed, revived) ==
  [kind |-> kind, req |-> q, row |-> r, reviewed |-> reviewed, revived |-> revived,
   phase |-> "queued", base |-> NoVal, snap |-> NoVal, outcome |-> "none"]
CanQueue(t) == Len(io[t]) < MaxIO
Queue(t, o) == io' = [io EXCEPT ![t] = Append(@, o)]

\* A review begun: of one worker, or of some of the tab's list for renewal. Whatever was open is withdrawn.
Review(t, kind, rows) ==
  /\ ops[t] < MaxOps
  /\ ops' = [ops EXCEPT ![t] = @ + 1]
  /\ LET p == [None EXCEPT !.kind = kind, !.id = ops[t] + 1, !.rows = rows, !.stage = "wait"]
     IN pend' = [pend EXCEPT ![t] = p] /\ wreq' = [wreq EXCEPT ![t] = @ \cup {p}]
  /\ UNCHANGED <<now, store, view, told, sreq, io, ideal, retired, forgotten, bad>>

ReviewWorker(t) == \E w \in Rows : Review(t, "worker", {w})
ReviewRenewal(t) == \E rows \in SUBSET view[t].rows : rows # {} /\ Review(t, "renew", rows)

\* The witness answers: the review is shown, with its expiry and (for a worker) the keys it says it replaces.
WitnessReply(t) == \E q \in wreq[t] :
  /\ wreq' = [wreq EXCEPT ![t] = @ \ {q}]
  /\ LET shown == [q EXCEPT !.stage = "shown", !.exp = now + Life,
                             !.retires = IF q.kind = "worker" THEN UNION {Retires(view[t].rows, w) : w \in q.rows} ELSE {}]
     IN IF Live(t, q, "wait") \/ ~GuardReplies THEN pend' = [pend EXCEPT ![t] = shown] ELSE UNCHANGED pend
  /\ UNCHANGED <<now, store, view, told, ops, sreq, io, ideal, retired, forgotten, bad>>

\* An edit, a change of selection: what is open is withdrawn.
Edit(t) ==
  /\ pend[t].kind # "none"
  /\ pend' = [pend EXCEPT ![t] = None]
  /\ UNCHANGED <<now, store, view, told, ops, wreq, sreq, io, ideal, retired, forgotten, bad>>

\* Sign pressed on a shown review: withdrawn if it has expired; else storage is read before the passkey is asked.
ClickSign(t) ==
  /\ pend[t].stage = "shown"
  /\ IF CheckExpiry /\ now >= pend[t].exp THEN pend' = [pend EXCEPT ![t] = None] /\ UNCHANGED io
     ELSE CanQueue(t) /\ Queue(t, Op("pre", pend[t], ARow, view[t], FALSE)) /\ UNCHANGED pend
  /\ UNCHANGED <<now, store, view, told, ops, wreq, sreq, ideal, retired, forgotten, bad>>

\* The passkey answers. A worker's saving, or a renewal's read of storage, is queued; an answer for a review
\* since withdrawn is dropped, and an expired worker withdrawn.
SignReply(t) == \E q \in sreq[t] :
  /\ sreq' = [sreq EXCEPT ![t] = @ \ {q}]
  /\ LET live == Live(t, q, "asked")
     IN IF ~live /\ GuardReplies THEN UNCHANGED <<pend, io>>
        ELSE IF q.kind = "worker" /\ CheckExpiry /\ now >= q.exp
          THEN pend' = [pend EXCEPT ![t] = IF live THEN None ELSE @] /\ UNCHANGED io
        ELSE CanQueue(t) /\ Queue(t, Op(IF q.kind = "worker" THEN "save" ELSE "read", q, ARow, view[t], ~live)) /\ UNCHANGED pend
  /\ UNCHANGED <<now, store, view, told, ops, wreq, ideal, retired, forgotten, bad>>

\* Forget pressed on a row of the tab's list: what is open is withdrawn, and the row's removal queued.
Forget(t) == \E r \in view[t].rows :
  /\ CanQueue(t) /\ Queue(t, Op("forget", None, r, view[t], FALSE))
  /\ pend' = [pend EXCEPT ![t] = None]
  /\ UNCHANGED <<now, store, view, told, ops, wreq, sreq, ideal, retired, forgotten, bad>>

\* A notice of another tab's change arrives: the tab queues a read of storage.
Arrive(t) ==
  /\ told[t] /\ CanQueue(t) /\ Queue(t, Op("refresh", None, ARow, view[t], FALSE))
  /\ told' = [told EXCEPT ![t] = FALSE]
  /\ UNCHANGED <<now, store, view, pend, ops, wreq, sreq, ideal, retired, forgotten, bad>>

\* The tab's next operation runs: one transaction. A read takes what storage holds. A write commits, or aborts and
\* changes nothing; a worker's saving is refused if storage is no longer the state it was reviewed against.
Ran(t, i, o) == io' = [io EXCEPT ![t][i] = o]
Commit(t, rows) ==
  /\ store.g < MaxRev
  /\ store' = [rev |-> store.rev + 1, rows |-> rows, g |-> store.g + 1]
  /\ told' = TellOthers(t)
Exec(t) == \E i \in 1..Len(io[t]) :
  LET o == io[t][i]
      base == IF o.phase = "read" THEN o.base ELSE IF FreshWrite THEN store ELSE view[t]
      w == CHOOSE r \in (IF o.kind = "save" THEN o.req.rows ELSE {ARow}) : TRUE
  IN /\ o.phase \in {"queued", "read"} /\ \A j \in 1..(i - 1) : io[t][j].phase = "done"
     /\ IF o.kind \in {"pre", "read", "refresh"}
          THEN Ran(t, i, [o EXCEPT !.phase = "done", !.snap = store]) /\ UNCHANGED <<store, told, ideal, retired, forgotten, bad>>
        ELSE IF ~Transactional /\ o.phase = "queued"
          THEN Ran(t, i, [o EXCEPT !.phase = "read", !.base = base]) /\ UNCHANGED <<store, told, ideal, retired, forgotten, bad>>
        ELSE IF o.kind = "save" /\ CheckReviewed /\ ~Same(base, o.reviewed)
          THEN Ran(t, i, [o EXCEPT !.phase = "done", !.snap = base, !.outcome = "changed"])
               /\ UNCHANGED <<store, told, ideal, retired, forgotten, bad>>
        ELSE \/ /\ o.kind = "save"
                /\ Commit(t, Remember(base.rows, w))
                /\ ideal' = Remember(ideal, w)
                /\ retired' = (retired \cup {[agent |-> w.agent, key |-> k] : k \in Retires(ideal, w)}) \ {[agent |-> w.agent, key |-> w.key]}
                /\ forgotten' = forgotten \ {w}
                /\ bad' = bad \cup (IF Retires(store.rows, w) # o.req.retires THEN {"unshown"} ELSE {})
                              \cup (IF store.g # o.reviewed.g THEN {"stale"} ELSE {})
                /\ Ran(t, i, [o EXCEPT !.phase = "done", !.snap = store', !.outcome = "saved"])
             \/ /\ o.kind = "forget"
                /\ Commit(t, Without(base.rows, o.row))
                /\ ideal' = ideal \ {o.row}
                /\ forgotten' = IF o.row \in ideal THEN forgotten \cup {o.row} ELSE forgotten
                /\ Ran(t, i, [o EXCEPT !.phase = "done", !.snap = store', !.outcome = "saved"])
                /\ UNCHANGED <<retired, bad>>
             \/ /\ Ran(t, i, [o EXCEPT !.phase = "done", !.snap = store, !.outcome = "unsaved"])   \* it aborts
                /\ UNCHANGED <<store, told, ideal, retired, forgotten, bad>>
     /\ UNCHANGED <<now, view, pend, ops, wreq, sreq>>

\* The tab hears of its oldest operation, and acts on it.
HandOver(t, q, more) ==
  LET live == Live(t, q, "asked")
      late == now >= q.exp
  IN IF ~live /\ GuardReplies THEN UNCHANGED <<pend, bad>>
     ELSE IF late /\ CheckExpiry THEN pend' = [pend EXCEPT ![t] = IF live THEN None ELSE @] /\ UNCHANGED bad
     ELSE /\ pend' = [pend EXCEPT ![t] = IF live THEN None ELSE @]
          /\ bad' = bad \cup more \cup (IF live THEN {} ELSE {"revived"}) \cup (IF late THEN {"expired"} ELSE {})
Cont(t) ==
  /\ Len(io[t]) > 0 /\ Head(io[t]).phase = "done"
  /\ io' = [io EXCEPT ![t] = Tail(@)]
  /\ LET o == Head(io[t])
         q == o.req
         w == CHOOSE r \in (IF o.kind = "save" THEN q.rows ELSE {ARow}) : TRUE
         meant == [o.snap EXCEPT !.rows = IF o.kind = "save" THEN Remember(view[t].rows, w) ELSE view[t].rows \ {o.row}]
     IN CASE o.kind = "refresh" ->
               view' = [view EXCEPT ![t] = o.snap] /\ pend' = [pend EXCEPT ![t] = None] /\ UNCHANGED <<sreq, bad>>
          [] o.kind = "pre" ->
               IF CheckChanged /\ ~Same(o.snap, view[t])
                 THEN view' = [view EXCEPT ![t] = o.snap] /\ pend' = [pend EXCEPT ![t] = None] /\ UNCHANGED <<sreq, bad>>
               ELSE /\ sreq' = [sreq EXCEPT ![t] = @ \cup {[q EXCEPT !.stage = "asked"]}]
                    /\ pend' = [pend EXCEPT ![t] = IF Live(t, q, "shown") THEN [q EXCEPT !.stage = "asked"] ELSE @]
                    /\ UNCHANGED <<view, bad>>
          [] o.kind = "read" ->
               IF CheckChanged /\ ~Same(o.snap, view[t])
                 THEN view' = [view EXCEPT ![t] = o.snap] /\ pend' = [pend EXCEPT ![t] = None] /\ UNCHANGED <<sreq, bad>>
               ELSE /\ HandOver(t, q, IF o.snap.g # view[t].g \/ ~(q.rows \subseteq o.snap.rows) THEN {"stale"} ELSE {})
                    /\ UNCHANGED <<view, sreq>>
          [] o.kind = "forget" ->
               /\ view' = [view EXCEPT ![t] = IF o.outcome = "unsaved" /\ ~ViewFromStore THEN meant ELSE o.snap]
               /\ pend' = [pend EXCEPT ![t] = IF WithdrawOnChange /\ view'[t] # view[t] THEN None ELSE @]
               /\ UNCHANGED <<sreq, bad>>
          [] o.kind = "save" /\ o.outcome = "saved" ->
               /\ view' = [view EXCEPT ![t] = o.snap]
               /\ IF ~Live(t, q, "asked") /\ GuardReplies
                    THEN pend' = [pend EXCEPT ![t] = IF WithdrawOnChange /\ view'[t] # view[t] THEN None ELSE @] /\ UNCHANGED bad
                  ELSE HandOver(t, q, {})
               /\ UNCHANGED sreq
          [] o.kind = "save" /\ o.outcome = "changed" ->
               /\ view' = [view EXCEPT ![t] = o.snap]
               /\ pend' = [pend EXCEPT ![t] = None] /\ UNCHANGED <<sreq, bad>>
          [] o.kind = "save" /\ o.outcome = "unsaved" ->
               /\ view' = [view EXCEPT ![t] = IF ViewFromStore THEN o.snap ELSE meant]
               /\ IF PublishAfterCommit
                    THEN /\ pend' = [pend EXCEPT ![t] = IF WithdrawOnChange /\ view'[t] # view[t] THEN None
                                                        ELSE IF Live(t, q, "asked") THEN [q EXCEPT !.stage = "shown"] ELSE @]
                         /\ UNCHANGED bad
                  ELSE HandOver(t, q, {"unsaved"})
               /\ UNCHANGED sreq
  /\ UNCHANGED <<now, store, told, ops, wreq, ideal, retired, forgotten>>

\* The tab is loaded again: it reads storage, and everything it had open, queued or in flight is gone.
Reload(t) ==
  /\ \A i \in 1..Len(io[t]) : io[t][i].phase # "read"
  /\ view' = [view EXCEPT ![t] = store] /\ told' = [told EXCEPT ![t] = FALSE] /\ pend' = [pend EXCEPT ![t] = None]
  /\ wreq' = [wreq EXCEPT ![t] = {}] /\ sreq' = [sreq EXCEPT ![t] = {}] /\ io' = [io EXCEPT ![t] = <<>>]
  /\ UNCHANGED <<now, store, ops, ideal, retired, forgotten, bad>>

Tick ==
  /\ now < MaxTime /\ now' = now + 1
  /\ UNCHANGED <<store, view, told, pend, ops, wreq, sreq, io, ideal, retired, forgotten, bad>>

Next ==
  \/ Tick
  \/ \E t \in Tabs : ReviewWorker(t) \/ ReviewRenewal(t) \/ WitnessReply(t) \/ Edit(t) \/ ClickSign(t) \/ SignReply(t)
                     \/ Forget(t) \/ Arrive(t) \/ Exec(t) \/ Cont(t) \/ Reload(t)

Spec == Init /\ [][Next]_vars

TypeOK ==
  /\ now \in 0..MaxTime /\ store.rows \subseteq Rows /\ ideal \subseteq Rows /\ store.g \in 0..MaxRev
  /\ told \in [Tabs -> BOOLEAN] /\ ops \in [Tabs -> 0..MaxOps] /\ bad \subseteq Flags
  /\ \A t \in Tabs : Len(io[t]) <= MaxIO /\ view[t].rows \subseteq Rows
  /\ forgotten \subseteq Rows /\ retired \subseteq [agent : Agents, key : Keys]

OneKeyPerAgent == \A r, s \in store.rows : r.agent = s.agent => r.key = s.key
NoLostUpdate == store.rows = ideal \/ \E t \in Tabs : \E i \in 1..Len(io[t]) : io[t][i].phase = "read"
NoResurrection == \A r \in store.rows : r \notin forgotten /\ [agent |-> r.agent, key |-> r.key] \notin retired
ViewHonest == \A t \in Tabs : view[t] = store \/ told[t] \/ Len(io[t]) > 0
NoRevival == "revived" \notin bad
ShownIsSaved == "unshown" \notin bad
ReviewedStateIsCurrent == "stale" \notin bad
SavedBeforeHandover == "unsaved" \notin bad
Unexpired == "expired" \notin bad
=============================================================================
