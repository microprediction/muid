---------------------------- MODULE IdRoot ----------------------------
(* The id page's stored root (SPEC §8) across the tabs of one browser, checked by TLC.

   The tabs share one stored root, or none. A tab holds its own copy (what it last read) and at most one job: making
   a root (its own identity's, or one joining another's), registering a root with the witness, or co-signing as a
   joining root. Each job is several steps (the passkey, the write, the witness, the mark), and between any two the
   other tab's steps, a notice of a change, a reload, or the browser's storage being cleared may come. A write to
   the stored root is one transaction, as the Indexed Database standard states: here one step.

   Checked, of every reachable state:
     NeverOverwritten        no write replaces one root with another;
     JoiningNeverRegistered  the witness is never sent a joining root as an identity of its own;
     MarkedIsTaken           a stored root is marked registered only if the witness took it;
     MemberIsCosigned        a stored root is marked the identity's only if the witness took its co-signature.

   Bounds: the tabs; MaxRoots roots made; MaxClears clearings of storage; MaxLoads reloads.

   Negative controls: each switch is TRUE in the page; FALSE, it is the page with one fault (the last two, the page
   as it was before review #74), and TLC must report the invariant the script names beside it. *)
EXTENDS Integers, FiniteSets

CONSTANTS
  Tabs, MaxRoots, MaxClears, MaxLoads,
  CasRoot,    \* a root is written only while storage holds the root the write was decided for
  OwnOnly,    \* a tab registers after making a root only if its own root was the one stored
  MarkSent    \* the mark after the witness answers is made on the root that was sent (FALSE: the tab's copy then)

None == [id |-> 0, joining |-> FALSE, reg |-> FALSE, cos |-> FALSE, mem |-> FALSE]
Idle == [kind |-> "idle", stage |-> "none", joining |-> FALSE, r |-> None]

VARIABLES
  store,    \* the stored root, or None
  view,     \* each tab's copy
  told,     \* each tab: a notice of a change is on its way
  job,      \* each tab's job
  next,     \* roots made so far
  clears, loads,
  joiners,  \* the roots made to join
  wreg,     \* roots the witness was sent as identities of their own
  wmem,     \* roots whose co-signature the witness took
  over      \* a write replaced one root with another

vars == <<store, view, told, job, next, clears, loads, joiners, wreg, wmem, over>>

Init ==
  /\ store = None /\ view = [t \in Tabs |-> None] /\ told = [t \in Tabs |-> FALSE] /\ job = [t \in Tabs |-> Idle]
  /\ next = 0 /\ clears = 0 /\ loads = 0 /\ joiners = {} /\ wreg = {} /\ wmem = {} /\ over = FALSE

Others(t) == [u \in Tabs |-> IF u = t THEN told[u] ELSE TRUE]
\* What a tab with nothing else to do sends again (its outbox): a registration, or a kept co-signature.
Outbox(r) == IF r.id # 0 /\ ~r.joining /\ ~r.reg THEN [Idle EXCEPT !.kind = "register", !.stage = "send", !.r = r]
             ELSE IF r.cos THEN [Idle EXCEPT !.kind = "cosign", !.stage = "send", !.r = r]
             ELSE Idle

\* Create or Join pressed: storage is read; a root found there is adopted, else a passkey is made.
Start(t, j) ==
  /\ job[t].kind = "idle" /\ view[t].id = 0 /\ next < MaxRoots
  /\ IF store.id # 0 THEN view' = [view EXCEPT ![t] = store] /\ UNCHANGED <<job, next, joiners>>
     ELSE /\ next' = next + 1
          /\ job' = [job EXCEPT ![t] = [kind |-> "create", stage |-> "passkey", joining |-> j, r |-> [None EXCEPT !.id = next + 1, !.joining = j]]]
          /\ joiners' = IF j THEN joiners \cup {next + 1} ELSE joiners
          /\ UNCHANGED view
  /\ UNCHANGED <<store, told, clears, loads, wreg, wmem, over>>

\* The passkey is made: the root is written if none is there; whatever is there is the tab's root from now.
Write(t) ==
  /\ job[t].kind = "create"
  /\ LET made == store.id = 0 \/ ~CasRoot
         after == IF made THEN job[t].r ELSE store
     IN /\ store' = after /\ over' = (over \/ (made /\ store.id # 0))
        /\ told' = IF made THEN Others(t) ELSE told
        /\ view' = [view EXCEPT ![t] = after]
        /\ job' = [job EXCEPT ![t] = IF ~job[t].joining /\ (made \/ ~OwnOnly)
                                        THEN [Idle EXCEPT !.kind = "register", !.stage = "send", !.r = after] ELSE Idle]
  /\ UNCHANGED <<next, clears, loads, joiners, wreg, wmem>>

\* The witness is sent the job's root, or its co-signature, and takes it.
Send(t) ==
  /\ job[t].stage = "send"
  /\ job' = [job EXCEPT ![t].stage = "sent"]
  /\ IF job[t].kind = "register" THEN wreg' = wreg \cup {job[t].r.id} /\ UNCHANGED wmem
     ELSE wmem' = wmem \cup {job[t].r.id} /\ UNCHANGED wreg
  /\ UNCHANGED <<store, view, told, next, clears, loads, joiners, over>>

\* The witness's answer arrives: the root is marked, if storage still holds the one the mark is for.
Mark(t) ==
  /\ job[t].stage = "sent"
  /\ LET mine == IF MarkSent THEN job[t].r.id ELSE view[t].id
         made == store.id # 0 /\ store.id = mine
         after == IF ~made THEN store
                  ELSE IF job[t].kind = "register" THEN [store EXCEPT !.reg = TRUE]
                  ELSE [store EXCEPT !.cos = FALSE, !.joining = FALSE, !.reg = TRUE, !.mem = TRUE]
     IN store' = after /\ view' = [view EXCEPT ![t] = after] /\ told' = IF made THEN Others(t) ELSE told
  /\ job' = [job EXCEPT ![t] = Idle]
  /\ UNCHANGED <<next, clears, loads, joiners, wreg, wmem, over>>

\* A joining tab is given a change that adds its root, and its passkey signs it: the co-signature is kept, if
\* storage still holds that root, and then sent.
Cosign(t) ==
  /\ job[t].kind = "idle" /\ view[t].id # 0 /\ view[t].joining /\ ~view[t].cos
  /\ LET made == store.id = view[t].id
         after == IF made THEN [store EXCEPT !.cos = TRUE] ELSE store
     IN /\ store' = after /\ view' = [view EXCEPT ![t] = after] /\ told' = IF made THEN Others(t) ELSE told
        /\ job' = [job EXCEPT ![t] = IF made THEN [Idle EXCEPT !.kind = "cosign", !.stage = "send", !.r = after] ELSE Idle]
  /\ UNCHANGED <<next, clears, loads, joiners, wreg, wmem, over>>

\* A notice arrives: the tab reads storage. What it was doing goes on.
Notice(t) ==
  /\ told[t] /\ told' = [told EXCEPT ![t] = FALSE] /\ view' = [view EXCEPT ![t] = store]
  /\ UNCHANGED <<store, job, next, clears, loads, joiners, wreg, wmem, over>>

\* The tab is loaded again: it reads storage, drops what it was doing, and sends again what is kept to be sent.
Reload(t) ==
  /\ loads < MaxLoads /\ loads' = loads + 1
  /\ view' = [view EXCEPT ![t] = store] /\ told' = [told EXCEPT ![t] = FALSE] /\ job' = [job EXCEPT ![t] = Outbox(store)]
  /\ UNCHANGED <<store, next, clears, joiners, wreg, wmem, over>>

\* The browser's storage for the site is cleared. No tab is told.
Clear ==
  /\ clears < MaxClears /\ clears' = clears + 1 /\ store' = None
  /\ UNCHANGED <<view, told, job, next, loads, joiners, wreg, wmem, over>>

Next == Clear \/ \E t \in Tabs : Start(t, TRUE) \/ Start(t, FALSE) \/ Write(t) \/ Send(t) \/ Mark(t) \/ Cosign(t) \/ Notice(t) \/ Reload(t)
Spec == Init /\ [][Next]_vars

TypeOK == next \in 0..MaxRoots /\ store.id \in 0..MaxRoots /\ wreg \subseteq 1..MaxRoots /\ wmem \subseteq 1..MaxRoots
NeverOverwritten == ~over
JoiningNeverRegistered == wreg \cap joiners = {}
MarkedIsTaken == store.reg => store.id \in wreg \cup wmem
MemberIsCosigned == store.mem => store.id \in wmem
=============================================================================
