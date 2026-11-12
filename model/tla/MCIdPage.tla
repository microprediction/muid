---------------------------- MODULE MCIdPage ----------------------------
EXTENDS IdPage, TLC
CONSTANTS a, b, x, y, k1, k2, t1, t2, MaxTotal
\* Both tabs begin with agent a under key k1 at audience x.
IdPageOne == {[agent |-> a, aud |-> x, key |-> k1]}
\* ... and agent b under k1 at x as well.
IdPageTwo == {[agent |-> a, aud |-> x, key |-> k1], [agent |-> b, aud |-> x, key |-> k1]}
\* ... or agent a at a second audience.
IdPageAuds == {[agent |-> a, aud |-> x, key |-> k1], [agent |-> a, aud |-> y, key |-> k1]}
\* The tabs are alike: a state with their parts exchanged is the same state.
TabsAlike == Permutations({t1, t2})
\* A bound on the reviews begun by the tabs together.
Sum(f, S) == IF S = {} THEN 0 ELSE LET RECURSIVE Go(_)
                                      Go(T) == IF T = {} THEN 0 ELSE LET e == CHOOSE e \in T : TRUE IN f[e] + Go(T \ {e})
                                  IN Go(S)
Bounded == Sum(ops, Tabs) <= MaxTotal
=============================================================================
