---- MODULE MCAdapter ----
\* Model values for Adapter.tla: worker 1's clock 1 s behind real time, worker 2's 1 s ahead.
EXTENDS Adapter
AdapterOffset == [w \in Workers |-> IF w = 1 THEN -1 ELSE 1]
====
