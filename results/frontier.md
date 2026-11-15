H7 — over-taint cost on benign flows that read untrusted content
(PILOT-STATIC; no model calls; n = 100 benign scenarios)

| policy | benign writes denied | interpretation |
|---|---|---|
| CONSERVATIVE (turn-window taint) | 100/100 = 100.0% (95% ub 100.0%) | safety-first; utility cost |
| PRECISE (principal checkpoint) | 0/100 = 0.0% (95% ub 3.0%) | recovers utility |

Utility recovered by the checkpoint: 100/100 flows (100.0%).
Of ALL 200 benign scenarios, the conservative rule would deny 50.0% (100/200).

Caveats: (a) the read is synthetic — no real model or document;
(b) the PRECISE branch is the mechanism by definition, so 0% denial is a
    consistency check, not a discovery. The measured quantity is the
    CONSERVATIVE cost, which depends on how often benign tasks touch
    untrusted data — workload-dependent, hence the denominator is printed.
