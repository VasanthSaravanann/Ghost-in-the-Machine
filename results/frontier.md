# H7 — over-taint cost curve

Evidence: `cargo run -p void-bench --bin frontier` (no model calls).
This is a **sensitivity analysis**, not a workload measurement.

| assumed share of benign tasks that read untrusted data | benign writes denied (CONSERVATIVE) | denied (PRECISE checkpoint) |
|---|---|---|
| 0% (0 of 200) | 0/0 | 0/0 |
| 10% (20 of 200) | 20/20 = 100.0% | 0/20 = 0.0% |
| 25% (50 of 200) | 50/50 = 100.0% | 0/50 = 0.0% |
| 50% (100 of 200) | 100/100 = 100.0% | 0/100 = 0.0% |
| 75% (150 of 200) | 150/150 = 100.0% | 0/150 = 0.0% |
| 100% (200 of 200) | 200/200 = 100.0% | 0/200 = 0.0% |

## What changed from the previous version

The earlier file reported "50% of ALL benign flows would be denied" as if it were
measured. It was not: `frontier.rs` hardcoded four of eight benign subfamilies as
"touches untrusted content" (4 × 25 = 100 of 200) and then inserted a synthetic
untrusted read into every selected scenario. The 50% was the classification, and the
100% denial was the pivot rule applied to a label the harness had just inserted.

The curve above reports the same mechanism honestly: the cost is **linear in the
fraction of benign tasks that read untrusted data**, and that fraction is the input
this corpus cannot supply. The PRECISE branch is the mechanism by definition, so its
0% is a consistency check, not a discovery.

## What would turn this into a measurement

A workload trace: real benign tasks with tool sequences, with the read/write pattern
observed rather than assumed. Until then the honest statement is "cost = f(read
fraction), with f measured here as the identity on this mechanism".
