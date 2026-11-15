# H6 — cross-session provenance laundering (the C2 result)

Evidence: `crates/gate-policy/tests/laundering.rs` (2 tests, green).
Reproduce: `cargo test -p gate-policy --test laundering`.

## Chain (no hand-labelled taint anywhere)

| Step | Mechanism | Observed |
|---|---|---|
| 1. Untrusted tool output | `SegmentSpec { label: EXTERNAL_UNTRUSTED_DATA, source: "tool:ticket #8841" (line 14) }` | segment inserted |
| 2. "Summarise into memory" (compaction) | `persist::summarise` = derivation, takes the **meet** (INV-3) | memory segment label = `EXTERNAL_UNTRUSTED_DATA` |
| 3. Session ends | redb `PersistentStore` commits | durable |
| 4. **New session** | reopen store, `memory_record`, `recover_label` | label still `EXTERNAL_UNTRUSTED_DATA` (restart cannot launder) |
| 5. Privileged call with **allowlisted parameters** | closure built from the reloaded graph | |
| 6. Policy + provenance (G) | `PolicyEngine` pivot, `PivotMode::Deny` | **DENY** `DENY_TAINT_PIVOT`, closure weakest = EXTERNAL |
| 7. Policy only (B3), same call | empty closure | **ALLOW** — policy cannot see memory |
| 8. Explanation | `TaintPath::build(...).render()` | names `ticket #8841` and `line 14`, not the summary |

## Why this matters for novelty (C2)

In-planner IFC (CaMeL / FIDES class of systems) constrains a *plan within one run*.
It has no representation of a memory record written in an earlier session and
retrieved after compaction. The boundary gate does, because provenance is
persistent data: the label is carried by the segment, not by the prompt.

**Claim supported by this test:** a delayed privileged call whose influence comes
only from a summarised memory record is denied, and the same call is allowed by
a policy-only configuration. That is a *mechanism* result (scripted, single host);
the missing measurement is whether a real model can be induced to make such a call
and how often (H1/H6 with real models).

## H7 — over-taint cost (theory of change)

Same file, second test: a benign "read untrusted doc → send allowlisted email"
flow is **denied** under conservative turn-window taint and **allowed** after a
principal-only checkpoint screens the read. That is the utility/security frontier
in miniature: the conservative default is safe but costly, and the checkpoint is
where the cost is recovered. Measuring the size of that cost on benign workloads
is the H7 experiment.
