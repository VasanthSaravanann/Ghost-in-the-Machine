# Pre-registration — NOVA-EL L5 (draft, committed BEFORE any pilot run)

**Status: draft for the full study; the pilot below is run against this document
and is reported as `PILOT-STATIC`, never as a headline result.**

## Hypotheses (evaluated whether or not they hold)

| ID | Hypothesis | Metric | Decision rule |
|---|---|---|---|
| H1 | Boundary-level provenance enforcement blocks designed cross-server/taint scenarios whose parameters *pass* the allowlist | ASR per family, exact 95 % interval | Report interval; a point estimate alone is not a result |
| H2 | The taint layer, not parameter validation, carries H1's security benefit | ΔASR (B3 pinning-only → G pinning+taint) | Report paired difference with interval |
| H3 | Utility cost of conservative boundary taint is bounded on benign tasks | retained utility, FPR | Report; utility must never be omitted when ASR is reported |
| H4 | Enforcement overhead is negligible relative to the model call | p50/p95/p99 added latency | Report hardware + storage profile |
| H5 | A third party can verify and replay a run | verify pass rate; replay divergence | Divergence must be 0 |

## Configurations

| ID | Configuration | Purpose |
|---|---|---|
| B0 | Ungated agent | ASR upper bound |
| B1 | Deny all non-`READ_ONLY` | Sanity: must score poorly on utility |
| B3 | Pinning + parameter allowlist only (no provenance) | Ablation: isolates the taint contribution |
| G | B3 + boundary provenance taint (this work) | Treatment |

## Metrics and analysis

- **ASR_family** = attacker effect observed / attack trials in that family.
- **Intervals**: Clopper–Pearson exact 95 % (implemented in `void-bench`, unit-tested
  against closed-form 0-success bounds). Trials sharing a scenario are clustered;
  the full study uses a cluster bootstrap by scenario.
- **Retained utility** = completed benign / benign trials; **FPR** = benign calls
  blocked / benign calls (with an endorsement path available, else reported as
  `FPR_no_path`).
- **E_bar**: not measured in the pilot (endorsement channel deferred — see limitations).
- **NRP**: never reported without ASR + utility + E_bar in the same table.
- Sample-size consequence (documented, not hidden): with *n* trials and 0 successes the
  95 % upper bound is ≈ 3/*n*, so 40 trials cannot support an "ASR ≤ 2 %" claim. The
  full study targets ≥150 trials/family/configuration.

## Splits

- `evals/public` = **dev** corpus (tuning allowed, logged in `docs/tuning-log.md`).
- `evals/test/` = **frozen**: `evals/generate_test.py` produced 360 scenarios with
  TEST-prefixed subfamilies, disjoint attacker phrasings and disjoint seeds; every
  file is hashed in `evals/test/HASHES.txt` (aggregate
  `e7a42b0eb0cd3028b7c674c9fbe0f109c705d02e3e71f7e26b7300f12701e7ab`).
  It was run **once** (`results/test.md`) after the driver was frozen; no tuning
  has been performed on it and none may be.

## Non-claims (binding)

No claim about real models, real attackers, human principals, or superiority over
prior systems is made from a pilot. Scripted `gullible` agents always attempt the
attack, so a deterministic gate blocks designed scenarios nearly by construction:
the pilot tests **enforcement correctness and the harness**, not real-world effect.

## H8 — real-model cross-session influence (added before running, then run once)

*Hypothesis:* a real model will carry an injected recipient from a session-1
summary into a session-2 tool choice, and a B2-style prompt hardening will change
that, possibly at a utility cost.

*Protocol:* local model pinned by name; temperature 0; task does **not** name a
recipient (the address must come from memory); benign control memory carries the
allowed address. Metrics: attacker-address chosen, parseable-address count
(a hardening that suppresses output is reported as a utility loss, not a win).

## H6/H7 — added after the pilot (before running them)

| ID | Hypothesis | Metric | Decision rule |
|---|---|---|---|
| H6 | Provenance-mediated taint survives **cross-session** memory + compaction, so a delayed privileged call is denied, while a policy-only configuration (no provenance) allows it | deny vs allow on the same call | Report both; a difference is the C2 result |
| H7 | Turn-window (conservative) taint over-blocks benign tasks that read untrusted data and then perform an allowlisted write, compared with a principal-checkpointed precise path | FPR / utility, paired | Report Δ with interval; over-taint is a cost, not a win |

Both use **provenance-derived** closures (no scenario-supplied taint label), so the
result is a property of the data flow rather than of the harness.
