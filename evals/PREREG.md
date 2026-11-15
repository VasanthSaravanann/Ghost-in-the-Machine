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
- `evals/test/` = generated once, hash-committed **before** tuning, run **once**.
  Not present yet; the pilot uses the dev corpus only.

## Non-claims (binding)

No claim about real models, real attackers, human principals, or superiority over
prior systems is made from a pilot. Scripted `gullible` agents always attempt the
attack, so a deterministic gate blocks designed scenarios nearly by construction:
the pilot tests **enforcement correctness and the harness**, not real-world effect.
