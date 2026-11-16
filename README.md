Inline enforcement proxy at the MCP transport boundary. The model is outside the
trusted computing base; authority is derived from data provenance
(`plan.md` is the build spec and wins over this file).

**Paper draft:** [`PAPER-DRAFT.md`](PAPER-DRAFT.md) — introduction, methodology,
results, discussion, limitations and dual-use/ethics, grounded in the committed
evidence below.

## Status

| Task | Status | Tests |
|---|---|---|
| M0-T00 workspace + CI + guardrails | DONE | T-REPO-001..006 |
| M0-T01 `gate-core` | DONE | T-CORE-001..012 |
| M0-T02 `gate-jcs` (RFC 8785) | DONE | T-JCS-001..020, T-JCS-V (100k differential) |
| M0-T03 `gate-crypto` | DONE | T-CRY-001..010 (RFC 8032 KATs) |
| M0-T04 `gate-span` | DONE | T-SPAN-001..014 |
| M0-T05 `gate-transport` | DONE | T-TRN-001..020, fuzz `mcp_frame` |
| M1-T01 `gate-policy` DSL + engine | DONE | T-POL-001..020 |
| M1-T02 parameter validators | DONE | T-PAR-001..030 |
| M2-T01 provenance lattice | DONE | T-PRV-001..015 |
| M2-T02 structural taint | DONE | T-TNT-001..020 |
| M2-T03 control-flow taint | DONE | T-CTL-001..012 |
| M2-T04 taint pivot halt | DONE | T-PIV-001..014 |
| M2-T05 provenance persistence | DONE | T-PER-001..016 |
| M2-T06 scoped declassification | DONE | T-DEC-001..008 |
| M3-T01 budget + rate limits | DONE | T-BUD-001..011 |
| M3-T02 brief builder + framing filter | DONE | T-BRF-001..011 |
| M3-T03 Sup-share validator | DONE | T-SYM-001..018 |
| M3-T04 split-leaf ledger | DONE | T-LDG-001..026 |
| M3-T06 drift/regret + dual principal | DONE | T-DRF-001..014 |
| M4-T01 RFC 9162 Merkle tree | DONE | T-MRK-001..020 |
| M4-T02 salted leaves + evidence store | DONE | T-SLT-001..018 |
| M1-T03 descriptor pinning + drift | DONE | T-SCH-001..018 |
| M1-T04 metadata + namespace isolation | DONE | T-META-001..016 |
| M5-T01 void-bench runner + manifest | DONE | T-VBN-001..020, T-SCN-001..003 |
| M5-T02 scenario corpus (360) | DONE | T-SCN-001..006 |
| M6-T04 FIPS profile | DONE | T-CRY fips suite |
| M6-T05 pentest prep | DONE | docs/pentest-brief.md |
| M0-T06 mcp-gate shadow mode | DONE | T-E2E-001/002/003/006 |
| M3-T05 endorsement channel | BLOCKED (ISSUE-005) | T-CHN-001..020 |
| G-M0 latency/INV-1 gate | PENDING (ISSUE-001) | measured p99 8.0 ms incl. fsync |

`STATE.md` is the authoritative machine-maintained ledger (task, commit, tests,
eval numbers, open issues, pending decisions).

## Evidence (read the claim level before quoting a number)

| File | What it is | Not what it is | Reproduce |
|---|---|---|---|
| `results/pilot.md` | `PILOT-STATIC`: scripted gullible agent, 360 templated scenarios, B0/B1/B3/G | real-model or real-attacker effectiveness | `cargo run -p void-bench` |
| `results/test.md` | the same runner on the hash-frozen split | proof of generalisation (the split differs by ids/seeds/phrasings, not content) | `cargo run -p void-bench -- --split test` |
| `results/laundering.md` | H6 mechanism: ticket → summary → persisted → reopened → `DENY_TAINT_PIVOT` | a model result (the content is scripted) | `cargo test -p gate-policy --test laundering` |
| `results/frontier.md` | H7 **sensitivity curve** over the share of benign tasks that read untrusted data | a workload measurement | `make frontier` |
| `results/model_pilot.md` | H8 (exploratory) + H8b (pre-registered): **three digest-pinned models**, paired B3 vs G on the same transcripts | an `mcp-gate` run; memory is still passed as text | `make pilot` |
| `results/model_adaptive.md` | H8c/H8d/H11: fixed-budget LLM-rewrite attacker, including a policy-aware variant | the §6.4 adaptive campaign (self-play, 3B, 5 rows) | `make adaptive` |
| `results/model_pilot_neutral.md` | H10: neutral-summariser control for the assisted prompt | a general claim (the effect is model-specific) | `make neutral` |
| `results/model_injecagent.md` | H9: **InjecAgent-derived** external corpus (payload verbatim, routing suffix added) | the InjecAgent benchmark (no tool-call score) | `make injecagent` |
| `results/model_pilot_frontier.md` | H12: **hosted 27B–31B models** via the Adaption API; plain 71% ASR, G denies 32/32; `b2allow` 0/45 with 81% utility | a general claim (`b2allow` is handed the answer) | `make hosted` (needs `ADAPTION_API_KEY`) |
| `results/model_injecagent_100.md` | H14: 100 external attack cases; plain 44/100, `b2allow` 0/100, G denies 44/44 | the InjecAgent benchmark (derived, attack-only) | `make injecagent100` |
| `results/model_benign_cost.md` | H13: **the cost of G** — benign external-content flows: raw utility 49/81, under G 0/81 | a workload estimate (9 templates) | `make cost` |
| `results/e2e_gate.md` | H15: **live hosted model through the real `mcp-gate` process** — attacker 7/7 blocked, shadow control 3/3 executed, benign 3/3 blocked | a full 360-scenario gate run | `make e2e` |
| `results/e2e_corpus.md` | full model corpus (8 rows × 3 modes) through the CLI, local and hosted | the 360 templated scenarios | `make e2e-corpus` |
| `results/agentdojo.md` | **real AgentDojo v1.2** baseline + **native pipeline defense** + post-hoc replay | the Rust gate linked into AgentDojo (the defense mirrors the rule) | `make agentdojo` |
| `results/cli_bench.md` | full **360-scenario** corpus through the real CLI (scripted agent, G vs B3) | a model-driven 360 run | `make cli-bench` |
| `results/model_pilot_large.md` | H17: 30 attack rows/model on llama3.2 + gemma3:4b; confirms H8b | a hosted larger-n run | `make pilot` |
| `results/camel_fides.md` | CaMeL/FIDES **reported** AgentDojo numbers with a non-comparability boundary | a head-to-head run (not performed) | — |
| `results/model_benign_checkpoint.md` | H18: simulated principal approval recovers 27/27 utility under G | a human-factors study | `make checkpoint` |
| `results/checkpoint_sensitivity.md` | how accurate the principal must be (q ≤ 7 % for ASR ≤ 5 %) | human data | `make checkpoint-sensitivity` |
| `results/head_to_head.md` | **matched 16-pair pilot**: CaMeL 93.8% utility/6.2% attack, gate 37.5%/0%, undefended 100%/0% | the full 949-attack benchmark | `docs/head-to-head-protocol.md` |
| `docs/head-to-head-protocol.md` | exact CaMeL/FIDES/gate protocol for the full run | a completed full benchmark | — |
| `docs/human-checkpoint-protocol.md` | IRB-ready within-subjects checkpoint study | human data (not run) | — |

Every rate in these files carries a Clopper–Pearson interval. `results/*.jsonl` are the
raw per-trial transcripts for the model runs; the markdown tables are derived from them.
`cargo test -p gate-policy --test model_transcript` closes the join between a **real
model summary**, a persisted/reopened provenance store, and a `DENY_TAINT_PIVOT`.
`crates/mcp-gate/tests/transport_taint.rs` closes the transport join: `mcp-gate` labels
a `tools/call` **response** itself and denies the next call, with no harness-declared
taint flag.

## Build and test

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace
bash ci/scripts/check.sh        # local mirror of the CI `fast` tier
```

Fuzzing (`cargo-fuzz`, nightly, separate workspace):

```sh
cargo +nightly fuzz run jcs_parse -- -max_total_time=600
cargo +nightly fuzz run mcp_frame -- -max_total_time=600
```

## Layout

See `plan.md` §2.1. Everything under `crates/` is Rust; `ref/` holds the
non-TCB independent verifier used only for differential tests.

## Known gaps in the log layer

- `verify_consistency` is deliberately not shipped (`ISSUE-006`): the prover is
  byte-identical to the independent reference, but the verifying fold is not yet
  derived correctly. No witness cosignature or `mcp-audit verify` consistency
  claim is made until it is.
- `M4-T03` (STH + witnessing) is blocked on `DEC-P04` and `ISSUE-006`.

## Human sign-off required

Per plan.md §0.2 R12, `DEC-P01`..`DEC-P04` are recorded in `STATE.md` as
**pending sign-off**; do not treat them as final. `ISSUE-001` (measuring G-M0
`P-LAT-1` on a defined storage profile) is open.

## Enforcement, not convention

- `ci/scripts/r_grep.sh` — product crates may not reference `evals/` or `void_bench`.
- `ci/scripts/tcb_lang_check.py` — walks the real dependency tree of the ten
  decision crates and fails on any native-code dependency (dev-deps excluded).
- `ci/scripts/dep_rule_check.py` — no product crate may depend on `gate-testkit`.
- `ci/scripts/lint_self_test.py` — proves the `unwrap_used` lint fails a build.
- `ci/scripts/forbid_unsafe_check.sh` — R5 crates carry `forbid(unsafe_code)`.

Each of these is covered by a test (`crates/gate-testkit/tests/repo_rules.rs`).
