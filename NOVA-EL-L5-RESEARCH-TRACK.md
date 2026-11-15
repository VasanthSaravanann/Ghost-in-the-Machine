# NOVA-EL L5 — Research Track (overlay on `NOVA-EL-L5-AGENT-BUILD.md`)

**Goal:** produce a defensible, reproducible evaluation of the architecture suitable for submission to a top-tier security venue (USENIX Security / IEEE S&P / CCS / NDSS class — check current CORE rankings yourself).
**Non-goal:** GA-grade productisation (HSM custody, multi-builder reproducibility, external pentest, legal DPIA sign-off).

> **Precedence.** Read `NOVA-EL-L5-AGENT-BUILD.md` first. This file then **overrides**: §0.2 R9 and R12, §0.5, the §4 phase plan (M0–M6 → R0–R6 below), and the §6.6 gates (pass/fail → pre-registered hypotheses). Everything else stays in force, **including R1–R8, R10, R11, all invariants INV-1..12, and every invariant adversarial test (§5.12)**.
> **v1.2 status-aware update:** §11–§13 audit the build agent's latest status report, replace the remaining-work order, record provisional decisions, and give the agent a steering directive. Where §11 conflicts with the §4 timeline, §11 wins.
> Nothing here guarantees acceptance. Rigorous testing is necessary, not sufficient; novelty positioning (§1.3) is the larger risk.

---

## 1. Claims-driven scope

A paper is judged on its claims. The PRD contains four primitives and a benchmark — too much for one paper, and the weakest parts would drag down the strongest. Decide the claims first, then build only what they need.

### 1.1 Recommended thesis

> A transparent proxy at the MCP boundary can, **without modifying the agent or the model**, enforce provenance-based authorisation over tool side effects. The central empirical question is what it costs: coarse (turn-level) taint at the boundary is sound but conservative, so how much utility is lost, how many escalations are needed, and how much does scoped human endorsement recover?

This is a genuine trade-off to measure, not a result to assume.

### 1.2 Research questions (each maps to a figure/table in the paper)

| RQ | Question | Primary evidence |
|---|---|---|
| RQ1 | Security: what attack-success rate does the gate allow across AF1–AF4 and external benchmarks, versus baselines, under adaptive attackers? | ASR with confidence intervals, per family, per model |
| RQ2 | Utility: what is the cost of conservative boundary-level taint on benign tasks? | Retained utility, FPR, over-taint rate |
| RQ3 | Oversight: how many escalations are needed, and do budget + balanced briefs change simulated-principal decisions? | Escalations/episode; approval rates by profile × framing |
| RQ4 | Overhead: latency and throughput added? | p50/p95/p99, calls/s, memory |
| RQ5 | Verifiability: can a third party verify and replay a run with zero divergence? | Verify pass rate, replay divergence, log size/cost |

### 1.3 Contributions and related work (**must be checked by a human literature review**)

A quick search in this revision confirmed substantial prior art on deterministic, system-level defences, so novelty must be argued explicitly:

| Work | What it is (per its abstract/summary) | Why it matters here |
|---|---|---|
| CaMeL (Debenedetti et al., arXiv 2503.18813) | Separates control and data flow with a custom interpreter and capability tracking; evaluated on AgentDojo; code released | Closest "by design" system. Requires a planner/interpreter; we do not. |
| FIDES (Costa et al., arXiv 2505.23643) | IFC planner with integrity/confidentiality labels; evaluated on AgentDojo with five LLMs; formal model | Sets the evaluation bar (multiple models, AgentDojo). Also discusses confirmation fatigue. |
| PRUDENTIA (arXiv 2602.11416) | Improves autonomy over FIDES; AgentDojo + WASP; reports deterministic policies can cost up to ~30% task completion | Overlaps RQ2/RQ3 directly. |
| RTBAS, Progent | IFC for tool agents; reference-monitor privilege control | Further baselines/related work |
| AgentPoison (arXiv:2407.12784) | Poisons an agent's long-term memory or knowledge base so a trigger retrieves an adversarial demonstration | **Direct prior art for memory poisoning.** Attacks the retrieval path; does not carry a provenance label through compaction or enforce at the boundary |
| MINJA (arXiv:2503.03704) | Query-only memory injection: malicious records are written through normal interaction | Establishes memory writes as an attack surface. No boundary enforcement, no cross-session label persistence |
| InjecAgent (arXiv:2403.02691) | Benchmark for indirect prompt injection in tool-integrated agents | Candidate external benchmark; measures model compliance, not boundary provenance |
| AgentDojo, MCPTox, MSB | Benchmarks for injection and MCP tool poisoning | External validity (§6) |

**Candidate contributions (hypotheses to validate against the literature, not facts):**

> Citation warning: the AgentPoison / MINJA / InjecAgent rows above were added from memory
> during a status-fix pass. Per the rule at the top of this section, a human must verify the
> identifiers and claims before they appear in a paper.
- **C1** Deployment model: out-of-band enforcement at the MCP transport, unmodified agents and servers, model outside the TCB.
- **C2** Cross-session provenance persistence and summarisation-as-derivation (memory/compaction laundering). **Delta over memory-poisoning work** (AgentPoison, MINJA): those attacks target the retrieval/memory write; C2 is about the *label* surviving compaction and restart and being enforced at the boundary, outside the planner. This delta is the claim a reviewer will test first.
- **C3** Measured cost of boundary-level taint versus in-planner IFC.
- **C4** Escalation scarcity + symmetric, third-person briefs as an HITL defence — **only if** evaluated credibly (§5, §8).
- **C5** `void-bench`, if released as a reusable MCP-native benchmark.

**Do not claim** the transparency log as a contribution: it is standard Merkle-log machinery applied here. Use it as an engineering substrate and say so.

---

## 2. Scope: IN / SIMPLIFIED / DEFERRED

| Item (main-spec ref) | Status | Rigour-preserving substitution |
|---|---|---|
| Schema pinning, allowlists, namespace isolation (P1) | **IN** | — |
| Signed, chained spans (P1-R1..R7) | **IN**, simplified | Soft keys; plain fsync; **no group commit** unless latency fails. Report measured latency honestly. |
| Provenance lattice, taint, control-flow, persistence (P2) | **IN** (core of the paper) | — |
| Budget, brief builder, Sup-share validator, split ledger (P3) | **IN**, simplified | Principal = simulated oracle + Ed25519 device key (no WebAuthn). Deterministic layout model kept; Playwright cross-check optional. |
| Human-factors claims | **IN only with evidence** | Either a small IRB-approved user study, or the claim is explicitly scoped to "simulated principals" (§8). |
| Merkle log, checkpoints, 2-of-3 witnesses (P4) | **SIMPLIFIED** | Vendored Merkle crate (§3); **C2SP signed-note / tlog-checkpoint / tlog-cosignature / tlog-witness formats (§11.2)**, not a bespoke STH; witnesses as local processes. Keep INV-9/INV-10 tests. **Consistency proofs are not optional.** |
| `mcp-audit verify/replay/explain` | **IN** | Needed for RQ5 |
| `void-bench` | **IN** + external benchmarks | §6 |
| HSM/TPM custody, `Pkcs11KeyStore` | **DEFERRED** | Stub stays; report as limitation |
| Kani proofs (M6-T01) | **DEFERRED (stretch)** | Replace with proptest + **bounded exhaustive** enumeration for lattice meet and budget counter; add Kani only if it installs cleanly |
| 72 h fuzzing (M6-T02) | **REDUCED** | 30–60 min per target in CI; one 8 h campaign before submission; report coverage and findings |
| Multi-builder reproducible build (M6-T03) | **REDUCED** | `cargo build --locked` in a pinned container; record image digest and binary hash |
| External pentest | **REPLACED** | Adaptive-attack campaign (§6.4) is the red team; report its budget |
| FIPS profile, SBOM signing, DPIA | **DEFERRED** | Discuss in limitations |
| Playwright/browser tests (T-CHN) | **OPTIONAL** | HTML snapshot tests + layout-model tests are blocking; browser tests run only if installed |

Every DEFERRED/REDUCED item must appear in the paper's limitations section.

---

## 3. Vendor-or-port policy (lesson of ISSUE-006)

Re-deriving a standard algorithm from memory is the wrong place to spend risk. **Rule V1:** for any standardised primitive, adopt a vetted implementation or port one with its published vectors; write your own code only where the contribution is novel (provenance engine, policy engine, brief validator, ledger state machine).

| Primitive | Adopt | Caveats to record |
|---|---|---|
| Merkle tree, inclusion, consistency | `ct-merkle` (RFC 6962 construction; the Merkle hash definition in RFC 9162 §2.1 uses the same `0x00`/`0x01` prefixes — confirm with vectors) | Verified to exist: memory-backed tree with inclusion/consistency proofs; **explicitly unaudited**; panics on some degenerate inputs (e.g. consistency from an empty tree) — wrap and test. Persist leaves yourself; rebuild the tree on start. |
| Independent cross-check | `ref/` Go program using Go's `golang.org/x/mod/sumdb/tlog` (third-party, maintained by the Go project; confirm leaf/node prefixes with vectors) **and** published CT/C2SP test vectors | Differential test, never a runtime dependency. **The reference must be third-party code or published vectors — an in-house Python/Rust re-implementation written by the same author/agent shares its misconceptions and is not independent.** |
| Checkpoints and cosignatures | Follow C2SP `signed-note`, `tlog-checkpoint`, `tlog-cosignature`, `tlog-witness` (pin to a tagged spec version). Cross-check with the Go library `filippo.io/torchwood`, which implements them | Community specs, not IETF standards; versions evolve — pin and record the tag |
| JCS (RFC 8785) | A maintained Rust JCS crate (evaluate at R0) wrapped with our stricter rules (reject duplicate keys, reject non-exact integers per DEC-P02) | Check Appendix B vectors pass |
| Hash / signatures | RustCrypto (`sha2`, `ed25519-dalek`, `p256`) | — |
| Embedded store | `redb` | — |

**Action on ISSUE-006:** keep the four failing edge-case counterexamples as permanent regression tests (`T-MRK-REG-001..004`), then replace the hand-written tree with the vendored one and require the differential test to pass on the same inputs. The counterexamples are useful evidence of where hand-rolled implementations break; they should not be discarded.

---

## 4. Revised task plan (R0–R6)

Tiers: **PC** = paper-critical (blocking), **EN** = engineering (blocking unless marked), **DF** = deferred/optional (`DEFERRED(reason)` is a valid terminal status).

| Phase | Scope | Main-spec tasks reused | Exit criteria (all PC) |
|---|---|---|---|
| **R0 Environment (≈1 wk)** | `tools-doctor` (reports missing `kani`, `playwright`, fuzz nightly, Docker, API keys); vendored Merkle + JCS; `ref/` stub; STATE.md | M0-T00..T03 (adapted) | Doctor output committed; Merkle differential test + RFC 8785 Appendix B vectors green |
| **R1 Mediation (≈2 wk)** | Transport (stdio first; HTTP second), spans, policy DSL, allowlists, pinning, metadata delimiting, shadow mode | M0-T04..T06, M1-* | AF1 dev-set ASR measured; INV-1/11/12 adversarial tests green; latency measured |
| **R2 Provenance (≈3 wk)** | Lattice, structural taint, control-flow, pivot halt, persistence, scoped declassification | M2-* | INV-3/INV-4 property + adversarial tests green; laundering corpus 0 launders |
| **R3 Endorsement (≈2 wk)** | Budget, rate limit, brief builder, deterministic Sup-share, split ledger, simulated principal | M3-T01..T04, T06 (no WebAuthn/Playwright) | INV-5/6/7/8 adversarial tests green; gaming corpus cannot pass |
| **R4 Log + audit (≈1 wk)** | `LeafSink` → Merkle log, STH, local witnesses, `mcp-audit` | M4-* (simplified) | INV-9/10 tests green; `verify` passes with no operator state; replay divergence = 0 |
| **R5 Evaluation campaign (≈3–4 wk, longest pole)** | §6 protocol: dev tuning, freeze, test run, baselines, ablations, adaptive attacks, latency | M5-* | Pre-registration committed *before* test-split run; all result tables regenerate from one command |
| **R6 Artifact + paper (≈2 wk)** | Reproduction package, figures, limitations | — | Fresh-machine reproduction of headline tables |

Total ≈ 14–16 weeks of wall-clock **if** API budget and rate limits cooperate. Treat this as an estimate, not a commitment; R5 dominates and is the least predictable.

---

## 5. Test-quality contract

### 5.1 What does **not** relax

- R1 (never weaken tests/thresholds/scenarios), R2 (held-out untouchable), R3/INV-2 (no model output in decisions), R4/INV-12 (fail closed).
- All 12 invariant adversarial tests (§5.12), including the differential test for INV-2.
- Differential tests for JCS and Merkle against `ref/`.
- Property tests for lattice meet, budget monotonicity, proof soundness.
- Parser fuzz smoke on every parser (shorter campaign, same targets).
- Deterministic replay (`mcp-audit replay` → 0 divergence) on every evaluation run.

### 5.2 What changes

- **R9′ (replaces R9):** a task is DONE when all **PC and EN** tests for it pass in CI on tools that `tools-doctor` reports as installed. A test needing an uninstalled tool is marked `DEFERRED(tool-missing)` in STATE.md **and listed in the paper's limitations**; it is not silently skipped and not counted as passing.
- **R12′ (replaces R12):** `DEC-P*` proposals are adopted as **PROVISIONAL**: implement the proposed behaviour behind a config flag, log it, continue. Humans review the PROVISIONAL list weekly. A PROVISIONAL choice that affects reported results must be listed in the paper's methodology.
- **§0.5′:** escalate only for (a) spec self-contradiction, (b) a gate-bypass finding (add failing test first), (c) needing `unsafe`/native code in a decision crate, (d) eval-integrity violations (touching held-out, test-split leakage). Everything else: record a DEC, pick the simplest option, move on. Time-box any task to **3 design iterations**, then record the best result and proceed.

---

## 6. Evaluation protocol (the heart of the quality argument)

### 6.1 Sample size and statistics

The main-spec target "AF1 ≤ 2%" cannot be demonstrated with 40 scenarios. With zero successes in *n* independent trials, the one-sided 95% upper bound is ≈ 3/*n*:

| Trials *n* (0 successes) | 95% upper bound on ASR |
|---|---|
| 40 | ≈ 7.2% |
| 60 | ≈ 5% |
| 100 | ≈ 3% |
| 150 | ≈ 2% |

Consequences:
1. **Do not report point estimates alone.** Report exact (Clopper–Pearson) or Wilson intervals per family and per model.
2. Scale trials by **parameterised scenario generators × seeds × models**, not by hand-writing more scenarios. Target ≥150 trials per family per configuration.
3. Trials that share a scenario are not independent: use a **cluster bootstrap by scenario** for intervals and paired tests (McNemar or paired bootstrap) for comparisons with baselines.
4. Replace gate thresholds with **pre-registered hypotheses** (e.g. "AF1 ASR upper bound < 5% for all models") and report outcomes whether or not they hold. A negative result with honest intervals is publishable; a tuned pass is not.

### 6.2 Dev/test discipline (prevents tuning-to-the-benchmark)

```
evals/dev/    scenarios you may tune on freely
evals/test/   generated once, hash-committed BEFORE tuning, run ONCE per release candidate
evals/PREREG.md  hypotheses, metrics, models, seeds, analysis plan, committed before the first test run
```
- Generators (not hand-written lists) produce both splits from disjoint template families **and** disjoint attacker phrasings.
- Tuning loop: run dev → bucket failures by cause → change **one** thing → rerun dev → log in `docs/tuning-log.md` → stop after K rounds (K=6 suggested) or plateau → freeze commit → run test split once.
- Every change made during tuning is a row in the log (what, why, metric delta). The log becomes the paper's design-evolution evidence and answers the reviewer question "how much did you fit to the benchmark?".
- Public-vs-held-out gap > 3 points on a family ⇒ report as overfitting evidence.

### 6.3 Baselines and external benchmarks

| Baseline | Purpose |
|---|---|
| B0 Ungated agent | ASR upper bound |
| B1 Deny all non-`READ_ONLY` | Sanity check on NRP (must score poorly) |
| B2 Prompt-level defences (e.g. delimiting/spotlighting, prompt sandwiching; reuse those shipped with the external benchmark where available) | Shows the gap versus model-level mitigation |
| B3 P1 only (pinning + allowlists, no provenance) | Ablation |
| B4 In-planner IFC (CaMeL and/or FIDES) | Closest prior art. Both report AgentDojo results and have public code (CaMeL repo; FIDES tutorial repo). Either **run on shared tasks/models**, or cite reported numbers with an explicit non-comparability caveat. |

External benchmarks (adapter via `TargetFramework`): **AgentDojo** (injection; used by CaMeL/FIDES/PRUDENTIA) and **MCPTox** or MSB (MCP tool poisoning; maps to AF1). Pick at least one of each class; confirm licences and whether MCP-native before committing effort.

Own benchmark `void-bench` supplements these; a self-authored benchmark alone invites "evaluating on your own test" criticism.

### 6.4 Agents, attackers, principals

- **Models:** ≥3 real LLMs with pinned IDs, recorded temperature/seed policy, ≥5 trials per scenario. Scripted `gullible` agents are kept for **deterministic gate testing only** and never aggregated with real-model results.
- **Adaptive attacker (replaces the external pentest):** attacker has full knowledge of policy, brief template and layout model; uses an LLM-driven search with a **fixed query budget** (report it); includes attacks *on the gate* (parser differentials, JCS/Unicode edge cases, taint-laundering transforms, Sup-share gaming, approval flooding). Report attacker budget vs success curve.
- **Simulated principals:** `diligent` / `distracted` / `fatigued` are **parameterised models, not evidence about humans**. Calibrate parameters from published HITL/automation-bias findings **with citations checked by a human**, run a sensitivity sweep over the parameters, and present RQ3 as "under these assumptions".

### 6.5 Cost planning (do this in R0)

Episodes ≈ scenarios × models × trials × configurations (e.g. 400 × 3 × 5 × 6 ≈ 36,000). At ~10–20 model calls per episode that is hundreds of thousands of calls. Compute the budget and rate-limit ceiling **before** committing to the matrix. Cache model responses keyed by the full prompt hash (valid only on exact-prompt hits; a gate change that alters what the agent sees invalidates downstream cache by construction). Prioritise: primary model full matrix; other models on test split only.

### 6.6 Reporting

- Always report ASR, retained utility and mean escalations together; NRP only alongside them (main-spec reporting rule). Report NRP sensitivity to λ weights, since they are author-chosen.
- Latency: state hardware and storage profile; report p50/p95/p99 and throughput; report effect of fsync policy (DEC-P01).
- Include failure analysis: every successful attack on the gate gets a root cause and a category.

---

## 7. Threats to validity (write these into the paper, don't hide them)

| Threat | Handling |
|---|---|
| Self-authored benchmark | External benchmarks; dev/test split; release generators |
| Scripted/simulated components | Real models for headline numbers; simulated principals labelled as such with sensitivity analysis |
| Over-tainting inflates security at utility's expense | Report utility/FPR beside ASR; B1 deny-all baseline |
| Author-chosen NRP weights | Sensitivity sweep; never report NRP alone |
| Unaudited vendored crypto/Merkle crates | Differential testing; disclose |
| Policy authored by the evaluators | Report policy size/complexity; test with an independently written policy for at least one suite |
| MCP ecosystem generality | State server/tool coverage honestly |
| Model drift over time | Pin IDs; record dates; cache outputs |

---

## 8. Human-factors claims

The Sup-share ≤ 0.50 rule and third-person briefs are **design hypotheses**; nothing in the build shows they improve decisions. Options, in order of strength:
1. **Small user study** (IRB/ethics approval required; pre-registered; e.g. between-subjects: agent-voice brief vs gate brief, measuring approval of malicious vs benign requests). Strongest, costs weeks.
2. **Scope down:** present the brief design as an engineering mechanism with simulated-principal results only, and state that human efficacy is unvalidated.
3. **Defer** C4 to a follow-up paper.
Option 3 is the safest way to keep the first paper's claims fully supported.

---

## 9. Artifact and paper checklist

- [ ] One-command reproduction of every table/figure (`make reproduce`), containerised, pinned toolchain, recorded image digest
- [ ] Seeds, manifests, signed evaluation manifest per run; generators released
- [ ] `PREREG.md` and `docs/tuning-log.md` committed with timestamps
- [ ] Limitations section lists every DEFERRED/REDUCED item in §2 and every PROVISIONAL decision affecting results
- [ ] Responsible disclosure plan if the evaluation finds vulnerabilities in third-party MCP servers or benchmarks
- [ ] Related-work section written from a **human-verified** literature search (the original PRD's citations are unverified and must not be reused unchecked)
- [ ] Ethics statement if any human participants

---

## 10. Recommended paper split (if time is tight)

| Paper | Contents |
|---|---|
| **Paper 1 (systems/security)** | C1 + C2 + C3 + C5: boundary-level provenance enforcement, cost vs in-planner IFC, benchmark. RQ1, RQ2, RQ4, RQ5. |
| **Paper 2 (HCI/security)** | C4 with a real user study: scarcity + symmetric briefs. RQ3 at full strength. |

Putting both in one submission raises the evidence bar on every part. Splitting keeps each claim fully supported.


---

## 11. Status audit and remaining-work plan (v1.2)

The build agent's latest status report (items A–D and its "shortest path to a defensible GA") was checked against this track. The mechanics it proposes are mostly sound; the **objective and ordering are wrong for a paper**, and several items would weaken the evidence.

### 11.1 Findings

| # | Report item | Assessment | Action |
|---|---|---|---|
| F1 | "Recommended order … shortest path to a defensible **GA**" | Optimises the wrong target. Pentest, DPIA, 72 h fuzz, signed releases are not paper evidence | Replace with §11.3 |
| F2 | M5-T03: run AF1–AF4 + BEN with `STATIC` labels; "tuning may take weeks"; run G-M1…G-M3, "expect failures → iterate" | Scripted-agent numbers cannot support the paper's claims. Iterating on the same scenarios you later report on is overfitting | No headline numbers until the §6 infrastructure exists. Static runs are for **debugging only**. Tune on the dev split only |
| F3 | Real-model run and held-out suite listed under "must be commissioned" | In the research track these are the **core evidence**, not optional extras | Move to the critical path (S4–S6). The test split is generated from templates authored without access to the dev corpus (§11.3 S4) |
| F4 | M4-T04 "minus consistency" | Consistency proofs underpin INV-9, fork detection and RQ5. Dropping them silently weakens the verifiability claim | Not droppable. Blocked only on ISSUE-006, which S1 fixes |
| F5 | ISSUE-006 fix: port Trillian/CT Go verifier plus `ref/merkle_ref.py` and an m×n matrix | A Python reference written in-house is not independent of the code under test. Porting Go is more work than adopting an existing Rust crate | Adopt `ct-merkle`; independent reference = third-party Go library + published vectors (§3). Keep the m×n matrix and the four recorded counterexamples as permanent regressions |
| F6 | DEC-P04 default: RFC 9162 §4.10 STH + a cosignature over `(tree_size, root_hash, timestamp)` | §4.10 is specific to certificate transparency. A cosignature that omits log identity and domain separation allows replay across logs | Use the C2SP formats instead (§11.2) |
| F7 | R12 blocks the agent on DEC-P01/02/03/04 and ISSUE-001 | The research track already adopts decisions provisionally (R12′) | Decision record in §12 resolves them now |
| F8 | ISSUE-003/005 Playwright and WebAuthn choice | Research track drops WebAuthn (Ed25519 device key for the simulated principal) and makes browser tests optional | Close as `DEFERRED(scope)`; keep layout-model and HTML snapshot tests blocking |
| F9 | M6-T01 Kani "cannot mark DONE until Kani runs" | Under R9′ it is `DEFERRED(tool-missing)` until installed. Per Kani's docs, `cargo kani setup` downloads its own pinned CBMC and toolchain; `rustup nightly` is needed for `cargo-fuzz`, not for Kani | Write harnesses (cheap, guard with `#[cfg(kani)]`); run when installable; never block on it |
| F10 | M6-T02 72 h fuzz = 3 days CI | Over-spec for a paper | One 8 h campaign before submission; keep per-PR smoke |
| F11 | M6-T03 double build + SBOM | Cheap and harmless | Low priority (S9) |
| F12 | External pentest; DPIA | Not code; not needed for the paper | Replaced by the adaptive-attack campaign (§6.4); DPIA goes in limitations |
| F13 | "3 iterations before escalation" applied to eval tuning | Conflates two things | 3 design iterations **per task**; evaluation tuning is a separate, logged loop of ≈6 rounds on the dev split (§6.2) |
| F14 | Same agent writes the gate, the scenarios and the tests | Correlated blind spots: attacks the author did not imagine are never tested | S4 requires a separate scenario-authoring pass (different session/model, spec + threat model only) and a human red-team review of the test split |

### 11.2 DEC-P04 revised: adopt C2SP formats (verified in this revision)

Findings from the specifications and an implementation:
- C2SP defines `signed-note` (text plus signature lines), `tlog-checkpoint` (origin line, tree size, root hash, optional extension lines), `tlog-cosignature` and `tlog-witness` (an HTTP protocol for obtaining witness cosignatures). The Go checksum database and other logs publish signed notes.
- A v1 witness cosignature is a timestamped Ed25519 signature over a message that begins with the fixed header `cosignature/v1` (domain separation), then a timestamp line, then the whole checkpoint body, which includes the log's **origin**. This closes the cross-log replay gap in the agent's proposal.
- A witness cosigns only after verifying a **consistency proof** from the last checkpoint it saw, which is exactly the split-view protection INV-9 needs.
- Implementations exist to cross-check against (Go `torchwood`; a small Rust `siglog` crate also implements the witness spec — treat as a reference to read, not a dependency).
- Caveats: these are community specifications, not IETF standards; spec text changes over time, so pin to a tagged version and record it. Check which signature types the current `tlog-checkpoint` expects for the *log's own* signature before choosing the log key type; the spec also references ML-DSA-44, which is relevant to the crypto-agility story.

**Resulting design:** `gate-tlog` emits a C2SP checkpoint; `nova-witness` implements `tlog-witness` and issues `tlog-cosignature` v1; `mcp-audit verify` checks checkpoint signature, cosignature quorum and Merkle proofs. The RFC 9162 citation is restricted to the Merkle tree and proof algorithms.

### 11.3 Remaining work, in order

| Step | Work | Exit criteria (PC unless marked) |
|---|---|---|
| **S0** (≈½ day) | Adopt this track in `STATE.md`: tag every task PC/EN/DF; convert ISSUE-001/003/005 per §12; record the Decision Record | STATE.md updated; no task still blocked on a resolved decision |
| **S1** | ISSUE-006: wrap `ct-merkle`; differential test against the independent Go reference over **all m ≤ n ≤ 64** plus random trees to ≥4096 leaves; keep the four counterexamples as `T-MRK-REG-001..004`; delete the hand-written tree once equal | 0 mismatches; wrappers tested for degenerate inputs (empty tree, m = n, m > n) |
| **S2** | Implement C2SP checkpoint + cosignature + witness protocol; cross-check with Go `torchwood` in `ref/` | A Go program verifies our checkpoints and cosignatures, and our verifier accepts the Go library's; replayed cosignature under a different origin is rejected (`T-WIT-*`); equivocating witness detected |
| **S3** | `mcp-audit` verify/explain/replay/report **including consistency proofs**; evidence-gap reporting | Verify passes with no operator state; replay divergence = 0 on recorded corpora; tampering of each component detected with a locator |
| **S4** | **Evaluation infrastructure before any tuning:** (a) scenario *generators* with disjoint template families and attacker phrasings for dev and test; (b) test split authored in a separate pass from the spec/threat model only, hash-committed; (c) `evals/PREREG.md`; (d) real-model runner with pinned model IDs, cost guard, response cache; (e) external-benchmark adapter (AgentDojo and/or MCPTox); (f) stats module (Clopper–Pearson, cluster bootstrap by scenario, paired tests; may be Python, non-TCB, committed); (g) `make reproduce` skeleton | Dry run on 10 scenarios regenerates a results table end to end; hashes of test split recorded; cost estimate computed (§6.5); human reviewer has red-teamed the test split |
| **S5** | Tune on the **dev split only**, following the §6.2 loop (K ≈ 6 logged rounds, one change per round); static scripted agents allowed for debugging | `docs/tuning-log.md` complete; invariant adversarial tests still green after every round; no change justified by a test-split result |
| **S6** | Freeze the commit; run the test split **once** per release candidate on ≥3 real models; baselines B0–B4; ablations (§6.9 of the main spec); external benchmark runs | Pre-registered hypotheses evaluated and reported whether or not they hold; intervals on every number |
| **S7** | Adaptive-attack campaign with a fixed query budget against the frozen gate | Attacker budget vs success curve; every success root-caused |
| **S8** | Overhead: latency (p50/p95/p99), throughput, memory, on **both** storage profiles in §12; fsync microbenchmark reported | Numbers with hardware/storage description |
| **S9** | Robustness: 8 h fuzz campaign; write Kani harnesses and run if installable; double-build hash compare (cheap) | Findings fixed or documented; DEFERRED items listed |
| **S10** | Artifact and paper: §9 checklist; limitations from §2 and §12; split decision from §10 | Fresh-machine reproduction of headline tables |

### 11.4 Submission-readiness checklist (go/no-go)

- [ ] All PC tests green; all 12 invariant adversarial tests green on the frozen commit
- [ ] Test split run once; no tuning after seeing it (check the git history)
- [ ] ≥3 real models, ≥150 trials per family per configuration (or intervals reported honestly where fewer)
- [ ] At least one external benchmark per attack class evaluated
- [ ] Baselines B0–B4 and ablations present, including the deny-all sanity baseline
- [ ] Adaptive attacker budget reported
- [ ] Verify/replay results reported (RQ5), including consistency/witness checks
- [ ] Every DEFERRED/REDUCED item and PROVISIONAL decision appears in limitations
- [ ] Related-work section written from a human-verified literature search
- [ ] Reproduction package works on a clean machine

**If the headline result is unfavourable** (for example utility is poor or ASR is not low), do not tune on the test split. Reframe as a measurement study of what boundary-level enforcement costs, which is still a legitimate contribution if the methodology is sound.

---

## 12. Decision record (PROVISIONAL — change any row you disagree with)

| ID | Decision | Status |
|---|---|---|
| DEC-P01 | Synchronous durable commit before release for classes with external side effects; asynchronous flush for `READ_ONLY`; group commit only if latency targets fail. **Report both fsync-per-call and group-commit results** | Accepted (provisional) |
| DEC-P02 | `gate-jcs` rejects integers not exactly representable as an IEEE 754 double | Accepted as implemented |
| DEC-P03 | Deferred prompts queue (depth N, default 3), budget consumed at render, overflow denied | Accepted (provisional); N configurable and swept in the oracle sensitivity analysis |
| DEC-P04 | **Superseded:** adopt C2SP signed-note / tlog-checkpoint / tlog-cosignature / tlog-witness (§11.2); RFC 9162 is cited for Merkle algorithms only | Accepted (provisional); pin spec tags |
| ISSUE-001 storage | Headline latency on **local NVMe**, with a second set of numbers on **networked block storage**; both described precisely in the paper | Accepted |
| ISSUE-003 / ISSUE-005 | Browser tests optional (use the official Playwright container image if run); WebAuthn dropped in favour of an Ed25519 device key for the simulated principal | `DEFERRED(scope)`; list in limitations |
| ISSUE-004 | Closed only when S4–S6 are complete, **not** when a first static run exists | Re-scoped |
| ISSUE-006 | Fixed by S1 | In progress |

---

## 13. Directive to paste to the build agent

> **Switch to the research track.** Read `NOVA-EL-L5-RESEARCH-TRACK.md` §5, §6 and §11–§12 now; they override your status report's recommended order and R9/R12 where they conflict.
> 1. Update `STATE.md`: tier every task PC/EN/DF; apply the Decision Record in §12; do not wait for human sign-off on provisional items.
> 2. Do S1 (adopt `ct-merkle`, differential test against an *independent third-party* reference, keep the four counterexamples as regression tests), then S2 (C2SP checkpoint/cosignature/witness), then S3 (audit CLI **with consistency proofs**).
> 3. Do **not** start tuning against `void-bench` yet. Build S4 first (generators, dev/test split, pre-registration, real-model runner, stats module). Static scripted-agent runs are for debugging only and must never be reported as results.
> 4. Do not spend time on the 72 h fuzz, signed releases, pentest brief, DPIA or held-out commissioning. Write Kani harnesses only if cheap; mark `DEFERRED(tool-missing)` otherwise.
> 5. Never weaken a test, scenario or threshold, never touch the test split, never let model output influence a decision (R1–R4 unchanged). Report any gate-bypass you find as a failing test first.

---

## 14. Venue and schedule (checked 16 Nov 2026 against the official pages — re-check before relying on them)

| Venue | Official dates (AoE, UTC−12) | Status for this project |
|---|---|---|
| IEEE S&P 2027, cycle 2 | Abstract registration **10 Nov 2026**; paper **17 Nov 2026** | **Not a target.** Registration has closed, and the CFP forbids changes to title, abstract or author list after it. The CFP also warns of aggressive desk-rejection in cycle 2, possible submission bans for ultra-low-quality submissions, and a one-year wait after rejection. A pilot-grade paper risks all three |
| USENIX Security '27, cycle 2 | Mandatory registration **19 Jan 2027** (fixed title, authors, tentative abstract, topics); paper **26 Jan 2027** | **Primary target** (≈10 weeks from today) |
| Others (CCS, NDSS, later cycles) | not verified | Check the CFPs before planning around them |

Both venues are CORE A*-ranked per aggregator listings; confirm current rankings yourself. Some third-party deadline sites list S&P dates one day off — use the official CFP.

### 14.1 Backward schedule to the USENIX cycle-2 deadline

| Window | Work | Gate |
|---|---|---|
| 16–22 Nov | S0, S1, ISSUE-009 (copy this file and the main spec into the repo), pilot shakedown (§15) | Pilot table regenerates from one command |
| 23 Nov–6 Dec | S2/S3 (reduced scope below), **S4 complete** | Real-model runner works end to end on 10 scenarios; test split authored, hash-committed |
| 7–13 Dec | S5 tuning on the dev split (≈6 logged rounds) | Tuning log complete |
| **14 Dec** | **Freeze commit + `PREREG.md`** | **Go/no-go:** if S4 is incomplete or real-model runs do not work, retarget the next cycle; do not compress the evaluation |
| 14 Dec–3 Jan | S6: test split on real models, baselines, ablations, external benchmark | Results regenerate from `make reproduce` |
| 4–10 Jan | S7 adaptive attacks, S8 overhead | Attacker-budget curve; latency on both storage profiles |
| 11–19 Jan | Writing; **register by 19 Jan** (title, authors, abstract, topics are then fixed) | Draft complete |
| 19–26 Jan | Final paper, anonymised artifact, ethics and generative-AI disclosure fields | Submit ≥24 h early |

This is tight: the §4 estimate was 14–16 weeks. To fit, scope cuts are allowed **in this order**:
1. RQ5 reduced to a single log with inclusion + consistency proofs and one witness (state the reduction).
2. One external benchmark instead of two (keep one per attack class only if budget allows).
3. C4 (endorsement UX and human-factors claims) moved to Paper 2 (§10).
4. Ablations limited to the three most informative.

**Never cut:** dev/test discipline, confidence intervals, ≥3 real models for headline numbers, baselines B0–B2 (and B4 if feasible), all invariant adversarial tests, the adaptive-attack campaign, honest limitations.

### 14.2 Policy items to handle early
- Generative-AI disclosure: S&P's CFP requires authors to disclose and motivate generative-AI use (in research methodology or manuscript preparation) and holds authors responsible for accuracy and literature review. Assume a similar requirement elsewhere and check the USENIX CFP. This project is agent-built, so write the disclosure from the start.
- Anonymity: the artifact repository must not reveal authors. Plan an anonymised mirror.
- Double submission: do not send the same work to another venue with proceedings while it is under review; check each venue's rules on preprints and workshops before posting anything.
- Concurrent work: a funding page found while searching describes a "fail-closed runtime for agentic AI systems" aiming at the same cycle. Include it in the related-work check; concurrent work changes the novelty argument.

---

## 15. Pilot protocol (any run before the freeze)

A pilot is a shakedown of the pipeline, not evidence.
- **Freeze and hash the scenario list before running.** No scenario edits after seeing results.
- **No tuning in the pilot.** Report the first-run numbers, including failures.
- Label every output `PILOT-STATIC` (scripted agent, templated scenarios, single host). It must never appear in a headline table.
- A scripted `gullible` agent always attempts the attack, so a deterministic gate will block designed scenarios almost by construction. The pilot tests enforcement **correctness and the harness**, not real-world effectiveness; say so wherever the numbers appear.
- Pilot scenarios become part of the **dev** split. The test split must be authored afresh (S4).
- One ablation in a pilot shows the harness can detect a difference; it is not a claim that the component matters.
- Do not submit a pilot-grade paper to a main-track venue (see §14).

---

## 16. 24-hour plan (technical report / preprint — **not** a main-track submission)

**Why this shape.** Testing quality cannot be compressed into a day: the real-model runs, baselines, intervals, adaptive attacks and frozen test split in §6 take weeks. What *can* be done in a day without compromising quality is to **make every claim no larger than the evidence**. A report that claims only what has been tested is high-integrity even if small; a main-track submission that claims effectiveness on a one-day pilot is not.

**Venue facts (official pages, 16 Nov 2026, AoE):** S&P 2027 cycle 2 registration closed 10 Nov (paper 17 Nov); EuroS&P 2027 registration 25 Nov, paper 2 Dec; USENIX Security '27 cycle 2 registration 19 Jan, paper 26 Jan. EuroS&P's CORE tier was not checked. Two weeks is too short for the §6 evaluation, so USENIX (§14) remains the realistic main-track target.

### 16.1 Hour-by-hour

| Hours | Work | Quality control |
|---|---|---|
| 0–1 | **ISSUE-009:** copy both spec files into the repo; update `STATE.md` (tiers, §12 decisions); run the full CI; tag the commit | CI green on the tagged commit |
| 1–3 | Freeze and **hash the scenario list**; commit a draft `evals/PREREG.md` for the *full* study (hypotheses, metrics, models, analysis plan) | Timestamped commit; nothing edited after the pilot starts |
| 3–5 | `void-bench` → `mcp-gate` adapter and eval driver; 10-scenario smoke test | Output regenerates from one command |
| 5–8 | **Pilot run** (§15): AF1–AF4 + BEN; configurations: ungated, gated, deny-all; one ablation (e.g. no pinning); signed manifest | Report **exact binomial (Clopper–Pearson) intervals** for every rate, even in the pilot; all outputs labelled `PILOT-STATIC` |
| 8–10 | Integrity checks: all 12 invariant adversarial tests; `mcp-audit verify` and `replay` on the pilot logs (divergence must be 0); differential tests for JCS/Merkle | Any failure is reported, not fixed-and-hidden |
| 10–16 | Write the report: problem, threat model, design, invariants, test evidence, pilot results, limitations, non-claims, generative-AI use statement | Every number cites a raw output file |
| 16–20 | **Claims ledger review** (below), preferably by a person who did not write the text | Cut every sentence the ledger cannot support |
| 20–24 | Tag release; anonymised artifact mirror if a venue needs one; decide whether to post as a preprint | Check the target venue's preprint policy first (S&P and EuroS&P CFPs allow preprints during review; verify for USENIX) |

### 16.2 Claims ledger

A table in the repo with one row per factual or numeric sentence: *claim · evidence file · command that reproduces it · interval (if a rate) · reviewer initials*. A sentence with no row is deleted.

| The report **may** claim | The report **must not** claim |
|---|---|
| The architecture, threat model and invariants | That the gate is effective against real attackers or models |
| Which invariant, property, differential and fuzz tests pass, and counts | Any "ASR reduced by X%" as a general result |
| That a deterministic gate blocked designed scenarios in a scripted-agent harness, with intervals | Utility/FPR numbers as representative of real workloads |
| Replay divergence = 0 and verify results on the pilot logs | Consistency/witness verification (unless S1–S3 are finished) |
| Overhead measured on the stated hardware | Superiority over CaMeL/FIDES or any prior system |
| Every limitation in §2, §7 and §12 | Human-factors benefits of the endorsement brief |

### 16.3 If you registered at S&P cycle 2 and still intend to submit tomorrow

The call for papers warns of aggressive desk-rejection in cycle 2, possible submission bans for ultra-low-quality submissions, and a one-year wait after rejection. If you proceed anyway, restrict the paper to the "may claim" column above, state plainly that no real-model or baseline evaluation was done, and accept that reviewers will likely treat the evaluation as insufficient. I do not recommend it: a reduced-claim report is better posted as a preprint and developed into the USENIX submission.

### 16.4 What this day buys the real submission

A tagged, CI-green baseline; a committed pre-registration draft; a working evaluation pipeline and signed manifests; a dev set; and an honest limitations list. The remaining work is §11.3 steps S1–S10.
