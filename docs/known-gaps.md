# Known gaps and open decisions

Generated from `STATE.md`. **This file is the honest answer to "is it safe yet?"**

## Open issues (all require a human decision or an external resource)

| ID | Blocks | Summary |
|---|---|---|
| ISSUE-001 | G-M0 / P-LAT-1 | No agreed storage profile or benchmark host for the p99 ≤ 15 ms latency gate. |
| ISSUE-002 | T-E2E-004/005 | Those flows need the endorsement channel (M3-T05) and a wired binary (M0-T06). |
| ISSUE-003 | T-SYM (G-M3) | Deterministic layout model is implemented; the ≤2 % headless-browser cross-check has no CI harness. |
| ISSUE-004 | G-M1..G-M3 | 23 tasks are *tests-green, gate-unrun*: the eval corpus now exists (M5-T02) but no gate has been executed against a wired target. |
| ISSUE-005 | M3-T05 | Browser CI image + `webauthn-rs` native-code policy undecided. |
| ISSUE-006 | M4-T03, half of M4-T04 | `verify_consistency` is not shipped. The prover is byte-identical to the independent reference; the verifying fold is not yet derived correctly. **Do not trust a cosignature until this is fixed.** |
| ISSUE-007 | M4-T03 | Witness protocol blocked on DEC-P04 and ISSUE-006. |
| ISSUE-010 | external validity | An Adaption-generated corpus exists (120 rows) but the MCP has no row export, so it cannot be ingested. No external benchmark was run. |

## Decisions pending human sign-off (R12)

* **DEC-P01** group commit / durable-commit policy — implemented (`SegmentLog::append` sync, `append_batch` grouped) but `append_batch` is used by no default path.
* **DEC-P02** JCS integer exactness — implemented and tested; awaiting sign-off.
* **DEC-P03** rate-limited prompt queue (budget consumed at render, overflow denies) — implemented; awaiting sign-off.
* **DEC-P04** own STH format + witness/cosignature protocol — **not** implemented; no community spec has been evaluated.
* **DEC-005 / DEC-006** task reordering (M1 before M0-T06; M5-T01 before M4-T04) and JSON-as-YAML — logged, reversible.

## Unverified claims from the spec (§0.7 / §12) — do not rely on these

* Every citation in the original PRD.
* Whether `webauthn-rs` links OpenSSL in the pinned release.
* Suitability of any community witness/cosignature specification.
* Whether Kani can discharge the lattice/budget proofs at the stated size.
* Whether the latency/throughput targets are reachable on the target storage profile.
* Whether the PRD's external works exist as stated.

## What the tests do *not* establish

* **Hosted models have no content digest.** H12 pins `qwen3.8-27b`,
  `deepseek-v4-flash` and `gemma-4-31b-it` by id; provider updates and safety filters
  can change behaviour without notice. `glm-5.2` refused the task at the provider layer
  (security policy), which is a model-level mitigation, not a gate result.
* **No eval gate has run against `mcp-gate`.** ASR, utility, `E_bar`, FPR, regret and NRP
  numbers have never been produced by the wired binary; the corpus (360 scenarios) is
  templated per subfamily, not curated attack prose.
* **Transport provenance is wired and exercised with a live model.** H15 drives a
  hosted model through the real `mcp-gate` process: attacker 7/7 blocked, shadow
  control 3/3 executed, benign 3/3 blocked (the measured cost). The upstream is a
  fake server and the run stopped at a provider 429; a real upstream is still open.
* **AgentDojo has a native defense; CaMeL/FIDES are reported-number comparisons.** The
  Rust-linked `RustGateLoop` removes the one travel attack at a 10/16 utility cost.
  CaMeL/FIDES were **not run head-to-head**; `results/camel_fides.md` compares their
  reported tables with an explicit non-comparability boundary. A 16-pair matched CaMeL pilot is in
  `results/head_to_head.md` (CaMeL 93.8% utility/6.2% attack; gate 37.5%/0%).
  FIDES is not head-to-head; the full 949-attack run is the remaining protocol
  (`docs/head-to-head-protocol.md`). H9's InjecAgent-derived corpus is still derived;
  the Adaption corpus could not be exported (ISSUE-010).
* **The adaptive attacker is self-play.** One 3B model writes the rewrites, budget 3,
  5 rows. H11 gives it the defender's instruction and allowlist (no improvement); it
  still does not search over gate evasions or see the brief template (§6.4 is unrun).
* **The checkpoint is simulated, not human.** H18 approves the benign segment and
  recovers 27/27 utility. The sensitivity analysis sets the target (`q <= 7 %` false
  approvals for ASR <= 5 %); the IRB-ready study is
  `docs/human-checkpoint-protocol.md`.
* **H8 (2026-11) is exploratory.** Its pre-registration was committed with its result
  and a prior 0/6 protocol was discarded. Only H8b/H8c/H8d are pre-registered before
  their runs.
* **No adversarial/chaos matrix run** (ADV-INV1..12) — several depend on
  M0-T06/M3-T05/M4-T03.
* **No formal verification**: Kani harnesses are not written; no proof has been
  discharged.
* **No fuzzing campaign**: three targets exist (`jcs_parse`, `mcp_frame`, `policy_toml`);
  cumulative runtime is minutes, not 72 h.
* **No reproducible build, SBOM or signed release.**
* **No external pentest.**
* **No legal/DPIA review** of crypto-shredding as an erasure mechanism.
* **Latency**: only framing-level numbers (≈0.04 µs/message) exist; end-to-end
  p50/p95/p99 are unmeasured.
