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

* **No eval gate has run against `mcp-gate`.** ASR, utility, `E_bar`, FPR, regret and NRP
  numbers have never been produced by the wired binary; the corpus (360 scenarios) is
  templated per subfamily, not curated attack prose.
* **The real-model loop is not an `mcp-gate` run.** `model_pilot` measures the model's
  `TO:` line and then asks the policy engine about that call, on the same transcript.
  Memory is still passed as text, and the attack/benign provenance label is assigned by
  the harness from the row kind; it is not derived from an instrumented tool call.
* **The external corpus is model-generated.** `evals/external/adaption-mp-v1.jsonl`
  (when present) comes from Adaption's dataset generator, not AgentDojo/MCPTox. It is
  independent of the B2 text but still synthetic.
* **The adaptive attacker is self-play.** One 3B model writes the rewrites, budget 3,
  5 rows; it does not see the policy, the brief template or the layout model, and does
  not search over gate evasions (§6.4 is still unrun).
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
