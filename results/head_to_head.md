# Head-to-head pilot: CaMeL vs boundary gate vs undefended

**Status: pilot, 16 pairs. Same model, suite, attack and task pairs. Not the full
949-attack benchmark.**

| setting | value |
|---|---|
| AgentDojo | v1.2; CaMeL's lock pins 0.1.34, our runner uses 0.1.35 |
| suite | travel |
| attack | `direct` |
| user tasks | `user_task_0` … `user_task_7` |
| injection tasks | first two (`injection_task_6`, `injection_task_0`) |
| model | `gemma-4-31b-it` via Adaption's OpenAI-compatible endpoint |
| CaMeL | `google-research/camel-prompt-injection` @ `f083b6b`, no security policies |
| boundary | Rust `PolicyEngine` via `gate-eval` + `RustGateLoop` (conservative rule) |

Commands: `docs/head-to-head-protocol.md`. Raw results: `results/h2h_undefended.json`,
`results/h2h_gate.json`; CaMeL logs under `camel/logs/`.

## Results

| system | utility | security (attack succeeded) |
|---|---|---|
| undefended | **16/16 = 100.0%** (82.9–100.0) | 0/16 = 0.0% (0.0–17.1) |
| **CaMeL** (in-planner IFC) | **15/16 = 93.8%** (73.6–99.7) | 1/16 = 6.2% (0.3–26.4) |
| **boundary gate** | **6/16 = 37.5%** (17.8–60.9) | **0/16 = 0.0%** (0.0–17.1) |

Wall-clock: CaMeL 17 m 49 s; boundary gate 3 m; undefended 4 m 24 s.

## What this establishes

* **Matched result, same model and task pairs.** CaMeL preserves far more utility than
  the boundary gate (93.8 % vs 37.5 %) while both are in the same security range on this
  subset (1/16 vs 0/16).
* **The boundary's conservative rule is the cause of the utility loss**, not the model:
  it denies every effectful call after an untrusted read, while CaMeL tracks exact data
  dependencies and allows data-independent actions.
* **The undefended baseline's 0/16 is not a paired ASR.** AgentDojo generates the
  injection per pipeline; the text the model saw under CaMeL is not byte-identical to
  the text it saw undefended. Utility is paired; security is indicative, not paired.
* **The honest conclusion**: in-planner IFC is more precise. The boundary's claim is
  deployability without a planner/model change and persistence across sessions, not
  superiority on AgentDojo utility.

## Cost and scaling

The pilot is 16 pairs. A linear estimate for the full 949-attack benchmark:
CaMeL ≈ 18 h, boundary gate ≈ 3 h, plus attack generation and retries. A stratified
**200-pair** run is ≈ 4 h CaMeL + 40 min gate and fits a $1,000 token budget; the full
949 is a multi-day wall-clock commitment, not a token-budget problem.

## What is still not head-to-head

* **FIDES**: its public artifact is a tutorial notebook, not the 949-attack harness.
  The reported-number comparison remains (`results/camel_fides.md`).
* **CaMeL with security policies** (`+camel+secpol`): this run uses the no-policy
  configuration, matching the paper's “separation only” result.
* **Full task set**: 16 of 949 pairs; intervals are wide and the attack success is one
  event.
