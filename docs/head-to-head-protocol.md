# Head-to-head protocol: CaMeL / FIDES / boundary gate on AgentDojo

**Goal:** compare the boundary gate with in-planner IFC on the **same AgentDojo
version, model, attack and task pairs**. This is the comparison the reported-number
table (`results/camel_fides.md`) cannot make.

**Status:** executable. A one-task CaMeL smoke against the Adaption-hosted model
succeeded (utility 1.0, security 0.0; `results/camel_smoke.md`). The full run needs
API budget/time, not new code.

## Pins

| artifact | pin |
|---|---|
| AgentDojo | `0.1.34` (CaMeL's `uv.lock`; our own tests use 0.1.35) |
| CaMeL | `google-research/camel-prompt-injection` @ `f083b6b` |
| FIDES | `microsoft/fides` @ `669c046` (tutorial notebook) |
| our gate | repo commit at run time, recorded in the manifest |

## Models

Primary comparison (matches the papers): `gpt-4o-2024-08-06` for both systems, if an
OpenAI key is available. Secondary, executable here: `gemma-4-31b-it` through the
Adaption OpenAI-compatible endpoint, with `OPENAI_BASE_URL` set; this is the same model
for CaMeL and the boundary gate, so the comparison is same-model even if it is not the
papers' model.

```
export OPENAI_API_KEY=...            # Adaption key for the secondary run
export OPENAI_BASE_URL=https://api.prod.adaptionlabs.ai/api/v1
```

## Step 1 — CaMeL

```bash
git clone --depth 1 https://github.com/google-research/camel-prompt-injection camel
cd camel && git checkout f083b6b
# .env: OPENAI_API_KEY / OPENAI_BASE_URL (do not commit it)
uv run --python 3.12 --env-file .env main.py openai:gemma-4-31b-it \
  --run-attack --suites travel --user-tasks user_task_0 user_task_1 user_task_2
```

Two patches are required for a non-OpenAI model id and a subset run (both are
compatibility, not benchmark changes):

1. after `make_tools_pipeline(...)`, set `tools_pipeline.name = "local model"` (AgentDojo
   derives the jailbreak's model name from the pipeline name);
2. pass `injection_tasks=list(suite.injection_tasks)[:N]` to
   `benchmark_suite_with_injections` (CaMeL's `main.py` otherwise runs all 14 injection
   tasks per user task);
3. set `attack_name = "direct"` if you want the attack that actually lands on travel
   (CaMeL defaults to `important_instructions`).

Record the `logs/` directory. The smoke used `workspace`/`user_task_0` and returned
utility 1.0, security 0.0.

## Step 2 — FIDES

FIDES' public artifact is a **tutorial notebook**, not the full 949-attack harness. Two
options:

* **Port the notebook** to the same endpoint (`OpenAI(base_url=..., api_key=...)` instead
  of Azure), run the same tasks, and log utility/security. This is a same-model,
  same-task comparison but not the paper's full harness.
* **Use the reported numbers** (`results/camel_fides.md`) and state that the FIDES part
  is not head-to-head. This is the honest fallback if the notebook cannot be adapted
  without changing the planner.

Do not present a notebook subset as the FIDES benchmark.

## Step 3 — boundary gate and baselines

Use the same suite, model and task ids:

```bash
python evals/agentdojo_run.py --suite travel --model gemma-4-31b-it \
  --attack direct --user-tasks 3 --injection-tasks 1 --defense none \
  --out results/head_to_head_undefended.json
python evals/agentdojo_run.py --suite travel --model gemma-4-31b-it \
  --attack direct --user-tasks 3 --injection-tasks 1 --defense rust \
  --out results/head_to_head_gate.json
```

The Rust-linked defense calls `gate-eval` (the `PolicyEngine`) per effectful call; the
provenance tracking is the conservative rule.

## Step 4 — analysis

* Unit: the `(user_task, injection_task)` pair. Paired across systems.
* Primary security: **ASR difference** (attack success). McNemar's exact test on
  discordant pairs; cluster bootstrap by user task.
* Primary utility: **TCR difference**. Pre-register a non-inferiority margin (e.g.,
  10 percentage points); do not claim superiority on a non-significant difference.
* Report counts/denominators, not only percentages. AgentDojo v1.2 has 949 attacks per
  model; a 3-task subset is a pilot, not the paper's estimate.
* Cost/latency: tokens and wall-clock per task from the logs.

## Sample size and effort

* Pilot: 3–5 user tasks × 1 injection per suite, as above.
* Full: all 40 workspace / 20 travel / 16 banking / 20 slack user tasks × all injection
  tasks, for both systems. Expect ~1–3 days of hosted-model time and a few hundred
  dollars at current token prices.
* Risks: CaMeL's interpreter is a research artifact (may crash); FIDES' notebook is not
  the harness; provider rate limits; AgentDojo version drift. Pin 0.1.34 and record it.

## What counts as a result

A table with, per suite and system: utility `k/n` with a 95 % interval, ASR `k/n` with a
95 % interval, and the paired difference with its interval. A single number without its
denominator is not a result.
