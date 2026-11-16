# Comparison to in-planner IFC: CaMeL and FIDES (reported numbers)

**We did not run CaMeL or FIDES.** This file compares against the numbers reported in
their papers on AgentDojo, with an explicit non-comparability boundary. It is not a
head-to-head experiment.

Sources:

* CaMeL — *Defeating Prompt Injections by Design*, arXiv:2503.18813. Tables 3 and 4,
  Claude 4 Sonnet (the paper’s main model).
* FIDES — *Securing AI Agents with Information-Flow Control*, arXiv:2505.23643.
  Tables 1 and 7, gpt-4o, Tool Knowledge attack.
* Denominator: both papers use AgentDojo v1.2; FIDES states **949 attacks** per model.
  CaMeL’s Table 4 reports **counts** of successful attacks, so its ASR below is
  `count / 949` (the paper’s own aggregate is “77 % vs 84 % of tasks solved with
  provable security”).

## Reported results

| system | model | utility | attack success | source |
|---|---|---|---|---|
| undefended | Claude 4 Sonnet | 80.1 % (under attack) | 75/949 = **7.9 %** | CaMeL T3/T4 |
| **CaMeL** (no policies) | Claude 4 Sonnet | 75.7 % (under attack) | 13/949 = **1.4 %** | CaMeL T3/T4 |
| **CaMeL** (with policies) | Claude 4 Sonnet | 75.7 % | 11/949 = **1.2 %** | CaMeL T3/T4 |
| undefended | gpt-4o | 83.30 % | 163/949 = **17.2 %** | FIDES T1/T7 |
| Tool Filter (probabilistic) | gpt-4o | 70.93 % | 28/949 = **2.95 %** | FIDES T1/T7 |
| **FIDES** (no policies) | gpt-4o | 59.79 % | 24/949 = **2.53 %** | FIDES T1/T7 |
| **FIDES** (with policies) | gpt-4o | **50.31 %** | 1/949 = **0.11 %** | FIDES T1/T7 |

FIDES notes that the single remaining success is a text-to-text injection; excluding
two injection tasks they do not consider attacks on their policies, FIDES★ is 0/949.
CaMeL notes that its residual successes are the same two exception-handling cases
(banking and travel), not prompt injections.

## Our results on AgentDojo (not the same subset)

| system | suite / model | utility | attack success |
|---|---|---|---|
| undefended | travel / qwen3.8-27b, `direct`, 8×2 | 16/16 = **100 %** | 1/16 = **6.2 %** |
| **boundary gate** (Rust engine linked) | travel / qwen3.8-27b, `direct`, 8×2 | **6/16 = 37.5 %** | **0/16 = 0 %** |
| undefended | workspace / deepseek-v4-flash, 20×3 | 55/60 = 91.7 % | 0/60 |
| undefended | workspace / qwen3.8-27b, `direct`, 10×2 | 20/20 = 100 % | 0/20 |

## Why this is not a head-to-head

1. **Different models.** CaMeL/FIDES use Claude 4 Sonnet / gpt-4o/o1/o3; our runs use
   qwen3.8-27b, deepseek-v4-flash and local 3B–4B models. Model capability dominates
   both utility and attack rate.
2. **Different subsets and attacks.** We run 8–20 user tasks × 1–3 injections; they run
   the full 949-attack benchmark. Our travel result is the `direct` attack; theirs is
   Tool Knowledge / Important Instructions.
3. **Different mechanisms.** CaMeL/FIDES are **in-planner** IFC: the planner separates
   control and data flow and tracks labels. Our boundary is **outside** the planner and
   model, and it does not require a planner. The comparison is about what class of
   guarantee each provides, not which is “better” on one number.
4. **Different utility semantics.** Their TCR counts task completion under the
   benchmark’s rubric; our utility is the recipient of a single email in a reduced
   harness.

## What the comparison does support

* The **order of magnitude is consistent**: in-planner IFC and the boundary gate both
  reduce attack success by roughly an order of magnitude on AgentDojo-class tasks, at a
  substantial utility cost.
* The **utility cost is the shared open problem**: FIDES★ drops from 59.8 % to 50.3 %
  with policies; CaMeL is 75.7 % under attack vs 80.1 % undefended; our gate drops
  travel utility from 100 % to 37.5 % on its subset. None of these systems makes
  declassification free.
* The **mechanism difference is real**: CaMeL/FIDES require a planner/interpreter;
  the boundary gate does not, and it can be deployed at the MCP transport. That is the
  claim the paper should make — not “better than CaMeL/FIDES”.

## What is still missing

A **head-to-head run** on the same AgentDojo version, models and attack, with the same
utility rubric. That requires their stacks and API budget; it is the one comparison
this repository does not contain, and it is stated as such rather than approximated.
