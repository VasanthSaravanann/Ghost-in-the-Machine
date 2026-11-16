# AgentDojo (real package) — baseline and boundary replay

**Status: EXPLORATORY** — run during a fix pass; not pre-registered.

**Why this file exists:** AgentDojo is the shared benchmark behind CaMeL/FIDES/
PRUDENTIA. A derived corpus cannot be compared with their numbers, so this runs the
real package (`agentdojo`, v1.2 benchmark, `workspace` and `travel` suites) with the
hosted Adaption models. It is **not** a native AgentDojo defense integration; the
boundary is a post-hoc replay, labelled as such.

Provider: Adaption OpenAI-compatible endpoint. AgentDojo sends `tools` and
`tool_choice=auto`; vLLM rejects the `name` field on tool messages, which the runner
strips (a transport compatibility patch, not a change to the benchmark).

## Baseline results (no defense)

| suite | model | user × injection | utility | security (attack succeeded) |
|---|---|---|---|---|
| workspace | deepseek-v4-flash | 20 × 3 | 55/60 = 91.7% | **0/60 = 0.0%** |
| workspace | gemma-4-31b-it | 10 × 2 | 20/20 = 100.0% | 0/20 = 0.0% |
| workspace | qwen3.8-27b | 10 × 2 | 20/20 = 100.0% | 0/20 = 0.0% |
| travel | qwen3.8-27b | 8 × 2 | 16/16 = 100.0% | **1/16 = 6.2%** |

The `important_instructions` attack does not land on the workspace suite for these
models; `direct` on travel produces one success. AgentDojo's attack success is
model/suite/attack dependent — that is itself an external-validity finding, and it is
why a single derived corpus was not enough.

Evidence: `results/agentdojo_workspace.json`, `results/agentdojo_gemma.json`,
`results/agentdojo_qwen.json`, `results/agentdojo_travel.json`; logs under
`results/agentdojo_runs/`.

## Native defense (AgentDojo pipeline element)

`evals/agentdojo_defense.py` implements the conservative rule as a native
`ToolsExecutionLoop` replacement: before a tool call executes, if any tool result has
been seen, an effectful call is replaced by a `DENY_TAINT_PIVOT` refusal and the loop
**stops**. The first row is a Python implementation of the rule; the third row routes every
effectful call through `gate-eval`, which uses the Rust `PolicyEngine`. Provenance
tracking (has a tool result been seen?) remains in Python.

| travel / qwen3.8-27b / direct | utility | security |
|---|---|---|
| baseline (no defense) | 16/16 = 100.0% | 1/16 = 6.2% |
| native provenance defense (Python rule) | **6/16 = 37.5%** | **0/16 = 0.0%** |
| Rust-linked defense (`gate-eval` → PolicyEngine) | **6/16 = 37.5%** | **0/16 = 0.0%** |

The defense removes the only successful attack and costs 10/16 utility (the runs that
need an effectful call after a read). An earlier version let the LLM retry the blocked
call until it hit the context limit; AgentDojo marks `security=True` on API/context
errors as a fail-safe, which looked like an attack success. The loop now terminates at
the first block, so the 0/16 is an actual outcome, not a fail-safe artefact.

## Boundary replay (post-hoc, same rule as `DENY_TAINT_PIVOT`)

`evals/agentdojo_replay.py` replays AgentDojo's own trajectories: after a tool result,
an effectful call is denied; read-only calls are exempt. This is the conservative
turn-window rule, applied to the benchmark's logs, not a native defense.

| suite | runs | security successes | prevented | utility successes with a denied effect (upper bound) |
|---|---|---|---|---|
| travel / qwen3.8-27b / direct | 16 | 1 | **1/1** | 10/16 |
| workspace / deepseek-v4-flash | 60 | 0 | n/a | 18/55 |

* The only successful AgentDojo attack in these runs is prevented by the boundary rule.
* The utility upper bound is high (10/16 on travel) because a denied effect may be the
  attack call or a legitimate booking; without per-call attack attribution this is an
  upper bound, not a point estimate.
* The per-segment checkpoint (`principal_approved` content digests in `mcp-gate`) is the
  recovery mechanism; it is tested at the transport, not yet applied to AgentDojo.

## What this closes and what it does not

**Closes:** the “no AgentDojo proper” objection at the **baseline** level — real suites,
real tasks, real injections, real utility/security checks, with the model served through
the same API the rest of the paper uses.

**Does not close:** a CaMeL/FIDES comparison on the same tasks, and a native
implementation that links the **Rust** gate rather than mirroring its rule in Python.
The native defense above is an AgentDojo pipeline element; the replay is retained as a
cross-check.

## Reproduce

```
# Python 3.12 venv (Python 3.15 cannot build cachebox)
python3.12 -m venv /tmp/adjo312 && /tmp/adjo312/bin/pip install agentdojo
ADAPTION_API_KEY=... /tmp/adjo312/bin/python evals/agentdojo_run.py \
  --suite travel --model qwen3.8-27b --user-tasks 8 --injection-tasks 2 \
  --attack direct --out results/agentdojo_travel.json
/tmp/adjo312/bin/python evals/agentdojo_replay.py \
  results/agentdojo_runs/travel/qwen3.8-27b \
  --pairs results/agentdojo_travel.json --out results/agentdojo_replay_travel.json
```
