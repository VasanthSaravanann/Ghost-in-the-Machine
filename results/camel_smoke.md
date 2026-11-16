# CaMeL smoke on the hosted model

**Status: feasibility smoke, one task. Not a comparison.**

CaMeL is runnable against the Adaption OpenAI-compatible endpoint by setting
`OPENAI_BASE_URL`; AgentDojo derives the jailbreak model name from the pipeline name, so
the pipeline name is set to `local model`.

Command (in a checkout of `google-research/camel-prompt-injection` @ `f083b6b`):

```bash
# .env
OPENAI_API_KEY=<adaption key>
OPENAI_BASE_URL=https://api.prod.adaptionlabs.ai/api/v1
OPENAI_API_KEY=...
```

Patch `main.py` after `make_tools_pipeline(...)`:

```python
tools_pipeline.name = "local model"
```

Run:

```bash
uv run --python 3.12 --env-file .env main.py openai:gemma-4-31b-it \
  --run-attack --suites workspace --user-tasks user_task_0
```

Observed:

```
workspace - utility: 1.0
workspace - security: 0.0
```

## What this shows

* The hosted `gemma-4-31b-it` can serve CaMeL's planner/interpreter through the
  OpenAI-compatible endpoint; the CaMeL pipeline executes and AgentDojo scores it.
* A one-task run is enough to validate the integration path, not to compare systems.

## What this does not show

* Any comparison with the boundary gate: one task, no matched baseline in this file.
* That CaMeL's full 949-attack results reproduce on this endpoint; the planner may fail
  on other suites/tasks (the paper itself reports travel is hard).
* That the FIDES notebook can be run the same way: FIDES' public artifact is a tutorial
  notebook, not the benchmark harness.

The full protocol is `docs/head-to-head-protocol.md`.
