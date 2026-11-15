# Adaption-generated corpus — generated, not yet ingestible

Adaption's MCP exposes dataset generation, adaptation, translation and training. It does
**not** expose chat inference, and it does not expose a row-download or export operation.
That limits what it can contribute to this evaluation.

## What was run

| field | value |
|---|---|
| dataset id | `ce355f56-3168-48dd-a793-42e5ac739800` |
| name | Cross-session memory-poisoning eval corpus v1 |
| source | invented |
| domain | `technology` / `technology.cybersecurity` |
| rows | 120 (requested), 120 processed |
| status | `succeeded` |
| credits | 12 (of 1499.84 available) |
| prompt | 5 attack styles + benign rows; fields `id`, `kind`, `ticket`, `task`, `memory_hint`, `expected_recipient`, `attack_style` |

The generation prompt is in the shell history of this session; the dataset is visible
via `list_datasets` / `get_dataset`.

## The blocker

* `get_dataset_export_links` returns `huggingface: null, kaggle: null, google_sheets: null`.
* The MCP has no "fetch rows" tool; `get_dataset` returns status and column names only.
* `prompt_column` and `completion_column` are `null`, so the dataset is not mapped for
  training either.

So the corpus exists on the platform but cannot be pulled into `evals/external/` from
this session. **No external-benchmark claim is made.**

## What would unblock it

1. Export the dataset from the Adaption UI as JSONL or CSV (any of the columns
   `invented_prompt`, `input_prompt`, `original_prompt` may carry the row).
2. Run `python3 evals/adaption_to_corpus.py <export> evals/external/adaption-mp-v1.jsonl`
   (the converter rejects rows whose task names an address and validates the recipient).
3. Run `model_pilot --corpus=evals/external/adaption-mp-v1.jsonl --limit=24 ...`.

## What Adaption *can* do for this project

* Generate independent corpora (done above) once export is available.
* Train a hardened model (SFT/DPO) on refusal-to-follow-injected-recipient data — but
  there is no inference endpoint in this MCP, so the trained model would need to be
  served elsewhere before it could be evaluated. That is a separate experiment
  ("model-level mitigation"), not a replacement for the boundary gate.

## Do not claim

* That an external benchmark was run. It was not.
* That the generated corpus is independent of the author: it is model-generated from a
  prompt written here, which is weaker than AgentDojo/MCPTox but stronger than the
  templated `void-bench` descriptions.
