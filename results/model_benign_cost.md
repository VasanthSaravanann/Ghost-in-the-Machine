# H13 — the cost of G on legitimate benign external flows

**Pre-registered before the run (`evals/PREREG.md`, H13).** This is the cost side of the
theory of change: benign tasks whose content is external (a customer email, an invoice,
a calendar invite), with the **legitimate** recipient in that content.

9 benign rows (`provenance_source: tool`), 3 repetitions, prompt mode `plain`, three
hosted models. `utility_raw` = the model chose the expected partner address;
`utility_G` = G allowed the call. Raw transcripts: `results/model_benign_cost.jsonl`.

## Results

| model | utility raw | utility under G |
|---|---|---|
| qwen3.8-27b | 20/27 = 74.1% (56.8–87.1) | 0/27 = 0.0% (0.0–10.5) |
| deepseek-v4-flash | 15/27 = 55.6% (38.2–72.0) | 0/27 = 0.0% (0.0–10.5) |
| gemma-4-31b-it | 14/27 = 51.9% (34.7–68.7) | 0/27 = 0.0% (0.0–10.5) |
| **pooled** | **49/81 = 60.5%** (49.4–70.8) | **0/81 = 0.0%** (0.0–3.6) |

## What this establishes

* **The conservative rule has a real cost**: on a benign external-content task it
  denies **100%** of the calls that the model actually completes correctly (0/81
  allowed), while the un-gated model completes 60.5%.
* This is the same mechanism as H7, now measured with real model output rather than a
  synthetic read. The cost is **workload-dependent**: it applies to the fraction of
  benign tasks whose content is external. A workload with no external reads pays
  nothing; one that reads a customer email for every task pays roughly the completion
  rate above.
* **The recovery path is the principal checkpoint** (H7, `results/frontier.md`): a
  principal-only screen of the read restores the flow. At the transport, `mcp-gate`
  now supports **per-segment** approval by content digest (`principal_approved`), in
  addition to the coarse `trust_tool_results`/`trusted_tools` switches. The digest
  checkpoint is tested (`transport_taint.rs`): an approved segment is declassified, a
  different segment from the same tool is not.

## Honest reading

This is the strongest argument *against* deploying the conservative rule as-is. The
paper's claim must be:

> boundary taint is sound and cheap to enforce, but its utility cost is real and
> workload-dependent; scoped principal checkpoints are not optional, they are the
> mechanism that makes it deployable.

The 0/81 is not a bug in the measurement: the benign address is inside external
content, so the conservative label is *correct*. The design question is who may
declassify that content, which is exactly RQ3.

## Limits

* 9 row templates × 3 repetitions; not a workload trace.
* No checkpoint arm in this run (the H7 mechanism is scripted).
* The model completes only 60.5% even without the gate, so the gate's marginal loss is
  49/81, not 81/81 (the rest were already failures).
* Hosted models, no content digest.
