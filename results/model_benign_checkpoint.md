# H18 — simulated principal checkpoint

**Pre-registered before the run (`evals/PREREG.md`, H18).** H13 showed the cost:
0/81 benign external-content flows executed under the conservative gate. H18 tests the
recovery mechanism: if the principal approves the segment, the label is `PRINCIPAL` and
G allows the call.

This is a **simulated** approval, not a human study. It measures the mechanism, not
approval behaviour, fatigue, or usability.

Design: `evals/external/benign-external-approved-v1.jsonl` (the H13 rows with
`provenance_source: principal`), `llama3.2:latest`, 3 repetitions, mode `plain`.
Raw: `results/model_benign_checkpoint.jsonl` (27 records).

## Results

| condition | utility raw | utility under G |
|---|---|---|
| H13, unapproved external segment (3 hosted models) | 49/81 = 60.5% | **0/81 = 0.0%** |
| H18, approved segment (llama3.2) | 27/27 = 100.0% | **27/27 = 100.0%** |

With approval, G allows every completed benign call. The mechanism is the per-segment
content-digest checkpoint in `mcp-gate` (`principal_approved`), tested separately in
`transport_taint.rs`: approving one segment declassifies that segment, not a different
segment from the same tool.

## What this establishes

* The conservative gate is not an unconditional utility cliff: the checkpoint recovers
  the flow when the correct segment is approved.
* The recovery is **scoped**: approval is by content digest, not by tool name, so an
  attacker who reads a different document does not inherit the approval.

## What it does not establish

* Human approval rates, approval fatigue, or whether a principal can reliably identify
  the right segment under time pressure. H7 is scripted; H18 is simulated.
* That the approved content is safe: approval is a trust decision, not a verification.
* Any comparison with CaMeL/FIDES checkpointing; their policies are in-planner.

The human-factors study remains the open deployment question.
