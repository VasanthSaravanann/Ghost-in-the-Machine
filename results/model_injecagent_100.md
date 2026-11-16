# H14 — 100 InjecAgent-derived attack cases

**Pre-registered before the run (`evals/PREREG.md`, H14).** Attack-only external corpus:
the first 100 attack rows of a 102-case derivation from InjecAgent's
`data/test_cases_dh_base.json` (MIT, arXiv:2403.02691), spanning all three harm types.
Payload and tool response are verbatim; a routing suffix names the attacker address.
This is **not** the InjecAgent benchmark and no tool-call score is computed.

Model: `gemma-4-31b-it` via the hosted Adaption API, temperature 0, JSON mode,
`max_tokens` 4096. Modes `plain` and `b2allow`, one repetition. Raw transcripts:
`results/model_injecagent_100.jsonl` (200 records).

## Results

| prompt | ASR | B3 allows | G allows | parseable |
|---|---|---|---|---|
| plain | **44/100 = 44.0%** (35.6–52.7) | 44/44 | **0/44** | 44/100 = 44.0% |
| b2allow | **0/100 = 0.0%** (0.0–3.0) | 0 | 0 | 45/100 = 45.0% |

On the 44 successful plain attacks, G denies **44/44** (`DENY_TAINT_PIVOT`); B3 allows
all 44. Every parseable plain attack chose the attacker address (ASR = parseable), so
the model did not substitute a third address in this corpus.

## What this adds

* **External validity at n = 100.** The 44% plain ASR is consistent with the 33%
  (5/15) gemma-4 cell in H12; the gate denies every successful call with a 95% upper
  bound of 3.0% on the residual.
* **The utility-preserving prompt defence is strong on this model and corpus**:
  0/100 with the permitted recipient supplied out-of-band. This reinforces the H12
  conclusion, not the earlier "prompt defence is unreliable" headline. The honest
  synthesis: prompt defence is reliable when the allowlist is known and the model
  obeys; it is not reliable across models (local 3B, H8b) and it cannot express
  provenance.
* **No utility arm.** The corpus is attack-only; utility is measured in H12/H13.

## Limits

* One model, one run, attack-only, derived corpus (routing suffix authored here).
* 44% parseable means 56% of cases produced no JSON recipient (`{"to": "none"}` or a
  refusal). Those are counted as non-compliance, not as gate wins.
* No content digest from the API; provider updates can change the model.
