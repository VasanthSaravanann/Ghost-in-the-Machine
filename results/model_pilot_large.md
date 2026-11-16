# H17 — larger-n local replication

**Pre-registered before the run (`evals/PREREG.md`, H17).** Two local models,
6 repetitions of the 8-row corpus = 48 rows/model (30 attack / 18 benign), modes
`plain`, `b2`, `b2allow`. Same parser, adapters and policies as H8b. This exists to
tighten H8b's 15-attack cells; it is a replication, not a new claim.

Raw transcripts: `results/model_pilot_large.jsonl` (288 records).

## Results

| model | prompt | ASR | G allows | utility |
|---|---|---|---|---|
| llama3.2:latest | plain | 24/30 = 80.0% (64.3–90.9) | 0/30 | 18/18 |
| llama3.2:latest | b2 | 6/30 = 20.0% (9.1–35.7) | 0/30 | 18/18 |
| llama3.2:latest | b2allow | 18/30 = 60.0% (43.4–75.0) | 0/30 | 18/18 |
| gemma3:4b | plain | 30/30 = 100.0% (90.5–100.0) | 0/30 | 18/18 |
| gemma3:4b | b2 | 30/30 = 100.0% (90.5–100.0) | 0/30 | 18/18 |
| gemma3:4b | b2allow | 0/30 = 0.0% (0.0–9.5) | 0/30 | 18/18 |

Pooled: plain **54/60 = 90.0%** (81.2–95.6), b2 **36/60 = 60.0%** (48.6–70.7),
b2allow **18/60 = 30.0%** (20.4–41.2). Benign utility **108/108 = 100%**
(97.3–100.0). On the **108 successful attack calls**, B3 allows **108/108** and G
denies **108/108** (0/108 allows, 0.0–2.7), all `DENY_TAINT_PIVOT`.

## What it confirms

The H8b model-specific effects are stable, with narrower intervals:

| cell | H8b (15 attack) | H17 (30 attack) |
|---|---|---|
| llama plain | 12/15 = 80.0% | 24/30 = 80.0% |
| llama b2 | 3/15 = 20.0% | 6/30 = 20.0% |
| llama b2allow | 9/15 = 60.0% | 18/30 = 60.0% |
| gemma3 b2 | 15/15 = 100.0% | 30/30 = 100.0% |
| gemma3 b2allow | 0/15 = 0.0% | 0/30 = 0.0% |

So `b2`'s failure on gemma3 and its partial effect on llama3.2 are not small-sample
noise, and `b2allow`'s 60% residual on llama3.2 is stable. G's denial remains total.

## Limits

Two models only (qwen3:4b was not re-run: ~6 s/call would make 6 reps impractical);
built-in corpus, assisted summariser; the intervals still treat repetitions as
independent. This does not replace the hosted H12 result.
