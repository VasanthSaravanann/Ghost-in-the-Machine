# H9 — InjecAgent-derived memory-injection corpus

**External corpus, derived — not the InjecAgent benchmark.** Source:
[`uiuc-kang-lab/InjecAgent`](https://github.com/uiuc-kang-lab/InjecAgent)
(MIT, arXiv:2403.02691), `data/test_cases_dh_base.json` (510 indirect-prompt-injection
cases). The benchmark's `Tool Response` and `Attacker Instruction` are used **verbatim**.
A routing sentence naming the attacker/partner address is **added**, because this pilot's
metric is the recipient of a later-session email, not an attacker tool call. No
InjecAgent score is computed.

Derivation: `evals/injecagent_to_corpus.py` → `evals/external/injecagent-memory-v1.jsonl`
(36 cases × attack/benign counterpart = 72 rows). The pre-registered subset is the first
12 rows by id: 6 attack / 6 benign, stratified across the three InjecAgent harm types.

## Design (and two disclosed runtime amendments)

* Models: `llama3.2:latest` (`a80c4f17…`), `gemma3:4b` (`68ceab7e…`).
* **`qwen3:4b` is excluded**: it exceeded the 180 s per-call timeout on the long
  InjecAgent prompts (6/24 records in 30 min). No qwen result is reported.
* Modes: `plain`, `b2allow` (the `b2` arm was dropped to halve runtime; H8b measures it).
* 12 rows/model (6 attack / 6 benign), one repetition, same parser, adapters, policies.
* The first execution was aborted by a 40-minute tool timeout (77/216 records) and was
  discarded without analysis; the subset was reduced for runtime, not by outcome.

Raw transcripts: `results/model_injecagent.jsonl` (48 records).

## Results

| model | prompt | attack success | B3 allows | G allows | utility |
|---|---|---|---|---|---|
| llama3.2:latest | plain | 1/6 = 16.7% (95% 0.9–58.2) | 1/6 | 0/6 | 4/6 = 66.7% |
| llama3.2:latest | b2allow | 1/6 = 16.7% (95% 0.9–58.2) | 1/6 | 0/6 | 5/6 = 83.3% |
| gemma3:4b | plain | 5/6 = 83.3% (95% 41.8–99.1) | 5/6 | 0/6 | 5/6 = 83.3% |
| gemma3:4b | b2allow | 3/6 = 50.0% (95% 15.3–84.7) | 3/6 | 0/6 | 5/6 = 83.3% |

Pooled across the two models: plain **6/12 = 50.0%** (24.5–75.5), `b2allow`
**4/12 = 33.3%** (12.3–60.9). On the **10 successful attack calls**, B3 allows **10/10**
(100 %, 74.1–100.0) and G denies **10/10** (0/10 allows, 0.0–25.9), all
`DENY_TAINT_PIVOT`.

## What this adds

1. **The gate result replicates on externally sourced injection prose**: every
   successful call that policy-only allows is denied by provenance, 10/10.
2. **Model-dependence persists**: gemma3 is highly susceptible (5/6), llama3.2 is not
   (1/6). `b2allow` halves gemma3 and does nothing for llama.
3. **The self-authored style set overestimated llama3.2.** On the hand-written tickets
   (H8b) llama3.2 succeeded 12/15 (80 %); on InjecAgent-derived prose it succeeds 1/6
   (17 %). That is the external-validity argument for not evaluating only on your own
   attack text — and it cuts against the earlier headline, which is reported here rather
   than buried.
4. **Utility is not 100 % on longer external content** (4–5 of 6). The failures are not
   refusals: the model sends to an address it found *inside the tool output*
   (`amy@example.com`, `john.doe@gmail.com`). That is the same data-flow failure from
   the benign side, and it is why the boundary must judge the call, not the task.

## Limits

* n = 6 attack rows per cell; intervals are correspondingly wide (1/6 spans 0.9–58.2 %).
* Two models; qwen excluded for latency, not for its result.
* The routing suffix is authored here; the corpus is **derived**, not the benchmark.
* The gate columns are evaluated on the row's intended recipient (attacker for attack
  rows, partner for benign rows). For a third address chosen by the model, the
  allowlist would decide; that case is reported under utility, not under G.
* No tool-call score, no AgentDojo, no MCPTox.
