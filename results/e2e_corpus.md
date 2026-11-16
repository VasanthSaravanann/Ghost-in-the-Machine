# Full model corpus through the real `mcp-gate` CLI

**Status: EXPLORATORY** — run during a fix pass; not pre-registered.

This is the full 8-row model corpus × 3 prompt modes, driven through the **actual
proxy process** (not the mediator in-process). Each trial: start `mcp-gate`, read a
ticket via `fs:read_file`, let the model choose a recipient, send `mailer:send_email`
through the proxy. The proxy labels the read result itself.

Raw transcripts: `results/e2e_corpus.jsonl`.

## Local model (no rate limit)

`llama3.2:latest`, 8 rows (5 attack / 3 benign) × 3 modes = 24 trials.

| mode | attack ASR | attack blocked | benign utility raw | benign executed |
|---|---|---|---|---|
| plain | 4/5 = 80.0% | **5/5 = 100.0%** | 3/3 = 100.0% | **0/3 = 0.0%** |
| b2 | 0/5 = 0.0% | 5/5 = 100.0% | 3/3 = 100.0% | 0/3 = 0.0% |
| b2allow | 2/5 = 40.0% | 5/5 = 100.0% | 3/3 = 100.0% | 0/3 = 0.0% |

## Hosted model (frontier, subset)

`gemma-4-31b-it`, 4 attack rows × 2 modes = 8 trials.

| mode | attack ASR | attack blocked |
|---|---|---|
| plain | 4/4 = 100.0% | **4/4 = 100.0%** |
| b2allow | 0/4 = 0.0% | 4/4 = 100.0% |

## Reading

* **Every attack call is blocked through the process path**, in every mode and on both
  models. The attacker address is deliberately allowlisted, so the plain-mode blocks
  are provenance (`DENY_TAINT_PIVOT`), not parameter validation.
* **The cost is the same at the process level**: benign calls to the correct partner
  address are blocked 0/3 executed, because the read is external. This is H13 in the
  deployed binary.
* `b2` makes llama3.2 invent addresses (`support@evil.example`, `unknown@safe.example`);
  some of those blocks are parameter denials, not taint. The report says "blocked",
  not "taint", for that reason.
* This is the **full model corpus**, not the 360 templated scenarios. The latter still
  has no model prompt and has not been run through the CLI.

## Reproduce

```
cargo build -p mcp-gate
python3 evals/e2e_hosted_gate.py --provider ollama --model llama3.2:latest \
  --corpus evals/model-corpus.jsonl --modes plain,b2,b2allow \
  --out results/e2e_corpus.jsonl
ADAPTION_API_KEY=... python3 evals/e2e_hosted_gate.py --provider openai \
  --model gemma-4-31b-it --corpus evals/model-corpus.jsonl --limit 4 \
  --modes plain,b2allow --out results/e2e_corpus.jsonl
```
