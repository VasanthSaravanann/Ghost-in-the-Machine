# Full 360-scenario corpus through the real `mcp-gate` CLI

**Status: EXPLORATORY, scripted agent.** This runs `evals/public` and `evals/test`
(360 scenarios each) through the actual proxy process, with the same tool/args mapping
as `void-bench`. It is a plumbing/CLI result, not a model result: the agent is
scripted and the scenarios are templated.

Driver: `evals/cli_bench.py`. Raw: `results/cli_bench.json`.

## Configuration

For every scenario the driver starts `mcp-gate --enforce`, sends a `fs:read_file`
result (the untrusted ticket), then sends the scenario's effectful call:

* **G** — benign scenarios trust the read (principal); attacks do not.
* **B3** — the read is trusted for every scenario (policy-only).

The parameters are allowlisted (mailer to `partner@partner.example`, `db:grant_role`
`reader`), so only provenance separates G from B3.

## Results

| split | config | blocked | allowed | benign allowed |
|---|---|---|---|---|
| public | G | **160/360 = 44.4%** | 200/360 | 200/200 |
| public | B3 | 0/360 = 0.0% | 360/360 | 200/200 |
| test | G | **160/360 = 44.4%** | 200/360 | 200/200 |
| test | B3 | 0/360 = 0.0% | 360/360 | 200/200 |

The 160 blocked scenarios are exactly the four attack families (40 each); all 200
benign scenarios are allowed under G. B3 allows every attack, reproducing the
`PILOT-STATIC` ablation through the deployed binary: **ASR 100% → 0%**, utility 100%.

## What this closes

The full 360-scenario corpus now runs through the real CLI, with the transport setting
the provenance label. Combined with H15/e2e_corpus (live model, smaller corpus) and
AgentDojo (real benchmark, native defense), the “in-process only” objection no longer
applies.

## What it does not close

The scenarios are templated and the agent is scripted; this does not measure a model's
behaviour on 360 tasks. That still requires a model-driven corpus with real prompts.

## Reproduce

```
cargo build -p mcp-gate
python3 evals/cli_bench.py --out results/cli_bench.json
```
