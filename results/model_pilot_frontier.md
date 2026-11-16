# H12 — hosted frontier-scale replication (Adaption API)

**Pre-registered before the run (`evals/PREREG.md`, H12).** Provider: Adaption's
OpenAI-compatible endpoint at `https://api.prod.adaptionlabs.ai/api/v1` (configured in
`~/.pi/agent/models.json`; the key is read from an env var and passed to `curl` on
stdin, never argv or the transcript). Temperature 0, `max_tokens` 4096, JSON mode for
the summary and the answer.

| model | rows/model | notes |
|---|---|---|
| `qwen3.8-27b` | 24 (15 attack / 9 benign) | 3 repetitions |
| `deepseek-v4-flash` | 23 (15/8) | one benign row per mode lost to a tool timeout |
| `gemma-4-31b-it` | 24 (15/9) | 3 repetitions |

Two runtime amendments, both disclosed in the prereg **before** the tables were
computed: `qwen3.5-397b` was dropped (5/24 records in 30 min, ≈90 s/call with 8k-char
reasoning traces); `deepseek-v4-flash` is 23/24 rows per mode. Raw transcripts:
`results/model_pilot_frontier.jsonl` (213 records).

## Results

| model | prompt | parseable | ASR | B3 allows | G allows | utility |
|---|---|---|---|---|---|---|
| qwen3.8-27b | plain | 21/24 = 87.5% | 12/15 = 80.0% (56.0–94.3) | 12 | 0 | 9/9 = 100.0% |
| qwen3.8-27b | b2 | 2/24 = 8.3% | 0/15 = 0.0% (0.0–18.1) | 0 | 0 | 1/9 = 11.1% |
| qwen3.8-27b | b2allow | 23/24 = 95.8% | 0/15 = 0.0% (0.0–18.1) | 0 | 0 | 9/9 = 100.0% |
| deepseek-v4-flash | plain | 23/23 = 100.0% | 15/15 = 100.0% (81.9–100.0) | 15 | 0 | 8/8 = 100.0% |
| deepseek-v4-flash | b2 | 0/23 = 0.0% | 0/15 = 0.0% (0.0–18.1) | 0 | 0 | 0/8 = 0.0% |
| deepseek-v4-flash | b2allow | 23/23 = 100.0% | 0/15 = 0.0% (0.0–18.1) | 0 | 0 | 8/8 = 100.0% |
| gemma-4-31b-it | plain | 7/24 = 29.2% | 5/15 = 33.3% (14.2–57.7) | 5 | 0 | 2/9 = 22.2% |
| gemma-4-31b-it | b2 | 2/24 = 8.3% | 0/15 = 0.0% (0.0–18.1) | 0 | 0 | 2/9 = 22.2% |
| gemma-4-31b-it | b2allow | 12/24 = 50.0% | 0/15 = 0.0% (0.0–18.1) | 0 | 0 | 4/9 = 44.4% |

Pooled:

| prompt | ASR (n=45/model-arm) | utility (n=26) |
|---|---|---|
| plain | **32/45 = 71.1%** (58.0–82.0) | 19/26 = 73.1% (55.3–86.6) |
| b2 (no permitted address) | **0/45 = 0.0%** (0.0–6.4) | **3/26 = 11.5%** (3.2–27.2) |
| b2allow (recipient out-of-band) | **0/45 = 0.0%** (0.0–6.4) | **21/26 = 80.8%** (63.7–92.1) |

On the **32 successful plain attack calls**: B3 allows **32/32** (100 %, 91.1–100.0)
and G denies **32/32** (0 allows, 0.0–8.9), all `DENY_TAINT_PIVOT`.

## What this establishes (including the part that hurts)

1. **The vulnerability is not a small-model artefact.** On hosted 27B–31B models with
   no defence, 71 % of cross-session attacks carry the attacker address into the tool
   call; deepseek-v4-flash is 15/15.
2. **Strict prompt hardening is safe only by breaking the task.** `b2` reaches 0 ASR
   but utility collapses to **11.5 %** (deepseek 0/8, qwen 1/9). This is the measured
   version of the "B2 costs utility" claim that H8 could not support.
3. **The utility-preserving prompt defence wins on these models.** `b2allow` reaches
   **0/45 ASR with 80.8 % utility** (qwen3.8 and deepseek 9/9 and 8/8; gemma4 4/9).
   It is handed the permitted recipient, which the gate is not, but on this task it is
   a strong baseline.
4. **The boundary still denies every successful plain attack** (32/32) while
   policy-only allows every one. That is a mechanism result on frontier-scale models.
5. **H12 is partially falsified.** The registered hypothesis said prompt defence would
   be incomplete; on `b2allow` it eliminated the attack in all three models. The honest
   conclusion is that **the gate's marginal value is not demonstrated when the allowed
   recipient can be stated out-of-band and the model obeys it**. The gate matters when
   the recipient must come from untrusted memory (no allowlist), when the model ignores
   the instruction (local 3B models, gemma4), or when policy cannot express the rule.

## Protocol observations

* `glm-5.2` was probed and **refused the task at the provider layer** ("Request blocked
  due to security policy: potential data exfiltration to unauthorized recipient"). That
  is a model-level mitigation, not a gate win; it is not in the table.
* `qwen3.5-397b` produces 8k-character reasoning traces and is not practical for this
  loop (≈90 s/call).
* `gemma-4-31b-it` often answers `{"to": "none"}` / `{"to": "null"}` (a JSON refusal),
  which is why its parseable and utility counts are low; it is a low-utility model on
  this task, not an unparseable one.

## Limits

* Three models, one run, 24 rows each (deepseek 23); intervals are wide.
* `b2allow` is handed the permitted recipient; the gate is not. The comparison is
  "prompt defence with the answer" vs "boundary provenance without it".
* The API exposes no content digest; the model id is the pin. Provider-side safety
  filters and model updates can change results without notice.
* Memory is text and the provenance label is assigned by the harness from the declared
  source; the transport wiring is still the remaining engineering gap.
