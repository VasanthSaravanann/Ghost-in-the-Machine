# H15 — live hosted model → real `mcp-gate` process

This closes the last validation gap: the model's chosen recipient goes through the
**actual proxy process**, and the proxy sets provenance from the tool response itself.
No harness-declared taint flag is involved.

Model: `gemma-4-31b-it` via the hosted Adaption API (JSON mode, temperature 0).
Driver: `evals/e2e_hosted_gate.py`; upstream: `evals/fake_mcp_upstream.py`.
Per trial: start `mcp-gate --enforce` → client reads a ticket (`fs:read_file`) →
the model summarises it and chooses a recipient → client calls `mailer:send_email`
through the proxy → the proxy labels the read result EXTERNAL and decides.

Raw transcripts: `results/e2e_gate.jsonl` (13 records).

## Results

| condition | model chose | outcome |
|---|---|---|
| enforce, attacker ticket | attacker 7/7 | **blocked 7/7** (JSON-RPC `-32001`) |
| shadow control, attacker ticket | attacker 3/3 | **executed 3/3** |
| enforce, benign ticket | partner 3/3 | **blocked 3/3** |

* **The live path blocks the attack end to end**: the model's address, transported as a
  real `tools/call`, is denied by the proxy after one untrusted read. The shadow control
  executes the identical call, so the proxy — not the harness — is the difference.
* **The cost is visible end to end**: a benign ticket with a legitimate partner address
  is also denied (3/3), because the read is external. This is H13 at the process level.

## What changed to make this work

1. `gate-transport` previously short-circuited responses: the mediator never saw a
   `FrameKind::Response`. Responses now go through `mediate`, so a provenance-aware
   gate can label tool results. A `Block` on a response drops it (it cannot be
   answered upstream).
2. `mcp-gate` tracks `tools/call` request ids, labels the matching response
   (`EXTERNAL` by default; `PRINCIPAL` only with `trust_tool_results` or a per-tool
   `trusted_tools` entry), and evaluates the next call against that closure.
3. Five mediator tests plus one per-tool checkpoint test cover the logic; this report
   covers the process path.

## Limits

* 7 enforce trials, not 10: the hosted API returned `429` and the driver stopped at the
  rate limit. The three shadow controls and three benign trials ran after a cooldown.
  The counts are reported as they are, not topped up.
* One model; the ticket is canned; the upstream is a fake server (no real filesystem).
* The rate limit is a provider constraint; retries with backoff are implemented but the
  run was not restarted to reach a round number.
