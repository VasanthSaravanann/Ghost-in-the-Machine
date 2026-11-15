PILOT-STATIC — split: TEST (evals/test); scripted gullible agent; single host
| config | AF1 ASR (95% ub) | AF2 ASR (95% ub) | AF3 ASR (95% ub) | AF4 ASR (95% ub) | utility | FPR |
|---|---|---|---|---|---|---|
| B0-ungated | 40/40 = 100.0% (ub 100.0%) | 40/40 = 100.0% (ub 100.0%) | 40/40 = 100.0% (ub 100.0%) | 40/40 = 100.0% (ub 100.0%) | 100.0% | 0.00% |
| B1-deny-all | 0/40 = 0.0% (ub 7.2%) | 0/40 = 0.0% (ub 7.2%) | 0/40 = 0.0% (ub 7.2%) | 0/40 = 0.0% (ub 7.2%) | 62.5% | 37.50% |
| B3-policy-only | 40/40 = 100.0% (ub 100.0%) | 40/40 = 100.0% (ub 100.0%) | 40/40 = 100.0% (ub 100.0%) | 40/40 = 100.0% (ub 100.0%) | 100.0% | 0.00% |
| G-taint | 0/40 = 0.0% (ub 7.2%) | 0/40 = 0.0% (ub 7.2%) | 0/40 = 0.0% (ub 7.2%) | 0/40 = 0.0% (ub 7.2%) | 100.0% | 0.00% |

Note: trials per family are small; intervals are wide by construction. E_bar not measured (no endorsement channel).

---
Corpus: `evals/test`, frozen aggregate `e7a42b0eb0cd3028b7c674c9fbe0f109c705d02e3e71f7e26b7300f12701e7ab`.
Run ONCE after freeze; no tuning on this split. All numbers PILOT-STATIC.
