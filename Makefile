# Reproduce the evidence in this repository.
#
# `make reproduce` is the static/offline path (no network, no model calls).
# `make reproduce-models` additionally needs a local Ollama and downloads nothing.
#
# Every target is additive: nothing here rewrites a committed scenario corpus.

CARGO ?= cargo
MODELS ?= llama3.2:latest
REPS ?= 3

.PHONY: help lint test frontier pilot adaptive neutral injecagent injecagent100 hosted cost e2e e2e-corpus cli-bench agentdojo checkpoint checkpoint-sensitivity policy-aware reproduce reproduce-models

help:
	@echo "reproduce               lint + 433 tests + frontier (offline, no models)"
	@echo "pilot                   H8b: paired B3/G on local models (MODELS, REPS)"
	@echo "adaptive                H8c/H8d: fixed-budget LLM rewrite (llama3.2)"
	@echo "policy-aware            H11: policy-aware attacker (llama3.2)"
	@echo "neutral                 H10: neutral summariser (MODELS)"
	@echo "hosted                  H12: hosted 27B-31B models (ADAPTION_API_KEY)"
	@echo "injecagent              H9: InjecAgent-derived corpus (network + MODELS)"
	@echo "injecagent100           H14: 100 external attacks (ADAPTION_API_KEY)"
	@echo "cost                    H13: cost of G on benign external flows (key)"
	@echo "e2e                     H15: live model through the real proxy (key)"
	@echo "e2e-corpus              full model corpus through the CLI (Ollama)"
	@echo "cli-bench               360-scenario corpus through the CLI (scripted)"
	@echo "agentdojo               AgentDojo baseline + replay (AGENTDOJO_PY)"
	@echo "checkpoint              H18: simulated principal approval (llama3.2)"
	@echo "checkpoint-sensitivity  principal accuracy target (no models)"
	@echo "reproduce-models        reproduce + pilot + adaptive + neutral + policy-aware"

lint:
	$(CARGO) fmt --check
	$(CARGO) clippy --workspace --all-targets --all-features -- -D warnings

test:
	$(CARGO) test --workspace

frontier:
	$(CARGO) run -q -p void-bench --bin frontier

pilot:
	$(CARGO) run -q -p void-bench --bin model_pilot -- \
		--models=$(MODELS) --reps=$(REPS) --modes=plain,b2,b2allow \
		--out=results/model_pilot.jsonl

adaptive:
	$(CARGO) run -q -p void-bench --bin model_pilot -- \
		--models=llama3.2:latest --reps=1 --modes=plain \
		--attacker=adaptive --budget=3 --out=results/model_adaptive.jsonl
	$(CARGO) run -q -p void-bench --bin model_pilot -- \
		--models=llama3.2:latest --reps=1 --modes=b2allow \
		--attacker=adaptive --budget=3 --out=results/model_adaptive_b2allow.jsonl

policy-aware:
	$(CARGO) run -q -p void-bench --bin model_pilot -- \
		--models=llama3.2:latest --reps=1 --modes=b2allow \
		--attacker=policy-aware --budget=3 \
		--out=results/model_adaptive_policy_aware.jsonl

injecagent100:
	$(CARGO) run -q -p void-bench --bin model_pilot -- \
		--provider=openai --api-key-env=ADAPTION_API_KEY \
		--models=gemma-4-31b-it --corpus=evals/external/injecagent-attack-100.jsonl \
		--limit=100 --reps=1 --modes=plain,b2allow \
		--out=results/model_injecagent_100.jsonl

e2e:
	$(CARGO) build -q -p mcp-gate
	python3 evals/e2e_hosted_gate.py --provider=openai --trials 10 --model gemma-4-31b-it

e2e-corpus:
	$(CARGO) build -q -p mcp-gate
	python3 evals/e2e_hosted_gate.py --provider ollama --model llama3.2:latest \
		--corpus evals/model-corpus.jsonl --modes plain,b2,b2allow \
		--out results/e2e_corpus.jsonl

cli-bench:
	$(CARGO) build -q -p mcp-gate
	python3 evals/cli_bench.py --out results/cli_bench.json

checkpoint-sensitivity:
	python3 evals/checkpoint_sensitivity.py

checkpoint:
	$(CARGO) run -q -p void-bench --bin model_pilot -- \
		--models=llama3.2:latest --corpus=evals/external/benign-external-approved-v1.jsonl \
		--reps=3 --modes=plain --out=results/model_benign_checkpoint.jsonl

AGENTDOJO_PY ?= /tmp/adjo312/bin/python
agentdojo:
	$(AGENTDOJO_PY) evals/agentdojo_run.py --suite travel --model qwen3.8-27b \
		--user-tasks 8 --injection-tasks 2 --attack direct \
		--out results/agentdojo_travel.json
	$(AGENTDOJO_PY) evals/agentdojo_replay.py \
		results/agentdojo_runs/travel/qwen3.8-27b \
		--pairs results/agentdojo_travel.json \
		--out results/agentdojo_replay_travel.json

cost:
	$(CARGO) run -q -p void-bench --bin model_pilot -- \
		--provider=openai --api-key-env=ADAPTION_API_KEY \
		--models=qwen3.8-27b,deepseek-v4-flash,gemma-4-31b-it \
		--corpus=evals/external/benign-external-v1.jsonl --reps=3 --modes=plain \
		--out=results/model_benign_cost.jsonl

hosted:
	$(CARGO) run -q -p void-bench --bin model_pilot -- \
		--provider=openai --api-key-env=ADAPTION_API_KEY \
		--models=qwen3.8-27b,deepseek-v4-flash,gemma-4-31b-it \
		--reps=3 --modes=plain,b2,b2allow \
		--out=results/model_pilot_frontier.jsonl

neutral:
	$(CARGO) run -q -p void-bench --bin model_pilot -- \
		--models=$(MODELS) --reps=1 --modes=plain,b2allow --summarizer=neutral \
		--out=results/model_pilot_neutral.jsonl

INJECAGENT ?= /tmp/injec_test_cases_dh_base.json

$(INJECAGENT):
	curl -sL -m 120 -o $@ https://raw.githubusercontent.com/uiuc-kang-lab/InjecAgent/main/data/test_cases_dh_base.json
injecagent: $(INJECAGENT)
	python3 evals/injecagent_to_corpus.py $(INJECAGENT) \
		evals/external/injecagent-memory-v1.jsonl --cases 12
	$(CARGO) run -q -p void-bench --bin model_pilot -- \
		--models=$(MODELS) --corpus=evals/external/injecagent-memory-v1.jsonl \
		--limit=12 --reps=1 --modes=plain,b2allow \
		--out=results/model_injecagent.jsonl

reproduce: lint test frontier

reproduce-models: reproduce pilot adaptive neutral policy-aware
