# Reproduce the evidence in this repository.
#
# `make reproduce` is the static/offline path (no network, no model calls).
# `make reproduce-models` additionally needs a local Ollama and downloads nothing.
#
# Every target is additive: nothing here rewrites a committed scenario corpus.

CARGO ?= cargo
MODELS ?= llama3.2:latest
REPS ?= 3

.PHONY: help lint test frontier pilot adaptive neutral injecagent injecagent100 hosted cost e2e policy-aware reproduce reproduce-models

help:
	@echo "lint              fmt --check + clippy -D warnings"
	@echo "test              full workspace test suite"
	@echo "frontier          H7 over-taint cost curve (no model calls)"
	@echo "pilot             H8b: three-model paired B3/G run (needs Ollama models)"
	@echo "adaptive          H8c/H8d: fixed-budget LLM-rewrite attacker (needs Ollama)"
	@echo "reproduce         lint + test + frontier (offline)"
	@echo "reproduce-models  reproduce + pilot + adaptive (local models)"

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
	python3 evals/e2e_hosted_gate.py --trials 10 --model gemma-4-31b-it

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
