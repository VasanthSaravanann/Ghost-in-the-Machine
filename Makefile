# Reproduce the evidence in this repository.
#
# `make reproduce` is the static/offline path (no network, no model calls).
# `make reproduce-models` additionally needs a local Ollama and downloads nothing.
#
# Every target is additive: nothing here rewrites a committed scenario corpus.

CARGO ?= cargo
MODELS ?= llama3.2:latest
REPS ?= 3

.PHONY: help lint test frontier pilot adaptive reproduce reproduce-models

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

reproduce: lint test frontier

reproduce-models: reproduce pilot adaptive
