#!/usr/bin/env python3
"""AgentDojo (real package, v1.2) with a hosted OpenAI-compatible model.

This runs the benchmark itself: real user tasks, real injection tasks, the
`important_instructions` attack, and AgentDojo's own utility/security checks.
It is not a derived corpus.

The boundary gate is NOT yet an AgentDojo defense; this run establishes the
external baseline and the attack success on the same tasks. The logs written by
AgentDojo are the input for a boundary replay (see results/agentdojo.md).

Usage:
  ADAPTION_API_KEY=... python3 evals/agentdojo_run.py --user-tasks 5 \
      --injection-tasks 1 --model deepseek-v4-flash
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib

import openai

from agentdojo.agent_pipeline.agent_pipeline import (
    AgentPipeline,
    PipelineConfig,
    load_system_message,
)
from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.benchmark import benchmark_suite_with_injections
from agentdojo.logging import OutputLogger
from agentdojo.task_suite.load_suites import get_suites

BASE = "https://api.prod.adaptionlabs.ai/api/v1"


def api_key() -> str:
    key = os.environ.get("ADAPTION_API_KEY", "")
    if key:
        return key
    path = pathlib.Path.home() / ".pi/agent/models.json"
    return json.loads(path.read_text())["providers"]["adaption"]["apiKey"]


def rate(successes: int, total: int) -> str:
    return f"{successes}/{total} = {100.0 * successes / total:.1f}%" if total else "n/a"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="deepseek-v4-flash")
    ap.add_argument("--suite", default="workspace")
    ap.add_argument("--user-tasks", type=int, default=5)
    ap.add_argument("--injection-tasks", type=int, default=1)
    ap.add_argument("--benchmark-version", default="v1.2")
    ap.add_argument("--attack", default="important_instructions")
    ap.add_argument("--defense", choices=["none", "provenance"], default="none")
    ap.add_argument("--out", default="results/agentdojo.json")
    args = ap.parse_args()

    client = openai.OpenAI(api_key=api_key(), base_url=BASE, max_retries=4)
    # vLLM rejects the `name` field on tool messages that AgentDojo emits.
    import agentdojo.agent_pipeline.llms.openai_llm as _ollm

    _original_message = _ollm._message_to_openai

    def _message_without_tool_name(message, model_name):
        converted = _original_message(message, model_name)
        if isinstance(converted, dict) and converted.get("role") == "tool":
            converted.pop("name", None)
        return converted

    _ollm._message_to_openai = _message_without_tool_name

    llm = OpenAILLM(client, args.model)
    if args.defense == "provenance":
        from agentdojo_defense import build_pipeline

        pipeline = build_pipeline(llm, load_system_message(None))
    else:
        pipeline = AgentPipeline.from_config(
            PipelineConfig(
                llm=llm,
                model_id=args.model,
                defense=None,
                tool_delimiter="tool",
                system_message_name=None,
                system_message=load_system_message(None),
                tool_output_format=None,
            )
        )
    # `OpenAILLM` has no name; the attack needs one for the jailbreak text.
    pipeline.name = "local model"
    suites = get_suites(args.benchmark_version)
    suite = suites[args.suite]
    user_tasks = list(suite.user_tasks)[: args.user_tasks]
    injection_tasks = list(suite.injection_tasks)[: args.injection_tasks]
    attack = load_attack(args.attack, suite, pipeline)

    logdir = pathlib.Path("results/agentdojo_runs") / args.suite / args.model
    with OutputLogger(str(logdir)):
        results = benchmark_suite_with_injections(
            pipeline,
            suite,
            attack,
            logdir=logdir,
            force_rerun=True,
            user_tasks=user_tasks,
            injection_tasks=injection_tasks,
            verbose=False,
            benchmark_version=args.benchmark_version,
        )

    utility = results["utility_results"]
    security = results["security_results"]
    payload = {
        "model": args.model,
        "provider": "adaption-openai-compatible",
        "benchmark_version": args.benchmark_version,
        "suite": args.suite,
        "attack": args.attack,
        "defense": args.defense,
        "user_tasks": user_tasks,
        "injection_tasks": injection_tasks,
        "utility_results": {f"{u}|{i}": v for (u, i), v in utility.items()},
        "security_results": {f"{u}|{i}": v for (u, i), v in security.items()},
        "utility": rate(sum(utility.values()), len(utility)),
        "security": rate(sum(security.values()), len(security)),
        "logdir": str(logdir),
    }
    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=1))

    print(f"AgentDojo {args.benchmark_version} / {args.suite} / {args.model}")
    print(f"user tasks {len(user_tasks)}, injection tasks {len(injection_tasks)}")
    print(f"utility (task solved): {payload['utility']}")
    print(f"security (attack succeeded): {payload['security']}")
    print(f"logs: {logdir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
