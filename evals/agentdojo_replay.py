#!/usr/bin/env python3
"""Boundary replay over real AgentDojo logs.

This is NOT a native AgentDojo defense. It applies the same rule the boundary gate
uses (`control_flow_taint` + `PivotMode::Deny`): once a tool result has been seen,
an effectful call is denied. Read-only calls are exempt. The verdicts are computed
on AgentDojo's own trajectories, so the attack and utility outcomes are the
benchmark's, not a synthetic corpus's.

Caveat: an effectful call is denied whether it is the attack or a legitimate user
action, so `utility_lost_upper` is an upper bound (the denied call may be the attack
call only).
"""
from __future__ import annotations

import argparse
import ast
import glob
import json
import pathlib

READ_PREFIXES = (
    "get_", "search_", "list_", "read_", "retrieve_", "find_", "lookup_", "check_",
)


def calls_of(message: dict) -> list[dict]:
    raw = message.get("tool_calls")
    if not raw:
        return []
    if isinstance(raw, str):
        try:
            raw = ast.literal_eval(raw)
        except (ValueError, SyntaxError):
            return []
    return [c for c in raw if isinstance(c, dict) and "function" in c]


def effectful(name: str) -> bool:
    return not name.startswith(READ_PREFIXES)


def replay(path: str) -> dict:
    data = json.load(open(path))
    seen_tool_output = False
    denied: list[str] = []
    effectful_calls = 0
    for message in data.get("messages", []):
        if message.get("role") == "tool":
            seen_tool_output = True
            continue
        for call in calls_of(message):
            name = str(call.get("function", ""))
            if effectful(name):
                effectful_calls += 1
                if seen_tool_output:
                    denied.append(name)
    return {
        "file": path,
        "suite": data.get("suite_name"),
        "user_task": data.get("user_task_id"),
        "injection_task": data.get("injection_task_id"),
        "attack": data.get("attack_type"),
        "utility": bool(data.get("utility")),
        "security": bool(data.get("security")),
        "effectful_calls": effectful_calls,
        "denied_effectful": denied,
        "attack_prevented": bool(data.get("security")) and bool(denied),
        "utility_lost_upper": bool(data.get("utility")) and bool(denied),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("logdir", help="AgentDojo run directory")
    ap.add_argument("--out", default="results/agentdojo_replay.json")
    ap.add_argument("--pairs", default=None, help="benchmark JSON; keep only its pairs")
    args = ap.parse_args()
    paths = sorted(glob.glob(str(pathlib.Path(args.logdir) / "**" / "*.json"), recursive=True))
    rows = [replay(p) for p in paths]
    if args.pairs:
        bench = json.load(open(args.pairs))
        wanted = set(bench["security_results"].keys())
        rows = [
            r for r in rows
            if f"{r['user_task']}|{r['injection_task']}" in wanted
        ]
        # keep the newest log per pair (force_rerun leaves old files behind)
        newest = {}
        for row in rows:
            key = (row["user_task"], row["injection_task"])
            stamp = pathlib.Path(row["file"]).stat().st_mtime
            if key not in newest or stamp > newest[key][0]:
                newest[key] = (stamp, row)
        rows = [row for _, row in newest.values()]
    payload = {
        "logdir": args.logdir,
        "runs": len(rows),
        "utility": sum(r["utility"] for r in rows),
        "security": sum(r["security"] for r in rows),
        "attack_prevented": sum(r["attack_prevented"] for r in rows),
        "utility_lost_upper": sum(r["utility_lost_upper"] for r in rows),
        "runs_with_denied_effect": sum(bool(r["denied_effectful"]) for r in rows),
        "details": rows,
    }
    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=1))
    print(f"runs {payload['runs']}")
    print(f"utility {payload['utility']}/{payload['runs']}")
    print(f"security (attack succeeded) {payload['security']}/{payload['runs']}")
    print(f"security successes prevented by replay {payload['attack_prevented']}/{payload['security']}")
    print(f"utility successes with a denied effect (upper bound) {payload['utility_lost_upper']}/{payload['utility']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
