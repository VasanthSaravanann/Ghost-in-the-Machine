"""Native AgentDojo defense: a pipeline element that applies the boundary rule.

This is the same conservative rule as `DENY_TAINT_PIVOT`: once a tool result has
been seen, an effectful call is denied; read-only calls are exempt. It is inserted
inside AgentDojo's `ToolsExecutionLoop`, so the benchmark executes it as a defense
rather than as a post-hoc replay.

It is a Python implementation of the rule, not the Rust `mcp-gate` binary; that
distinction is stated in results/agentdojo.md.
"""
from __future__ import annotations

from collections.abc import Sequence

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
from agentdojo.types import ChatMessage, text_content_block_from_string

READ_PREFIXES = (
    "get_", "search_", "list_", "read_", "retrieve_", "find_", "lookup_", "check_",
)


def _name(call) -> str:
    return getattr(call, "function", None) or (
        call.get("function", "") if isinstance(call, dict) else ""
    )


def is_read_only(name: str) -> bool:
    return name.startswith(READ_PREFIXES)


class ProvenanceGate(BasePipelineElement):
    """Deny effectful tool calls that follow any tool result."""

    name = "provenance-gate"

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = [],
        extra_args: dict = {},
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        if not messages:
            return query, runtime, env, messages, extra_args
        last = messages[-1]
        calls = last.get("tool_calls")
        if last.get("role") != "assistant" or not calls:
            return query, runtime, env, messages, extra_args

        tainted = any(message.get("role") == "tool" for message in messages)
        if not tainted:
            return query, runtime, env, messages, extra_args

        kept = [call for call in calls if is_read_only(_name(call))]
        if len(kept) == len(calls):
            return query, runtime, env, messages, extra_args

        filtered = dict(last)
        filtered["tool_calls"] = kept
        if not kept:
            filtered["content"] = [
                text_content_block_from_string(
                    "Blocked by boundary provenance (DENY_TAINT_PIVOT)."
                )
            ]
        return query, runtime, env, [*messages[:-1], filtered], extra_args


def build_pipeline(llm, system_message: str):
    """AgentDojo pipeline with the gate inside the tool loop."""
    from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline
    from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
    from agentdojo.agent_pipeline.tool_execution import (
        ToolsExecutionLoop,
        ToolsExecutor,
        tool_result_to_str,
    )

    loop = ProvenanceGateLoop([ToolsExecutor(tool_result_to_str), llm])
    pipeline = AgentPipeline([SystemMessage(system_message), InitQuery(), llm, loop])
    pipeline.name = "local model"
    return pipeline


class ProvenanceGateLoop(BasePipelineElement):
    """Tools loop that stops on the first provenance block.

    `ToolsExecutionLoop` would hand the refusal back to the LLM, which can retry the
    blocked call until the context limit is hit (AgentDojo then records security=True
    as a fail-safe). This loop checks provenance *before* executing and terminates.
    """

    name = "provenance-gate-loop"

    def __init__(self, elements, max_iters: int = 15) -> None:
        self.elements = elements
        self.max_iters = max_iters

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = [],
        extra_args: dict = {},
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        if not messages:
            raise ValueError("Messages should not be empty when calling the gate loop")
        for _ in range(self.max_iters):
            last = messages[-1]
            if last.get("role") != "assistant" or not last.get("tool_calls"):
                break
            tainted = any(message.get("role") == "tool" for message in messages)
            if tainted:
                calls = last["tool_calls"]
                kept = [call for call in calls if is_read_only(_name(call))]
                if len(kept) != len(calls):
                    filtered = dict(last)
                    filtered["tool_calls"] = kept
                    if not kept:
                        filtered["content"] = [
                            text_content_block_from_string(
                                "Blocked by boundary provenance (DENY_TAINT_PIVOT)."
                            )
                        ]
                    messages = [*messages[:-1], filtered]
                    break
            for element in self.elements:
                query, runtime, env, messages, extra_args = element.query(
                    query, runtime, env, messages, extra_args
                )
        return query, runtime, env, messages, extra_args
