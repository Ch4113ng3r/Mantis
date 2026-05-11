"""
ReAct Agent — the core reasoning loop.

Replaces LangGraph entirely with a ~100-line while loop.
The agent maintains a conversation history, dispatches tool calls
through guardrails, and persists state via the checkpoint system.

Loop:
    1. Send conversation history + tool schemas to LLM
    2. If LLM returns tool_calls → validate, execute, record, loop
    3. If LLM returns text only → return as final answer
"""

import asyncio
import json
from dataclasses import dataclass, field
from typing import Optional, Callable, Any

from .llm_client import AsyncLLMClient, LLMResponse
from .findings import Finding
from .guardrails import GuardrailEngine
from .checkpoint import CheckpointStore, Checkpoint
from .memory import EpisodicMemory
from .knowledge import KnowledgeGraph
from .token_tracker import TokenBudget
from .events import EventBus, Event


@dataclass
class ToolSpec:
    """
    Definition of a tool the agent can call.

    Each engagement module (network, webapp, api, codereview, exploit)
    registers its tools as ToolSpec instances. The agent converts
    these to Claude tool-use JSON schemas automatically.
    """
    name: str                      # Unique tool name
    description: str               # What the tool does (shown to LLM)
    parameters: dict               # JSON Schema for the tool's input
    handler: Callable              # Async function to execute
    requires_approval: bool = False  # Human gate for destructive tools
    category: str = "general"      # For grouping in the tool registry


@dataclass
class AgentConfig:
    """Configuration for the ReAct agent."""
    max_iterations: int = 50           # Safety limit on loop iterations
    max_consecutive_errors: int = 3    # Abort after N tool errors in a row
    checkpoint_interval: int = 5       # Save state every N iterations
    verbose: bool = True               # Print reasoning to console


class ReActAgent:
    """
    Pure-Python ReAct agent with tool dispatch, guardrails, and persistence.

    This is the beating heart of MANTIS. It replaces LangGraph's entire
    state-graph machinery with a simple, readable while loop.
    """

    def __init__(
        self,
        llm: AsyncLLMClient,
        tools: list[ToolSpec],
        guardrails: GuardrailEngine,
        checkpoint_store: CheckpointStore,
        memory: Optional[EpisodicMemory] = None,
        knowledge: Optional[KnowledgeGraph] = None,
        budget: Optional[TokenBudget] = None,
        event_bus: Optional[EventBus] = None,
        config: Optional[AgentConfig] = None,
    ):
        self.llm = llm
        self.tool_registry: dict[str, ToolSpec] = {t.name: t for t in tools}
        self.guardrails = guardrails
        self.checkpoints = checkpoint_store
        self.memory = memory
        self.knowledge = knowledge
        self.budget = budget
        self.events = event_bus
        self.config = config or AgentConfig()
        self.history: list[dict] = []
        self.findings: list[Finding] = []
        self.iteration: int = 0

    def _tool_schemas(self) -> list[dict]:
        """Convert ToolSpecs to Claude tool-use JSON schema format."""
        return [
            {
                "name": tool.name,
                "description": tool.description,
                "input_schema": tool.parameters,
            }
            for tool in self.tool_registry.values()
        ]

    async def run(
        self,
        objective: str,
        system_prompt: str,
        session_id: str,
    ) -> str:
        """
        Execute the ReAct loop until completion.

        Args:
            objective: What the agent should accomplish
            system_prompt: System context (mode-specific instructions)
            session_id: For checkpoint persistence

        Returns:
            Final text response from the agent.
        """
        # ── Try to resume from checkpoint ──
        cp = self.checkpoints.resume_or_start(session_id, {
            "objective": objective,
            "history": [],
        })
        self.history = cp.agent_state.get("history", [])
        self.findings = [Finding.from_dict(f) for f in cp.findings_so_far]
        self.iteration = cp.step_index

        # If fresh start, add the objective as the first user message
        if not self.history:
            self.history.append({"role": "user", "content": objective})

        consecutive_errors = 0

        # ── Main ReAct loop ──
        while self.iteration < self.config.max_iterations:
            self.iteration += 1

            # Budget check — abort if we've spent too much
            if self.budget and self.budget.is_exceeded():
                return (
                    f"Token budget exceeded "
                    f"(${self.budget.spent_usd:.2f} / ${self.budget.limit_usd:.2f}). "
                    f"Stopping with {len(self.findings)} findings."
                )

            # Step 1: Ask the LLM what to do next
            response = await self.llm.chat(
                messages=self.history,
                tools=self._tool_schemas(),
                system=system_prompt,
            )

            # Update budget tracking
            if self.budget:
                self.budget.record(response.usage)

            # Step 2: No tool calls = terminal state (LLM is done)
            if not response.tool_calls:
                self.history.append({
                    "role": "assistant",
                    "content": response.content,
                })
                self._save_checkpoint(session_id, phase="complete")
                return response.content

            # Step 3: Process tool calls
            # Build the assistant message with tool_use content blocks
            assistant_content: list[dict] = []
            if response.content:
                assistant_content.append({"type": "text", "text": response.content})
            for tc in response.tool_calls:
                assistant_content.append({
                    "type": "tool_use",
                    "id": tc["id"],
                    "name": tc["name"],
                    "input": tc["args"],
                })
            self.history.append({"role": "assistant", "content": assistant_content})

            # Execute each tool call and collect results
            tool_results: list[dict] = []
            for tc in response.tool_calls:
                result = await self._execute_tool_call(tc)
                tool_results.append(result)

                # Track consecutive errors for abort logic
                if result.get("is_error"):
                    consecutive_errors += 1
                    if consecutive_errors >= self.config.max_consecutive_errors:
                        return (
                            f"Aborting: {consecutive_errors} consecutive tool errors. "
                            f"Last: {result.get('content', 'unknown')}"
                        )
                else:
                    consecutive_errors = 0

            # Append all tool results as a single user message
            self.history.append({"role": "user", "content": tool_results})

            # Periodic checkpoint save
            if self.iteration % self.config.checkpoint_interval == 0:
                self._save_checkpoint(session_id, phase="running")

        return (
            f"Reached max iterations ({self.config.max_iterations}). "
            f"Findings so far: {len(self.findings)}"
        )

    async def _execute_tool_call(self, tc: dict) -> dict:
        """Validate and execute a single tool call."""
        tool_name = tc["name"]
        tool_args = tc["args"]
        tool_id = tc["id"]

        # Unknown tool
        tool_spec = self.tool_registry.get(tool_name)
        if not tool_spec:
            return {
                "type": "tool_result",
                "tool_use_id": tool_id,
                "content": f"Error: Unknown tool '{tool_name}'. "
                           f"Available: {', '.join(self.tool_registry.keys())}",
                "is_error": True,
            }

        # Guardrail validation
        violation = self.guardrails.check(tool_name, tool_args)
        if violation:
            if self.events:
                self.events.emit(Event("guardrail_blocked", {
                    "tool": tool_name, "reason": violation,
                }))
            return {
                "type": "tool_result",
                "tool_use_id": tool_id,
                "content": f"BLOCKED by guardrail: {violation}",
                "is_error": True,
            }

        # Human approval gate for destructive tools
        if tool_spec.requires_approval:
            approved = await self._request_approval(tool_name, tool_args)
            if not approved:
                return {
                    "type": "tool_result",
                    "tool_use_id": tool_id,
                    "content": "DENIED by operator. Choose a different approach.",
                    "is_error": False,
                }

        # Execute the tool
        try:
            result = await tool_spec.handler(**tool_args)
            result_str = (
                json.dumps(result, default=str)
                if not isinstance(result, str)
                else result
            )

            # Record in memory and knowledge graph
            if self.memory:
                self.memory.record(tool_name, tool_args, result_str)
            if self.knowledge:
                self.knowledge.ingest_tool_result(tool_name, tool_args, result)

            return {
                "type": "tool_result",
                "tool_use_id": tool_id,
                "content": result_str[:15000],  # Truncate large outputs
            }
        except Exception as e:
            return {
                "type": "tool_result",
                "tool_use_id": tool_id,
                "content": f"Tool execution error: {type(e).__name__}: {str(e)}",
                "is_error": True,
            }

    async def _request_approval(self, tool_name: str, args: dict) -> bool:
        """Pause and ask the operator for approval before executing."""
        print(f"\n{'=' * 60}")
        print(f"  APPROVAL REQUIRED: {tool_name}")
        print(f"  Arguments:")
        for key, value in args.items():
            print(f"    {key}: {value}")
        print(f"{'=' * 60}")
        response = input("  Approve? [y/N]: ").strip().lower()
        return response in ("y", "yes")

    def _save_checkpoint(self, session_id: str, phase: str):
        """Persist current state to SQLite."""
        self.checkpoints.save(Checkpoint(
            session_id=session_id,
            phase=phase,
            step_index=self.iteration,
            agent_state={"history": self.history},
            findings_so_far=[f.to_dict() for f in self.findings],
            pending_targets=[],
            completed_targets=[],
            token_usage={
                "prompt": self.llm.usage.prompt_tokens,
                "completion": self.llm.usage.completion_tokens,
                "cost_usd": self.llm.usage.total_cost_usd,
            },
        ))

    def add_finding(self, finding: Finding):
        """Record a finding from a tool execution."""
        self.findings.append(finding)
        if self.knowledge:
            self.knowledge.add_finding(finding.id, finding.target, finding.to_dict())
