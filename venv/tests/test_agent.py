"""Tests for the ReAct agent."""

# Integration tests for the agent require an LLM API key.
# Run with: ANTHROPIC_API_KEY=sk-... pytest tests/test_agent.py

import pytest


def test_tool_spec_creation():
    from mantis.core.agent import ToolSpec

    async def dummy_handler(x: str) -> str:
        return f"result: {x}"

    tool = ToolSpec(
        name="test_tool",
        description="A test tool",
        parameters={"type": "object", "properties": {"x": {"type": "string"}}},
        handler=dummy_handler,
    )
    assert tool.name == "test_tool"
    assert tool.requires_approval is False
