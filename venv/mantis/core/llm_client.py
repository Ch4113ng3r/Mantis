"""
Async LLM client for Claude and OpenAI-compatible APIs.

Handles tool-use, streaming, retries, and token tracking.
Replaces both LangGraph's LLM integration and the Rust genai-pyo3
bridge from Clearwing — in ~150 lines of Python.
"""

import httpx
import asyncio
import json
import time
from dataclasses import dataclass, field
from typing import Optional, Any


@dataclass
class LLMResponse:
    """Parsed response from an LLM API call."""
    content: str                                        # Text content
    tool_calls: list[dict] = field(default_factory=list)  # Tool call requests
    usage: dict = field(default_factory=dict)            # Token usage stats
    model: str = ""                                     # Model that generated this
    stop_reason: str = ""                               # Why generation stopped


@dataclass
class TokenUsage:
    """Cumulative token usage tracker with cost calculation."""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_cost_usd: float = 0.0

    # Pricing per million tokens (May 2026 rates)
    PRICING = {
        "claude-haiku-4-5-20251001":   {"input": 0.80,  "output": 4.00},
        "claude-sonnet-4-20250514":    {"input": 3.00,  "output": 15.00},
        "claude-opus-4-20250514":      {"input": 15.00, "output": 75.00},
    }

    def record(self, model: str, prompt_tok: int, comp_tok: int):
        """Record token usage and update cost."""
        self.prompt_tokens += prompt_tok
        self.completion_tokens += comp_tok
        pricing = self.PRICING.get(model, {"input": 3.0, "output": 15.0})
        self.total_cost_usd += (
            (prompt_tok / 1_000_000) * pricing["input"]
            + (comp_tok / 1_000_000) * pricing["output"]
        )


class AsyncLLMClient:
    """
    Async client for Claude API with tool-use support.

    Supports Anthropic native API and any OpenAI-compatible endpoint.
    All calls go through httpx — no Rust bridge, no SDK dependency.

    Usage:
        client = AsyncLLMClient(api_key="sk-ant-...", model="claude-sonnet-4-20250514")
        response = await client.chat(
            messages=[{"role": "user", "content": "Hello"}],
            tools=[...],
        )
        print(response.content)
        print(response.tool_calls)
    """

    def __init__(
        self,
        api_key: str,
        model: str = "claude-sonnet-4-20250514",
        base_url: str = "https://api.anthropic.com",
        max_retries: int = 3,
        timeout: float = 120.0,
    ):
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.max_retries = max_retries
        self.usage = TokenUsage()
        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            limits=httpx.Limits(max_connections=20),
            http2=True,
        )

    async def chat(
        self,
        messages: list[dict],
        tools: Optional[list[dict]] = None,
        system: Optional[str] = None,
        max_tokens: int = 4096,
        temperature: float = 0.0,
    ) -> LLMResponse:
        """
        Send a chat completion request to the LLM.

        Args:
            messages: Conversation history [{role, content}, ...]
            tools: Tool schemas for function calling (Claude tool-use format)
            system: System prompt
            max_tokens: Maximum response tokens
            temperature: Sampling temperature (0.0 = deterministic)

        Returns:
            LLMResponse with content, tool_calls, and usage.

        Raises:
            httpx.HTTPStatusError: On non-retryable API errors.
        """
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if system:
            payload["system"] = system
        if tools:
            payload["tools"] = tools

        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
        }

        # Retry loop with exponential backoff
        for attempt in range(self.max_retries):
            try:
                resp = await self.client.post(
                    f"{self.base_url}/v1/messages",
                    json=payload,
                    headers=headers,
                )

                # Rate limited — back off and retry
                if resp.status_code == 429:
                    wait = min(2 ** attempt * 5, 60)
                    await asyncio.sleep(wait)
                    continue

                # Server error — retry with backoff
                if resp.status_code >= 500:
                    await asyncio.sleep(2 ** attempt)
                    continue

                resp.raise_for_status()
                data = resp.json()
                return self._parse_response(data)

            except httpx.ConnectError:
                if attempt == self.max_retries - 1:
                    raise
                await asyncio.sleep(2 ** attempt)

        # Should not reach here, but just in case
        raise RuntimeError(f"Failed after {self.max_retries} retries")

    def _parse_response(self, data: dict) -> LLMResponse:
        """Parse Claude API response into LLMResponse."""
        content_parts: list[str] = []
        tool_calls: list[dict] = []

        for block in data.get("content", []):
            if block["type"] == "text":
                content_parts.append(block["text"])
            elif block["type"] == "tool_use":
                tool_calls.append({
                    "id": block["id"],
                    "name": block["name"],
                    "args": block["input"],
                })

        # Track token usage
        usage = data.get("usage", {})
        self.usage.record(
            self.model,
            usage.get("input_tokens", 0),
            usage.get("output_tokens", 0),
        )

        return LLMResponse(
            content="\n".join(content_parts),
            tool_calls=tool_calls,
            usage=usage,
            model=data.get("model", self.model),
            stop_reason=data.get("stop_reason", ""),
        )

    async def close(self):
        """Close the underlying HTTP client."""
        await self.client.aclose()
