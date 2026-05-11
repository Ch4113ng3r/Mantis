"""
Token budget tracking and enforcement.

Prevents runaway costs by tracking cumulative spend per model
and aborting when a configurable budget limit is reached.
"""

from dataclasses import dataclass, field


@dataclass
class TokenBudget:
    """
    Tracks cumulative token spend and enforces a hard USD limit.

    Usage:
        budget = TokenBudget(limit_usd=50.0)
        budget.record(response.usage)
        if budget.is_exceeded():
            # stop the engagement
    """
    limit_usd: float = 50.0
    spent_usd: float = 0.0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    calls_by_model: dict = field(default_factory=dict)

    # Pricing per million tokens
    PRICING = {
        "claude-haiku-4-5-20251001":   {"input": 0.80,  "output": 4.00},
        "claude-sonnet-4-20250514":    {"input": 3.00,  "output": 15.00},
        "claude-opus-4-20250514":      {"input": 15.00, "output": 75.00},
    }

    def record(self, usage: dict):
        """Record token usage from a single LLM response."""
        model = usage.get("model", "unknown")
        input_tok = usage.get("input_tokens", 0)
        output_tok = usage.get("output_tokens", 0)

        self.prompt_tokens += input_tok
        self.completion_tokens += output_tok

        if model not in self.calls_by_model:
            self.calls_by_model[model] = {"calls": 0, "input": 0, "output": 0}
        self.calls_by_model[model]["calls"] += 1
        self.calls_by_model[model]["input"] += input_tok
        self.calls_by_model[model]["output"] += output_tok

        self.spent_usd = self._calculate_cost()

    def _calculate_cost(self) -> float:
        """Recalculate total cost from per-model usage."""
        total = 0.0
        for model, counts in self.calls_by_model.items():
            pricing = self.PRICING.get(model, {"input": 3.0, "output": 15.0})
            total += (
                (counts["input"] / 1_000_000) * pricing["input"]
                + (counts["output"] / 1_000_000) * pricing["output"]
            )
        return total

    def is_exceeded(self) -> bool:
        """Check if budget has been exceeded."""
        return self.spent_usd >= self.limit_usd

    def remaining_usd(self) -> float:
        """How much budget remains."""
        return max(0.0, self.limit_usd - self.spent_usd)

    def summary(self) -> str:
        """Human-readable budget summary."""
        return (
            f"Budget: ${self.spent_usd:.2f} / ${self.limit_usd:.2f} "
            f"({self.prompt_tokens:,} prompt + "
            f"{self.completion_tokens:,} completion tokens)"
        )
