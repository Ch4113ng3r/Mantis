"""
Episodic and mechanism memory for cross-run intelligence.

Episodic memory: records tool calls and results within a session
for context summarization when the conversation grows too long.

Mechanism memory: extracts abstract vulnerability patterns from
verified findings and persists them across runs. On subsequent
scans, these patterns are injected as hints into scanning prompts.
"""

import json
import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class MemoryEntry:
    """A single recorded action within a session."""
    tool_name: str
    args_summary: str
    result_summary: str
    timestamp: str = ""
    importance: float = 0.5  # 0.0-1.0, higher = more important to retain


class EpisodicMemory:
    """
    Within-session memory with importance-based retention.

    As the session progresses, less important entries are evicted
    to keep the memory buffer manageable. High-importance entries
    (findings, errors, key discoveries) are retained.
    """

    def __init__(self, max_entries: int = 200):
        self.entries: list[MemoryEntry] = []
        self.max_entries = max_entries

    def record(self, tool_name: str, args: dict, result: str):
        """Record a tool execution in memory."""
        entry = MemoryEntry(
            tool_name=tool_name,
            args_summary=json.dumps(args, default=str)[:200],
            result_summary=result[:500],
            importance=self._score_importance(tool_name, result),
        )
        self.entries.append(entry)

        # Evict low-importance entries when buffer is full
        if len(self.entries) > self.max_entries:
            self.entries.sort(key=lambda e: e.importance)
            self.entries = self.entries[len(self.entries) // 4:]

    def _score_importance(self, tool_name: str, result: str) -> float:
        """Score how important this entry is for retention."""
        score = 0.5
        result_lower = result.lower()

        # Findings and vulns are high importance
        if any(kw in result_lower for kw in [
            "vulnerability", "found", "exploit", "critical",
            "injection", "xss", "sqli", "rce",
        ]):
            score += 0.3

        # Errors are medium importance (learn from failures)
        if "error" in result_lower or "exception" in result_lower:
            score += 0.1

        # Exploit tools are always important
        if "exploit" in tool_name:
            score += 0.2

        return min(score, 1.0)

    def get_context_summary(self, max_tokens: int = 2000) -> str:
        """Generate a summary of session activity for context injection."""
        important = sorted(self.entries, key=lambda e: -e.importance)[:20]
        lines = ["## Session Activity Summary"]
        for e in important:
            lines.append(f"- {e.tool_name}: {e.result_summary[:100]}")
        return "\n".join(lines)[:max_tokens]


class MechanismMemory:
    """
    Cross-run mechanism memory.

    Stores abstract vulnerability patterns discovered during previous
    engagements. On subsequent scans, matching mechanisms are injected
    as hints to improve detection of similar patterns.

    Examples of mechanisms:
    - "length field trusted before allocation; size_t wrapping"
    - "user input concatenated into SQL via ORM .raw() method"
    - "JWT secret stored in environment variable, leaked via error page"
    """

    def __init__(self, path: str = "~/.mantis/mechanisms.jsonl"):
        self.path = os.path.expanduser(path)
        self.mechanisms: list[dict] = []
        self._load()

    def _load(self):
        """Load mechanisms from JSONL file."""
        if os.path.exists(self.path):
            with open(self.path) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            self.mechanisms.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue

    def add(self, mechanism: str, vuln_type: str, evidence: str, confidence: float):
        """Record a new mechanism from a verified finding."""
        entry = {
            "mechanism": mechanism,
            "vuln_type": vuln_type,
            "evidence": evidence,
            "confidence": confidence,
        }
        self.mechanisms.append(entry)
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def recall(self, context: str, top_k: int = 5) -> list[dict]:
        """Find mechanisms relevant to the given code/target context."""
        context_words = set(context.lower().split())
        scored = []
        for mech in self.mechanisms:
            mech_words = set(mech["mechanism"].lower().split())
            overlap = len(context_words & mech_words)
            if overlap > 0:
                scored.append((overlap * mech["confidence"], mech))
        scored.sort(key=lambda x: -x[0])
        return [m for _, m in scored[:top_k]]
