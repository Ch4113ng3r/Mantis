"""
Vulnerability chain analyzer.

After all individual findings are collected, this module asks the
LLM to identify exploitable chains — sequences of vulnerabilities
that compound into a higher-impact attack path.

Example chain:
  SSRF → internal API access → credential leak → admin takeover

Each chain gets its own severity rating (usually higher than any
individual finding) and appears in the report as an "Attack Chain".
"""

from dataclasses import dataclass, field
from typing import Optional

from .llm_client import AsyncLLMClient
from .findings import Finding, Severity, EvidenceLevel, FindingSource
import json


@dataclass
class AttackChain:
    """A sequence of findings that chain into a higher-impact attack."""
    id: str
    title: str                              # "SSRF → Internal API → Admin Takeover"
    description: str                        # Full narrative of the chain
    steps: list[dict] = field(default_factory=list)  # Ordered finding refs + transitions
    findings: list[str] = field(default_factory=list)  # Finding IDs in this chain
    combined_severity: Severity = Severity.CRITICAL
    combined_impact: str = ""
    exploitation_narrative: str = ""        # Step-by-step attack description
    remediation: str = ""                   # Which link to break
    confidence: float = 0.0


class ChainAnalyzer:
    """
    Analyzes findings for exploitable chains.

    Process:
    1. Collect all findings from the engagement
    2. Send them to the LLM with chain-discovery prompt
    3. LLM identifies which findings can be chained
    4. Each chain is scored and documented
    5. Chains are added to the report as a separate section

    This runs AFTER all scanning/verification phases but BEFORE reporting.
    """

    def __init__(self, llm: AsyncLLMClient):
        self.llm = llm

    async def analyze(self, findings: list[Finding]) -> list[AttackChain]:
        """Identify exploitable chains across all findings."""
        if len(findings) < 2:
            return []

        # Build a concise summary of all findings for the LLM
        findings_summary = []
        for f in findings:
            findings_summary.append({
                "id": f.id,
                "title": f.title,
                "vuln_type": f.vuln_type,
                "severity": f.severity.value,
                "target": f.target,
                "endpoint": f.endpoint,
                "description": f.description[:200],
                "impact": f.impact[:200],
            })

        prompt = f"""You are an expert penetration tester analyzing findings for exploitable attack chains.

FINDINGS:
{json.dumps(findings_summary, indent=2)}

Identify any chains where exploiting one vulnerability enables or amplifies another.

For each chain, explain:
1. The step-by-step attack path
2. How each vulnerability enables the next step
3. The combined impact (which is greater than any individual finding)
4. Which single fix would break the chain most effectively

Respond ONLY with JSON:
{{
  "chains": [
    {{
      "title": "Short chain title with arrows",
      "steps": [
        {{"finding_id": "F-...", "action": "What the attacker does with this vuln", "gains": "What this gives them"}}
      ],
      "combined_impact": "What the full chain achieves",
      "break_point": "Which finding to fix first to break the chain",
      "confidence": 0.0-1.0
    }}
  ]
}}

If no chains exist, return {{"chains": []}}.
"""

        resp = await self.llm.chat(
            messages=[{"role": "user", "content": prompt}],
            temperature=0.0,
            max_tokens=4096,
        )

        try:
            data = json.loads(resp.content)
            chains = []
            for i, chain_data in enumerate(data.get("chains", [])):
                chain = AttackChain(
                    id=f"CHAIN-{i+1:03d}",
                    title=chain_data.get("title", ""),
                    description=chain_data.get("combined_impact", ""),
                    steps=chain_data.get("steps", []),
                    findings=[s["finding_id"] for s in chain_data.get("steps", [])],
                    combined_severity=Severity.CRITICAL,
                    combined_impact=chain_data.get("combined_impact", ""),
                    exploitation_narrative=self._build_narrative(chain_data),
                    remediation=chain_data.get("break_point", ""),
                    confidence=chain_data.get("confidence", 0.5),
                )
                chains.append(chain)
            return chains
        except (json.JSONDecodeError, KeyError):
            return []

    def _build_narrative(self, chain_data: dict) -> str:
        """Build a step-by-step exploitation narrative."""
        lines = []
        for i, step in enumerate(chain_data.get("steps", []), 1):
            lines.append(f"Step {i}: {step.get('action', '')}")
            lines.append(f"  → Gains: {step.get('gains', '')}")
        return "\n".join(lines)
