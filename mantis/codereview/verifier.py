"""
Opus adversarial verification phase.

Layer 4 of the four-layer funnel. Takes each finding from the deep
scanner and asks Claude Opus to steel-man BOTH sides: argue why it
IS a real vulnerability AND why it might be a false positive. The
stronger argument wins.
"""

from mantis.engage.phases import Phase
from mantis.core.llm_client import AsyncLLMClient
from mantis.core.findings import Finding, EvidenceLevel
from mantis.config import load_config, get_api_key, get_model
import json


class AdversarialVerifier:
    """Opus-powered adversarial finding verification."""

    def __init__(self, llm: AsyncLLMClient):
        self.llm = llm

    async def verify(self, finding: Finding, file_content: str = None) -> bool:
        """
        Adversarially verify a finding.

        Returns True if the finding is confirmed, False if likely false positive.
        """
        context = ""
        if file_content:
            # Include relevant code around the finding
            lines = file_content.splitlines()
            start = max(0, (finding.line_number or 1) - 10)
            end = min(len(lines), (finding.line_number or 1) + 10)
            context = "\n".join(f"{i+1}: {line}" for i, line in enumerate(lines[start:end], start=start))

        prompt = f"""You are an expert security auditor performing adversarial verification.

FINDING:
  Title: {finding.title}
  Type: {finding.vuln_type}
  Severity: {finding.severity.value}
  File: {finding.file_path}
  Line: {finding.line_number}
  Description: {finding.description}
  CWE: {finding.cwe}

CODE CONTEXT:
```
{context}
```

Steel-man BOTH sides:

1. ARGUMENT FOR (why this IS a real vulnerability):
   - What conditions make this exploitable?
   - What's the realistic attack scenario?
   - What evidence supports this being real?

2. ARGUMENT AGAINST (why this might be a false positive):
   - Is there sanitization we're not seeing?
   - Is the input actually attacker-controlled?
   - Are there mitigating controls?

3. VERDICT: Based on the strength of both arguments, is this a TRUE POSITIVE or FALSE POSITIVE?

Respond with JSON:
{{
  "argument_for": "...",
  "argument_against": "...",
  "verdict": "true_positive" or "false_positive",
  "confidence": 0.0-1.0,
  "reasoning": "which argument was stronger and why"
}}
"""

        try:
            resp = await self.llm.chat(
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0,
                max_tokens=2048,
            )
            text = resp.content.strip()
            if text.startswith("```"):
                text = text.split("\n", 1)[1] if "\n" in text else text[3:]
                if text.endswith("```"):
                    text = text[:-3]
            data = json.loads(text)
            return data.get("verdict") == "true_positive"
        except Exception:
            return True  # Default to keeping the finding if verification fails


class VerifyPhase(Phase):
    """Phase: adversarially verify findings using Claude Opus."""

    async def execute(self, context) -> dict:
        # Only verify code review findings
        code_findings = [f for f in context.findings if f.source.value == "code_review"]
        if not code_findings:
            print("    No code review findings to verify")
            return {}

        config = load_config()
        api_key = get_api_key(config)
        model = get_model(config, "verifier")

        if not api_key:
            print("    No API key — skipping verification")
            return {}

        llm = AsyncLLMClient(api_key=api_key, model=model)
        verifier = AdversarialVerifier(llm)

        verified_count = 0
        fp_count = 0
        for finding in code_findings:
            # Load file content for context
            content = ""
            if finding.file_path:
                try:
                    with open(finding.file_path, "r", errors="replace") as f:
                        content = f.read()
                except Exception:
                    pass

            is_real = await verifier.verify(finding, content)
            if is_real:
                finding.mark_verified(True)
                finding.escalate(EvidenceLevel.ROOT_CAUSE_EXPLAINED, "adversarial_verified")
                verified_count += 1
            else:
                finding.mark_verified(False)
                fp_count += 1

        await llm.close()
        print(f"    Verified: {verified_count}, False positives: {fp_count}")
        return {}
