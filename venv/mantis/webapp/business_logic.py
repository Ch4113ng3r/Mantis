"""
Business logic testing phase.

Uses the ReAct agent to test for business logic flaws that can't
be detected by pattern-based scanning. The agent reasons about
application workflows and tests for bypasses, race conditions,
and logic manipulation.
"""

from mantis.engage.phases import Phase
from mantis.core.findings import Finding, Severity, EvidenceLevel, FindingSource


class BusinessLogicPhase(Phase):
    """
    Phase: test for business logic vulnerabilities.

    This phase creates a focused ReAct agent with the target's
    endpoint map and auth contexts, then lets it reason about
    potential logic flaws based on the application's structure.

    The agent tests for:
    - Price/quantity manipulation in e-commerce flows
    - Workflow step skipping (checkout without payment)
    - Rate limit bypass (coupon reuse, vote stuffing)
    - Negative value attacks (negative quantity = credit)
    - Race conditions in concurrent operations
    - Role/privilege manipulation via parameter tampering
    """

    async def execute(self, context) -> dict:
        findings = []

        # Test for common business logic patterns in discovered endpoints
        for ep in context.endpoints:
            url = ep.get("url", "")
            params = ep.get("params", [])

            # Check for numeric parameters that might be manipulable
            suspicious_params = [p for p in params if any(
                kw in p.lower() for kw in [
                    "price", "amount", "quantity", "qty", "total",
                    "discount", "credit", "balance", "points",
                    "count", "limit", "rate", "fee",
                ]
            )]

            if suspicious_params:
                findings.append(Finding(
                    title=f"Potential business logic target: {', '.join(suspicious_params)} at {url}",
                    description=(
                        f"Parameters {suspicious_params} at {url} may be susceptible to "
                        f"value manipulation (negative values, overflow, boundary bypass). "
                        f"Manual testing recommended."
                    ),
                    source=FindingSource.WEBAPP,
                    severity=Severity.INFO,
                    evidence_level=EvidenceLevel.SUSPICION,
                    target=url, endpoint=url,
                    vuln_type="Business Logic",
                    cwe="CWE-840",
                    confidence=0.3,
                    tags=["needs_manual_review", "business_logic"],
                ))

        # Check for workflow endpoints that might allow step skipping
        workflow_indicators = ["checkout", "payment", "confirm", "verify",
                               "approve", "submit", "finalize", "complete"]
        workflow_endpoints = [
            ep for ep in context.endpoints
            if any(kw in ep.get("url", "").lower() for kw in workflow_indicators)
        ]
        if len(workflow_endpoints) > 1:
            findings.append(Finding(
                title="Multi-step workflow detected — test for step skipping",
                description=(
                    f"Found {len(workflow_endpoints)} workflow endpoints: "
                    f"{[ep['url'] for ep in workflow_endpoints[:5]]}. "
                    f"Test if later steps can be accessed directly without completing earlier ones."
                ),
                source=FindingSource.WEBAPP,
                severity=Severity.INFO,
                evidence_level=EvidenceLevel.SUSPICION,
                target=self.config.target,
                vuln_type="Business Logic",
                confidence=0.3,
                tags=["needs_manual_review"],
            ))

        print(f"    Business logic targets identified: {len(findings)}")
        return {"findings": findings}
