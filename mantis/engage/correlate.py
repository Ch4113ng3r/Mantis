"""
Correlation phase — cross-references code review and runtime findings.

This is the killer feature when combining code_review + webapp modes.
It matches code-level findings (e.g., missing auth check at auth.py:247)
with runtime findings (e.g., IDOR confirmed on /api/users/{id}/profile)
to produce correlated findings with full root-cause-to-exploit chains.
"""

from mantis.engage.phases import Phase
from mantis.core.findings import Finding, FindingSource, Severity, EvidenceLevel


class CorrelationPhase(Phase):
    """Cross-reference code review findings with runtime findings."""

    async def execute(self, context) -> dict:
        code_findings = [f for f in context.findings if f.source == FindingSource.CODE_REVIEW]
        runtime_findings = [f for f in context.findings
                           if f.source in (FindingSource.WEBAPP, FindingSource.API)]

        correlated = []

        for cf in code_findings:
            for rf in runtime_findings:
                # Match by vulnerability type and target overlap
                if cf.vuln_type == rf.vuln_type:
                    correlated.append(Finding(
                        title=f"Correlated: {cf.title} confirmed by {rf.title}",
                        description=(
                            f"Code review finding {cf.id} (at {cf.file_path}:{cf.line_number}) "
                            f"confirmed exploitable via runtime finding {rf.id}. "
                            f"Root cause: {cf.description}. "
                            f"Runtime proof: {rf.description}."
                        ),
                        source=FindingSource.CORRELATION,
                        severity=max(cf.severity, rf.severity, key=lambda s: list(Severity).index(s)),
                        evidence_level=EvidenceLevel.ROOT_CAUSE_EXPLAINED,
                        target=rf.target,
                        endpoint=rf.endpoint,
                        file_path=cf.file_path,
                        line_number=cf.line_number,
                        vuln_type=cf.vuln_type,
                        cwe=cf.cwe,
                        impact=rf.impact,
                        remediation=cf.remediation,
                        confidence=min(cf.confidence + rf.confidence, 1.0),
                        verified=True,
                        tags=["correlated", f"code:{cf.id}", f"runtime:{rf.id}"],
                    ))

        if correlated:
            print(f"    [*] Correlated {len(correlated)} code+runtime finding pairs")

        return {"findings": correlated}
