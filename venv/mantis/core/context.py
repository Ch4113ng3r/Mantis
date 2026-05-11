"""
EngagementContext — shared state that flows across phases.

Each phase produces output (findings, recon data, discovered endpoints,
credentials) that subsequent phases consume. The context object carries
all accumulated state through the pipeline.
"""

from dataclasses import dataclass, field
from typing import Any, Optional
from .findings import Finding


@dataclass
class EngagementContext:
    """
    Shared state flowing across engagement phases.

    Phases read from and write to this context. On checkpoint resume,
    the context is rehydrated from the last saved state.
    """
    target: str = ""
    scope: list[str] = field(default_factory=list)
    mode: str = ""

    # Accumulated findings from all phases
    findings: list[Finding] = field(default_factory=list)

    # Recon data (populated by recon phases)
    subdomains: list[str] = field(default_factory=list)
    technologies: dict = field(default_factory=dict)
    dns_records: dict = field(default_factory=dict)
    osint_data: dict = field(default_factory=dict)

    # Discovered attack surface
    endpoints: list[dict] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)
    parameters: list[dict] = field(default_factory=list)

    # Network data
    open_ports: list[dict] = field(default_factory=list)
    services: list[dict] = field(default_factory=list)

    # API data
    api_schema: Optional[dict] = None
    auth_tokens: dict = field(default_factory=dict)

    # Code review data
    source_files: list[str] = field(default_factory=list)
    triage_results: list[dict] = field(default_factory=list)
    taint_paths: list[dict] = field(default_factory=list)

    # Credentials discovered during testing
    credentials: list[dict] = field(default_factory=list)

    def merge(self, result: dict):
        """Merge phase output into context."""
        if not result:
            return

        # Merge findings
        if "findings" in result:
            self.findings.extend(result["findings"])

        # Merge list fields
        list_fields = [
            "subdomains", "endpoints", "forms", "parameters",
            "open_ports", "services", "source_files",
            "triage_results", "taint_paths", "credentials",
        ]
        for f in list_fields:
            if f in result:
                existing = getattr(self, f)
                existing.extend(result[f])

        # Merge dict fields
        dict_fields = ["technologies", "dns_records", "osint_data", "auth_tokens"]
        for f in dict_fields:
            if f in result:
                existing = getattr(self, f)
                existing.update(result[f])

        # Set scalar fields
        if "api_schema" in result:
            self.api_schema = result["api_schema"]

    def finding_count_by_severity(self) -> dict:
        """Count findings grouped by severity."""
        counts: dict[str, int] = {}
        for f in self.findings:
            sev = f.severity.value
            counts[sev] = counts.get(sev, 0) + 1
        return counts
