"""
Universal Finding type — the one canonical finding across all modes.

Every module (network, webapp, API, code review, exploit) produces
Finding instances. The report generator, knowledge graph, and
deduplication all work on this single type.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional, Any
from datetime import datetime
import hashlib
import json


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EvidenceLevel(Enum):
    """
    Evidence ladder — how confident are we in this finding?

    Each level strictly implies all levels below it.
    A finding starts at SUSPICION and climbs as more evidence accrues.
    """
    SUSPICION = "suspicion"                  # LLM thinks it might exist
    STATIC_CORROBORATION = "static"          # Pattern match or AST confirms
    DYNAMIC_CONFIRMED = "dynamic"            # Runtime probe confirmed
    CRASH_REPRODUCED = "crash"               # Sanitizer crash / error triggered
    ROOT_CAUSE_EXPLAINED = "root_cause"      # Full causal chain documented
    EXPLOIT_DEMONSTRATED = "exploited"       # PoC achieved impact
    PATCH_VALIDATED = "patched"              # Fix applied and verified


class FindingSource(Enum):
    """Which module produced this finding."""
    NETWORK = "network"
    WEBAPP = "webapp"
    API = "api"
    CODE_REVIEW = "code_review"
    EXPLOIT = "exploit"
    CORRELATION = "correlation"   # Cross-reference between code and runtime
    MANUAL = "manual"


@dataclass
class HTTPEvidence:
    """A single HTTP request/response pair as evidence."""
    request_method: str
    request_url: str
    request_headers: dict
    request_body: Optional[str]
    response_status: int
    response_headers: dict
    response_body: str             # Truncated to 5KB max
    timestamp: str = ""
    notes: str = ""                # What this particular exchange proves


@dataclass
class Finding:
    """
    Universal finding across all MANTIS modes.

    Carries enough fields to represent network vulns, web app issues,
    API flaws, source code bugs, and exploitation results uniformly.
    """

    # ── Identity ──
    id: str = ""                                  # Auto-generated deterministic hash
    title: str = ""                               # Human-readable title
    description: str = ""                         # Detailed description
    source: FindingSource = FindingSource.WEBAPP
    severity: Severity = Severity.MEDIUM
    evidence_level: EvidenceLevel = EvidenceLevel.SUSPICION

    # ── Location — where the vulnerability exists ──
    target: str = ""                              # URL, IP, or file path
    endpoint: str = ""                            # Specific endpoint or function
    port: Optional[int] = None                    # For network findings
    protocol: Optional[str] = None                # tcp/udp/http/https
    file_path: Optional[str] = None               # For code review findings
    line_number: Optional[int] = None             # For code review findings
    function_name: Optional[str] = None           # For code review findings

    # ── Classification ──
    vuln_type: str = ""                           # XSS, SQLi, BOLA, etc.
    cwe: Optional[str] = None                     # CWE-79, CWE-89, etc.
    cve: Optional[str] = None                     # If known CVE
    owasp_category: Optional[str] = None          # OWASP Top 10 / API Top 10
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None

    # ── Evidence ──
    evidence: list = field(default_factory=list)   # list[HTTPEvidence]
    reproduction_steps: list[str] = field(default_factory=list)
    payload: Optional[str] = None                  # The payload that triggered it
    impact: str = ""                               # What an attacker can achieve
    remediation: str = ""                          # How to fix it

    # ── Code review specific ──
    taint_path: Optional[str] = None               # Source -> sink data flow
    code_snippet: Optional[str] = None             # Relevant code fragment
    mechanism: Optional[str] = None                # Abstract vulnerability pattern

    # ── Metadata ──
    confidence: float = 0.0                        # 0.0-1.0
    false_positive: bool = False                   # Marked as FP by verifier
    verified: bool = False                         # Passed adversarial verification
    timestamp: str = field(
        default_factory=lambda: datetime.utcnow().isoformat()
    )
    session_id: str = ""
    variant_of: Optional[str] = None               # Parent finding ID if variant
    tags: list[str] = field(default_factory=list)

    def __post_init__(self):
        """Generate deterministic ID from key identifying fields."""
        if not self.id:
            key = f"{self.target}:{self.endpoint}:{self.vuln_type}"
            key += f":{self.file_path}:{self.line_number}"
            self.id = "F-" + hashlib.sha256(key.encode()).hexdigest()[:12].upper()

    def to_dict(self) -> dict:
        """Serialize to dict for JSON/checkpoint storage."""
        d = asdict(self)
        d["severity"] = self.severity.value
        d["evidence_level"] = self.evidence_level.value
        d["source"] = self.source.value
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        """Deserialize from dict."""
        d = d.copy()
        d["severity"] = Severity(d["severity"])
        d["evidence_level"] = EvidenceLevel(d["evidence_level"])
        d["source"] = FindingSource(d["source"])
        evidence_raw = d.pop("evidence", [])
        d["evidence"] = [
            HTTPEvidence(**e) if isinstance(e, dict) else e
            for e in evidence_raw
        ]
        return cls(**d)

    def escalate(self, new_level: EvidenceLevel, reason: str = ""):
        """Promote finding to a higher evidence level."""
        self.evidence_level = new_level
        if reason:
            self.tags.append(f"escalated:{reason}")

    def mark_verified(self, verified: bool = True):
        """Mark as verified (or false positive) after adversarial review."""
        self.verified = verified
        if verified:
            self.tags.append("adversarial_verified")
        else:
            self.false_positive = True
            self.tags.append("false_positive")
