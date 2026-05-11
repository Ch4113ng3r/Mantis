"""Tests for the Finding dataclass."""

from mantis.core.findings import Finding, Severity, EvidenceLevel, FindingSource


def test_finding_auto_id():
    f = Finding(title="Test XSS", vuln_type="XSS", target="http://example.com")
    assert f.id.startswith("F-")
    assert len(f.id) == 14  # F- + 12 hex chars


def test_finding_serialization():
    f = Finding(
        title="SQL Injection",
        severity=Severity.CRITICAL,
        evidence_level=EvidenceLevel.DYNAMIC_CONFIRMED,
        source=FindingSource.WEBAPP,
        vuln_type="SQLi",
        target="http://example.com/search",
    )
    d = f.to_dict()
    assert d["severity"] == "critical"
    assert d["source"] == "webapp"

    f2 = Finding.from_dict(d)
    assert f2.severity == Severity.CRITICAL
    assert f2.source == FindingSource.WEBAPP
    assert f2.id == f.id


def test_finding_escalation():
    f = Finding(title="Test", evidence_level=EvidenceLevel.SUSPICION)
    f.escalate(EvidenceLevel.DYNAMIC_CONFIRMED, reason="runtime probe")
    assert f.evidence_level == EvidenceLevel.DYNAMIC_CONFIRMED
    assert "escalated:runtime probe" in f.tags
