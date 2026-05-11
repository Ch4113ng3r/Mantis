"""
API endpoint-by-endpoint vulnerability scanner.

Tests each discovered endpoint for OWASP API Top 10 issues.
Uses the webapp vuln scanner functions for injection tests
and the privilege tester for authorization checks.
"""

import httpx
from mantis.engage.phases import Phase
from mantis.webapp.vuln_scanner import test_xss_reflected, test_sqli
from mantis.core.findings import Finding, Severity, EvidenceLevel, FindingSource


class EndpointScanPhase(Phase):
    """Phase: scan API endpoints for vulnerabilities."""

    async def execute(self, context) -> dict:
        findings = []
        endpoints = context.endpoints[:100]  # Cap for performance

        async with httpx.AsyncClient(verify=False, timeout=15) as http:
            for ep in endpoints:
                url = ep.get("url", "")
                method = ep.get("method", "GET")
                params = ep.get("params", [])

                for param in params:
                    # Test for injection
                    if method == "GET":
                        xss = await test_xss_reflected(http, url, param)
                        if xss:
                            xss.source = FindingSource.API
                            findings.append(xss)

                        sqli = await test_sqli(http, url, param, method)
                        if sqli:
                            sqli.source = FindingSource.API
                            findings.append(sqli)

                # Test for excessive data exposure
                try:
                    resp = await http.request(method, url, timeout=10)
                    if resp.status_code == 200:
                        body = resp.text
                        sensitive_patterns = ["password", "secret", "token", "ssn",
                                              "credit_card", "api_key", "private_key"]
                        found_sensitive = [p for p in sensitive_patterns if p in body.lower()]
                        if found_sensitive:
                            findings.append(Finding(
                                title=f"Potential excessive data exposure at {url}",
                                description=f"Response contains potentially sensitive fields: {found_sensitive}",
                                source=FindingSource.API,
                                severity=Severity.MEDIUM,
                                evidence_level=EvidenceLevel.SUSPICION,
                                target=url, endpoint=url,
                                vuln_type="Excessive Data Exposure",
                                cwe="CWE-200",
                                owasp_category="API3:2023 Broken Object Property Level Authorization",
                                confidence=0.5,
                            ))
                except Exception:
                    continue

        print(f"    API endpoint findings: {len(findings)}")
        return {"findings": findings}
